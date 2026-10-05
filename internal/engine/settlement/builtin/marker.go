// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package builtin

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/engine/finding"
	"github.com/zeroroot-ai/gibson/internal/engine/settlement"
)

// MarkerPresentType is the predicate type name registered by
// [RegisterMarkerPresent].
const MarkerPresentType settlement.PredicateType = "marker_present"

// MarkerPresentParams configures the MarkerPresent evaluator.
type MarkerPresentParams struct {
	// Marker is the exact, benign token a demonstration must have captured
	// for the predicate to hold — for example a per-run nonce written to a
	// file the demonstration proves it can read. Matching is an exact
	// substring match, case-sensitive: proof of control depends on a
	// marker no unrelated evidence would ever contain, not on fuzzy
	// matching.
	Marker string `json:"marker"`

	// EvidenceType, if set, restricts the search to evidence of that one
	// type. Left empty, every piece of evidence with a text representation
	// is searched.
	EvidenceType finding.EvidenceType `json:"evidence_type,omitempty"`
}

// RegisterMarkerPresent registers the MarkerPresent evaluator for technique.
// MarkerPresent evaluates true iff at least one piece of captured evidence
// contains the configured marker string — the deterministic check behind
// "prove control, not damage" (ADR-0131): a demonstration
// captures a benign marker as its proof, and this predicate confirms the
// marker actually shows up in what was captured.
func RegisterMarkerPresent(r *settlement.Registry, technique settlement.TechniqueID) error {
	if err := r.Register(technique, MarkerPresentType, markerPresentEvaluate); err != nil {
		return fmt.Errorf("builtin: register %s: %w", MarkerPresentType, err)
	}
	return nil
}

func markerPresentEvaluate(params json.RawMessage, evidence []finding.EnhancedEvidence) (bool, error) {
	var p MarkerPresentParams
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return false, fmt.Errorf("builtin: decode %s params: %w", MarkerPresentType, err)
		}
	}
	if p.Marker == "" {
		return false, fmt.Errorf("builtin: %s requires a non-empty marker: %w", MarkerPresentType, errEmptyMarker)
	}

	for _, e := range evidence {
		if p.EvidenceType != "" && e.Type != p.EvidenceType {
			continue
		}
		text, ok := evidenceText(e)
		if !ok {
			continue
		}
		if strings.Contains(text, p.Marker) {
			return true, nil
		}
	}
	return false, nil
}

var errEmptyMarker = errors.New("empty marker")
