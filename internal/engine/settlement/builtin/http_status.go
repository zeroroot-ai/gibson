// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package builtin

import (
	"encoding/json"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/engine/finding"
	"github.com/zeroroot-ai/gibson/internal/engine/settlement"
)

// HTTPStatusEqualsType is the predicate type name registered by
// [RegisterHTTPStatusEquals].
const HTTPStatusEqualsType settlement.PredicateType = "http_status_equals"

// HTTPStatusEqualsParams configures the HTTPStatusEquals evaluator.
type HTTPStatusEqualsParams struct {
	// Want is the HTTP status code at least one captured HTTP response
	// must carry for the predicate to hold.
	Want int `json:"want"`
}

// RegisterHTTPStatusEquals registers the HTTPStatusEquals evaluator for
// technique. HTTPStatusEquals evaluates true iff at least one captured
// HTTP-response evidence item has the configured status code — a
// deterministic proof-of-reach check for techniques whose claim is "this
// endpoint returns status N", such as an authorization bypass.
func RegisterHTTPStatusEquals(r *settlement.Registry, technique settlement.TechniqueID) error {
	if err := r.Register(technique, HTTPStatusEqualsType, httpStatusEqualsEvaluate); err != nil {
		return fmt.Errorf("builtin: register %s: %w", HTTPStatusEqualsType, err)
	}
	return nil
}

func httpStatusEqualsEvaluate(params json.RawMessage, evidence []finding.EnhancedEvidence) (bool, error) {
	var p HTTPStatusEqualsParams
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return false, fmt.Errorf("builtin: decode %s params: %w", HTTPStatusEqualsType, err)
		}
	}
	if p.Want < 100 || p.Want > 599 {
		return false, fmt.Errorf("builtin: %s requires a valid HTTP status code, got %d", HTTPStatusEqualsType, p.Want)
	}

	for _, e := range evidence {
		if e.Type != finding.EvidenceHTTPResponse {
			continue
		}
		var resp finding.HTTPResponseEvidence
		if !decodeContent(e.Content, &resp) {
			continue
		}
		if resp.StatusCode == p.Want {
			return true, nil
		}
	}
	return false, nil
}
