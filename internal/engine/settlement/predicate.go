// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package settlement

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/engine/finding"
)

// TechniqueID identifies the technique (from the ontology / Domain Pack,
// ADR-0124, ADR-0133) that a success predicate belongs to. A predicate
// type is only ever meaningful scoped to the technique that defines it.
type TechniqueID string

// Validate reports whether the technique id is usable. It rejects an empty
// or whitespace-only id; it does not check that the technique exists in any
// Domain Pack, which is the Registry's job.
func (t TechniqueID) Validate() error {
	if strings.TrimSpace(string(t)) == "" {
		return ErrEmptyTechnique
	}
	return nil
}

// String returns the technique id as plain text.
func (t TechniqueID) String() string {
	return string(t)
}

// PredicateType names one kind of machine-checkable success condition, such
// as "marker_present" or "http_status_equals". A PredicateType is meaningful
// only in combination with the [TechniqueID] that registered it: the same
// name registered by two different techniques is two independent entries,
// never a collision (see [Registry]).
type PredicateType string

// Validate reports whether the predicate type is usable. It rejects an
// empty or whitespace-only value; it does not check registration, which is
// the Registry's job.
func (p PredicateType) Validate() error {
	if strings.TrimSpace(string(p)) == "" {
		return ErrEmptyPredicateType
	}
	return nil
}

// String returns the predicate type as plain text.
func (p PredicateType) String() string {
	return string(p)
}

// Predicate is a typed, technique-scoped success condition: "the claim
// holds iff this is observed" (ADR-0131). It is plain,
// JSON-serializable data on purpose — it is stored on the graph next to the
// Hypothesis it belongs to, and replay reconstructs it from that stored
// form to re-run [Registry.Evaluate] without re-executing anything
// (ADR-0131). A Predicate never carries an evaluator function
// itself; the [Registry] resolves (Technique, Type) to an [Evaluator] at
// evaluation time.
type Predicate struct {
	// Technique is the technique this predicate's type was registered
	// under. It is never inferred or free-form (ADR-0131).
	Technique TechniqueID `json:"technique"`

	// Type names the kind of condition, e.g. "marker_present".
	Type PredicateType `json:"type"`

	// Params is the type's own configuration, e.g. which marker string or
	// which HTTP status code to look for. Its shape is defined by the
	// Evaluator registered for (Technique, Type); Predicate itself does
	// not interpret it.
	Params json.RawMessage `json:"params,omitempty"`
}

// Validate reports whether the predicate is well-formed data: a non-empty
// technique and a non-empty type. It does not check that (Technique, Type)
// is registered anywhere — that check happens at construction time via
// [Registry.NewPredicate] and again at evaluation time via
// [Registry.Evaluate], so that replaying a predicate persisted before a
// technique's registration was available fails closed rather than silently
// passing.
func (p Predicate) Validate() error {
	if err := p.Technique.Validate(); err != nil {
		return err
	}
	if err := p.Type.Validate(); err != nil {
		return err
	}
	return nil
}

// Evaluator deterministically checks one predicate's params against
// captured evidence. It must be a pure function of its two inputs: the same
// params and the same evidence slice always yield the same (bool, error)
// result. An Evaluator must never call an LLM, never consult wall-clock
// time or randomness, and never reach outside the evidence it is given —
// that is what makes settlement replayable and un-gameable (ADR-0131).
type Evaluator func(params json.RawMessage, evidence []finding.EnhancedEvidence) (bool, error)

// Sentinel errors returned by this package. Callers should use errors.Is
// against these, since Register and Evaluate wrap them with the offending
// technique and predicate type for a useful message.
var (
	// ErrEmptyTechnique is returned when a TechniqueID is empty or
	// whitespace-only.
	ErrEmptyTechnique = errors.New("settlement: technique id must not be empty")

	// ErrEmptyPredicateType is returned when a PredicateType is empty or
	// whitespace-only.
	ErrEmptyPredicateType = errors.New("settlement: predicate type must not be empty")

	// ErrNilEvaluator is returned by Register when given a nil Evaluator.
	ErrNilEvaluator = errors.New("settlement: evaluator must not be nil")

	// ErrAlreadyRegistered is returned by Register when the given
	// (technique, type) pair already has an Evaluator. Registration is not
	// an overwrite: re-registering the same predicate type could silently
	// change what an already-settled bet would replay to, so it is
	// rejected rather than allowed to shadow the earlier definition.
	ErrAlreadyRegistered = errors.New("settlement: predicate type already registered for technique")

	// ErrUnregisteredPredicate is returned by NewPredicate and Evaluate
	// when the given (technique, type) pair has no registered Evaluator.
	// This is the fail-closed anti-gaming check: a technique with no
	// registered predicate type cannot have one fabricated for it, and a
	// predicate for an unknown type never silently evaluates to true.
	ErrUnregisteredPredicate = errors.New("settlement: predicate type not registered for technique")
)
