// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package settlement

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"

	"github.com/zeroroot-ai/gibson/internal/engine/finding"
)

// Registry is the technique -> predicate-type -> [Evaluator] table.
//
// A technique registers the predicate types it defines — in practice, a
// Domain Pack loader calls Register once per predicate type the technique
// declares, when the Pack loads. Nothing else may add a predicate type for
// a technique it does not own: NewPredicate and Evaluate both fail closed
// ([ErrUnregisteredPredicate]) for any (technique, type) pair no one has
// registered. This is the seam ADR-0027 decision 3 requires, and it is the
// only way settlement code should ever construct or evaluate a [Predicate].
//
// The zero value is not usable; construct one with [NewRegistry]. A
// Registry is safe for concurrent use.
type Registry struct {
	mu         sync.RWMutex
	evaluators map[TechniqueID]map[PredicateType]Evaluator
}

// NewRegistry returns an empty, ready-to-use Registry.
func NewRegistry() *Registry {
	return &Registry{
		evaluators: make(map[TechniqueID]map[PredicateType]Evaluator),
	}
}

// Register adds an Evaluator for one (technique, type) pair. It returns an
// error wrapping:
//   - [ErrEmptyTechnique] or [ErrEmptyPredicateType] if either identifier is
//     empty or whitespace-only;
//   - [ErrNilEvaluator] if eval is nil;
//   - [ErrAlreadyRegistered] if the pair is already registered.
//
// Register never overwrites an existing entry. Call sites that legitimately
// need to redefine a predicate type must build a new Registry (or a new
// predicate type name) rather than mutate one in place, so an evaluator a
// settled bet was replayed against can never change out from under it.
func (r *Registry) Register(technique TechniqueID, ptype PredicateType, eval Evaluator) error {
	if err := technique.Validate(); err != nil {
		return err
	}
	if err := ptype.Validate(); err != nil {
		return err
	}
	if eval == nil {
		return fmt.Errorf("%w: technique %q, type %q", ErrNilEvaluator, technique, ptype)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	byType, ok := r.evaluators[technique]
	if !ok {
		byType = make(map[PredicateType]Evaluator)
		r.evaluators[technique] = byType
	}
	if _, exists := byType[ptype]; exists {
		return fmt.Errorf("%w: technique %q, type %q", ErrAlreadyRegistered, technique, ptype)
	}
	byType[ptype] = eval
	return nil
}

// MustRegister is [Registry.Register], but it panics on error. It is meant
// for package-init-time registration of built-in predicate types (mirroring
// the standard library's driver-registration pattern), where a registration
// error is a programming mistake, not a runtime condition to handle.
func (r *Registry) MustRegister(technique TechniqueID, ptype PredicateType, eval Evaluator) {
	if err := r.Register(technique, ptype, eval); err != nil {
		panic(err)
	}
}

// Registered reports whether (technique, type) has a registered Evaluator.
func (r *Registry) Registered(technique TechniqueID, ptype PredicateType) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	byType, ok := r.evaluators[technique]
	if !ok {
		return false
	}
	_, ok = byType[ptype]
	return ok
}

// Types returns the predicate types registered for technique, sorted for
// deterministic output. It returns an empty slice for a technique with no
// registrations.
func (r *Registry) Types(technique TechniqueID) []PredicateType {
	r.mu.RLock()
	defer r.mu.RUnlock()

	byType := r.evaluators[technique]
	types := make([]PredicateType, 0, len(byType))
	for t := range byType {
		types = append(types, t)
	}
	sort.Slice(types, func(i, j int) bool { return types[i] < types[j] })
	return types
}

// NewPredicate builds a [Predicate] for a registered (technique, type)
// pair, encoding params to JSON. It returns [ErrUnregisteredPredicate]
// wrapped with the offending technique and type if the pair has no
// registered Evaluator — an agent settling a bet can only ever construct a
// predicate its technique actually defines.
//
// params may be nil (an empty object is stored), a json.RawMessage (used
// as-is, so callers that already hold encoded params avoid a re-encode),
// or any value accepted by [json.Marshal].
func (r *Registry) NewPredicate(technique TechniqueID, ptype PredicateType, params any) (Predicate, error) {
	if !r.Registered(technique, ptype) {
		return Predicate{}, fmt.Errorf("%w: technique %q, type %q", ErrUnregisteredPredicate, technique, ptype)
	}

	raw, err := encodeParams(params)
	if err != nil {
		return Predicate{}, fmt.Errorf("settlement: encode params for technique %q, type %q: %w", technique, ptype, err)
	}

	return Predicate{Technique: technique, Type: ptype, Params: raw}, nil
}

func encodeParams(params any) (json.RawMessage, error) {
	switch v := params.(type) {
	case nil:
		return nil, nil
	case json.RawMessage:
		return v, nil
	default:
		data, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("settlement: marshal params: %w", err)
		}
		return data, nil
	}
}

// Evaluate deterministically checks predicate against evidence: it resolves
// predicate.Technique and predicate.Type to a registered [Evaluator] and
// calls it. It returns [ErrUnregisteredPredicate], wrapped with the
// offending technique and type, if no Evaluator is registered — this is
// the fail-closed path replay takes if a predicate names a technique or
// type the current Registry does not know, rather than treating an unknown
// predicate as vacuously true.
//
// Evaluate checks ctx for cancellation before calling the Evaluator, but
// the Evaluator itself is not given ctx: an Evaluator's result must depend
// only on params and evidence, never on how long evaluation is allowed to
// run, so that replay is exact.
func (r *Registry) Evaluate(ctx context.Context, predicate Predicate, evidence []finding.EnhancedEvidence) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, fmt.Errorf("settlement: %w", err)
	}
	if err := predicate.Validate(); err != nil {
		return false, err
	}

	r.mu.RLock()
	var eval Evaluator
	if byType, ok := r.evaluators[predicate.Technique]; ok {
		eval = byType[predicate.Type]
	}
	r.mu.RUnlock()

	if eval == nil {
		return false, fmt.Errorf("%w: technique %q, type %q", ErrUnregisteredPredicate, predicate.Technique, predicate.Type)
	}

	ok, err := eval(predicate.Params, evidence)
	if err != nil {
		return false, fmt.Errorf("settlement: evaluate technique %q, type %q: %w", predicate.Technique, predicate.Type, err)
	}
	return ok, nil
}
