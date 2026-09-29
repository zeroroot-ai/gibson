// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package celenv

import (
	"errors"
	"fmt"
	"sort"

	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
)

// ErrNilDomainPack is returned by LoadDomainPack when given a nil pack.
var ErrNilDomainPack = errors.New("celenv: domain pack must not be nil")

// LoadDomainPack compiles and type-checks every predicate expression in
// pack.Predicates (ADR-0031 decision 1, gibson#398) against the
// gibson-owned CEL environment ([NewEnv]), returning them keyed by
// technique name. It builds one environment and reuses it across every
// predicate in the pack, rather than paying [NewEnv]'s declaration cost once
// per technique.
//
// LoadDomainPack fails closed (ADR-0031 decisions 1 and 2), with no partial
// result:
//   - pack.Validate() runs first, so a pack with a structurally malformed
//     predicate (wrong technique-name shape, non-UTF-8 or over-length
//     expression text — see internal/engine/ontology.DomainPack.Validate)
//     never reaches CEL compilation at all;
//   - the first predicate that fails [CompileWithEnv] — a syntax error, a
//     reference to a variable or function the environment does not
//     declare, or a non-bool result type — fails the WHOLE load, wrapped
//     with the offending technique's name. A pack that ships one bad
//     predicate loads none of them.
func LoadDomainPack(pack *ontology.DomainPack) (map[string]*CompiledPredicate, error) {
	if pack == nil {
		return nil, ErrNilDomainPack
	}
	if err := pack.Validate(); err != nil {
		return nil, fmt.Errorf("celenv: load domain pack %q: %w", pack.Name, err)
	}
	if len(pack.Predicates) == 0 {
		return map[string]*CompiledPredicate{}, nil
	}

	env, err := NewEnv()
	if err != nil {
		return nil, fmt.Errorf("celenv: load domain pack %q: %w", pack.Name, err)
	}

	// Sorted so a pack with more than one bad predicate always fails on the
	// same technique first, regardless of Go's random map iteration order.
	techniques := make([]string, 0, len(pack.Predicates))
	for technique := range pack.Predicates {
		techniques = append(techniques, technique)
	}
	sort.Strings(techniques)

	compiled := make(map[string]*CompiledPredicate, len(pack.Predicates))
	for _, technique := range techniques {
		cp, err := CompileWithEnv(env, pack.Predicates[technique])
		if err != nil {
			return nil, fmt.Errorf("celenv: load domain pack %q: technique %q: %w", pack.Name, technique, err)
		}
		compiled[technique] = cp
	}
	return compiled, nil
}
