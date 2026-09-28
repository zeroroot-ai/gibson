// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package settlement provides the typed success-predicate framework behind
// proof-of-demonstration (ADR-0027, gibson#278).
//
// # Overview
//
// A Bet settles TRUE only when a machine-checkable success predicate fires
// against captured evidence — never by an LLM opinion, and never by a
// free-form condition an agent invents for itself. A [PredicateType] is
// scoped to a [TechniqueID]: only the technique's owner (the Domain Pack
// loader) may register the predicate types that technique may use. This is
// what keeps settlement un-gameable (ADR-0027, decision 3).
//
// # Key types
//
//   - [TechniqueID] identifies the technique a predicate belongs to.
//   - [PredicateType] names one kind of machine-checkable condition.
//   - [Predicate] is plain, JSON-serializable data: a (technique, type,
//     params) triple that can be stored on the graph next to the Hypothesis
//     it belongs to and re-evaluated later without re-executing anything.
//   - [Evaluator] is the pure function that checks a predicate's params
//     against captured evidence. It never calls an LLM and never consults
//     wall-clock time, randomness, or any other nondeterministic input:
//     the same predicate and the same evidence always yield the same
//     result, so replay reproduces settlement exactly (ADR-0027, decision 2).
//   - [Registry] is the technique -> predicate-type -> [Evaluator] table.
//     A technique (via its Domain Pack) registers the predicate types it
//     defines; nothing else may add one on its behalf.
//
// # What this package does not do
//
// This package has no opinion on what a Bet or a Hypothesis is, and it does
// not fold Hypothesis observations or settle bets. It is the deterministic
// evaluation primitive later settlement code plugs into: construct a
// [Predicate] through a [Registry] when a hypothesis names its success
// condition, then call [Registry.Evaluate] against the evidence captured by
// a demonstration to get the TRUE/FALSE settlement verdict.
package settlement
