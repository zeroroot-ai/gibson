// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package celenv is the gibson-owned CEL environment a Domain Pack's
// settlement predicate compiles and evaluates against (ADR-0131, gibson#388,
// epic #376). ADR-0131 makes a Pack's Predicates map
// (internal/engine/ontology.DomainPack.Predicates, gibson#398) the SOLE
// binding source for a technique's success predicate: no Go evaluator is
// ever registered per technique. ADR-0131 makes the environment
// itself — the evidence schema plus a curated helper-function catalog — the
// seam gibson owns and version-controls; a predicate that stays within it
// compiles, type-checks, and evaluates with no gibson change at all.
//
// # Key types and functions
//
//   - [NewEnv] builds the environment: one variable, "evidence" (the
//     recorded []finding.EnhancedEvidence for a bet's demonstration,
//     exposed as its own schema — type/title/content/timestamp — see
//     evidence.go), plus the helper-function catalog in functions.go
//     (evidenceText, regexMatch, jsonPath, httpStatus, markerPresent).
//   - [Compile] parses, type-checks, and builds an executable program from
//     one predicate expression. It fails closed (ADR-0131): a
//     reference to any variable or function the environment does not
//     declare is a compile-time "undeclared reference" error, never a
//     silently-wrong runtime answer, and a predicate whose checked result
//     type is not bool is rejected before it is ever run.
//   - [CompiledPredicate.Evaluate] runs a compiled predicate over a
//     recorded evidence set and returns its boolean verdict.
//   - [LoadDomainPack] is the loader: it compiles and type-checks every
//     entry in a DomainPack's Predicates map against one shared
//     environment, keyed by technique, failing the WHOLE load (no partial
//     result) on the first predicate that does not compile.
//
// # Safety
//
// CEL is non-Turing-complete and terminating, with no side effects (ADR-0131):
// evaluating an untrusted pack's expression is bounded and
// safe by construction. [EvaluationCostLimit] is a defense-in-depth ceiling
// on top of that, not what makes evaluation safe to begin with — it mirrors
// the same conservative limit internal/engine/brain/condition.go already
// uses for mission condition nodes, the other cel-go consumer in this repo.
//
// # What this package does not do
//
// This package does not read or write a Bet, a Hypothesis, or the graph. It
// is the deterministic compile/evaluate primitive that gibson#389's
// SubmitProof RPC handler calls: name a pack's technique, resolve its
// [CompiledPredicate] (via [LoadDomainPack]), and call Evaluate against the
// evidence the agent posted.
package celenv
