// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package beliefvi is the native Go belief-runtime engine (ADR-0034,
// gibson#377): exact variable elimination over a discrete Bayesian network,
// plus the noisy-OR enablement-CPT decomposition (ADR-0029 SS6) and the
// bounded-slice grounding it feeds (ADR-0029 SS5), all in-process.
//
// It is a line-for-line port of the algorithm sidecar/belief/{infer,noisy_or,
// ground,model}.py ran as the (now-retired) Python belief sidecar — see
// ADR-0034 for why the port exists and docs/adr/0005-belief-field-pgm.md /
// docs/adr/0029-belief-is-a-relational-prm-over-the-graph.md for the algorithm
// this replaces. Variable elimination is EXACT inference (sum-product over
// the factor set in some elimination order); the order changes the cost,
// never the answer, so this package's answers agree with pgmpy's
// VariableElimination to 1e-12 — CI's parity test (parity_test.go) asserts
// this directly against a fixture the retained sidecar/belief Python package
// generates offline (pgmpy stays ONLY as that oracle; it is never imported by
// this package or shipped in any runtime image).
//
// Determinism (ADR-0005, replay). Every public entry point is a pure function
// of its inputs: no clock, no goroutine-scheduling-dependent iteration, no Go
// map iterated directly for a result that numeric output depends on. Variable
// order within a factor is preserved exactly as declared; the elimination
// order is derived deterministically from the factor set (see
// eliminationOrder). Identical inputs therefore produce bit-identical
// float64 outputs on the same build, which is what mission replay needs.
//
// Every variable in this package is binary ("false"/"true", see States) —
// the same restriction infer.py declared; noisy-MAX (ADR-0029 SS6 names both)
// would generalise to multi-valued variables, which nothing in this codebase
// has yet.
package beliefvi
