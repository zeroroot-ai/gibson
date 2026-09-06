// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package checks implements the gibsoncheck analyzers — the custom
// go/analysis passes that enforce Gibson's architectural and security
// invariants in CI: tenant scoping, store-client ownership, the daemon's
// K8s-API freedom, the single-writer graph, and more.
//
// One analyzer per file, each exporting a single *analysis.Analyzer that
// tools/gibsoncheck/main.go registers with multichecker. Every analyzer
// file opens with a header stating the invariant it enforces, why the
// rule is shaped the way it is, and — for the security guards — which
// near-miss shapes it deliberately does NOT report. Those negatives are
// part of the contract: a rule that reports correct code gets muted, and
// a muted guard is worse than no guard.
//
// The security-defect-class guards (failopenauthorizer,
// privilegedfallback, fgalistusers, constantverdictdouble) share two
// mechanisms declared here:
//
//   - guard_baseline.txt records findings that predate the guards. It is
//     a two-directional, shrink-only ratchet — see its header and
//     scripts/check-guard-baselines.sh.
//   - suppression directives are PARSED and VALIDATED, never bare. A
//     directive must name a compensating guard (resolved through the
//     type system) or a tracking issue with an expiry. A malformed
//     directive is itself a diagnostic, so opting out is never cheaper
//     than fixing the code.
package checks
