// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package builtin provides reusable, deterministic [settlement.Evaluator]
// implementations that a technique's Domain Pack loader may register under
// its own [settlement.TechniqueID].
//
// These are reference building blocks, not a free-standing predicate
// catalog: registering one of them still requires an explicit call naming
// the technique it belongs to (e.g. RegisterMarkerPresent(registry,
// technique)). That call is expected to happen where a technique's other
// Domain Pack data loads, never at agent/bet-construction time — this
// package does not weaken the anti-gaming property from ADR-0131,
// it just saves every technique from reimplementing the same few
// well-tested checks.
//
// MarkerPresent backs "proof of control by default" (ADR-0131):
// a demonstration proves it could reach, read, or act by capturing a
// benign, out-of-band marker, and MarkerPresent is the deterministic check
// that the marker actually shows up in the captured evidence.
package builtin
