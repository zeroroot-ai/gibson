// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import "testing"

// A nil target store must yield a nil INTERFACE, not a typed nil.
//
// The harness decides whether to look a target up at all with
// `h.targetFacts == nil`. A typed nil wrapped in a non-nil interface passes
// that check and then panics on the call — so a daemon running without Redis
// would crash on the first sandboxed tool dispatch instead of dispatching
// without target facts (gibson#485).
func TestTargetFactsLookup_NilStoreIsANilInterface(t *testing.T) {
	d := &daemonImpl{}

	got := d.targetFactsLookup()
	if got != nil {
		t.Fatalf("a nil target store produced a non-nil interface (%T); the harness "+
			"nil check would pass and the first tool dispatch would panic", got)
	}
}

// And a configured store is handed through.
func TestTargetFactsLookup_ConfiguredStoreIsReturned(t *testing.T) {
	d := &daemonImpl{targetStore: &fakeTargetStoreForMission{}}

	if d.targetFactsLookup() == nil {
		t.Fatal("a configured target store was dropped; tools would get no target facts")
	}
}
