// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"reflect"
	"testing"
)

// TestDomainPack_EnableDisable_ReplayReproducesTheWorld is the core gibson#381
// determinism unit: World == fold(Timeline) for enable/disable, mirroring
// TestFlightRecorder_ReplayReproducesTheWorld for the other per-tenant
// singleton-shaped state.
func TestDomainPack_EnableDisable_ReplayReproducesTheWorld(t *testing.T) {
	tl := &Timeline{}
	w := NewWorld("tenant-1")
	apply := func(ev Event) { tl.Append(ev); Reduce(w, ev) }

	apply(DomainPackEnabled{
		Name:                      "main",
		Version:                   1,
		TaxonomyNodeLabels:        []string{"Container"},
		TaxonomyRelationshipTypes: []string{"RUNS_ON"},
		Predicates:                map[string]string{"privilege_escalation": `evidence.exists(e, e.kind == "root_shell")`},
	})
	apply(DomainPackEnabled{Name: "k8s", Version: 2})
	apply(DomainPackDisabled{Name: "k8s"})

	want := w.DomainPackSnapshot()
	if len(want) != 1 || want[0].Name != "main" {
		t.Fatalf("DomainPackSnapshot() = %+v, want exactly [main]", want)
	}

	replayed := Replay("tenant-1", tl)
	if got := replayed.DomainPackSnapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("DomainPack replay diverged:\n got %+v\nwant %+v", got, want)
	}
}

// TestDomainPack_Enable_IsPerTenant proves enablement is structurally
// per-tenant (ADR-0033 decision 1, "per-tenant, not per-install"): enabling a
// pack in one tenant's World never affects another's.
func TestDomainPack_Enable_IsPerTenant(t *testing.T) {
	acme := NewWorld("acme")
	other := NewWorld("other")

	Reduce(acme, DomainPackEnabled{Name: "main", Version: 1})

	if !acme.IsDomainPackEnabled("main") {
		t.Fatal("acme should have main enabled")
	}
	if other.IsDomainPackEnabled("main") {
		t.Fatal("other tenant must never see acme's enabled pack")
	}
}

// TestDomainPack_Disable_RemovesContent proves DomainPackDisabled removes the
// pack's bindings from the tenant's live registry entirely — ADR-0033
// decision 4's "disabling removes them" — rather than merely marking it
// inactive while leaving stale content queryable.
func TestDomainPack_Disable_RemovesContent(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, DomainPackEnabled{
		Name:       "main",
		Version:    1,
		Predicates: map[string]string{"lateral_movement": "true"},
	})
	if _, ok := w.DomainPackPredicate("lateral_movement"); !ok {
		t.Fatal("predicate must be live while the pack is enabled")
	}

	Reduce(w, DomainPackDisabled{Name: "main"})

	if w.IsDomainPackEnabled("main") {
		t.Fatal("pack must no longer be enabled")
	}
	if _, ok := w.DomainPackPredicate("lateral_movement"); ok {
		t.Fatal("a disabled pack's predicate bindings must no longer be live")
	}
	if got := w.DomainPackSnapshot(); len(got) != 0 {
		t.Fatalf("DomainPackSnapshot() = %+v, want empty after disable", got)
	}
}

// TestDomainPack_DisableUnknownPack_IsNoOp proves disabling a pack that was
// never enabled (or already disabled) is a harmless no-op, not a panic —
// defensive against a duplicate or out-of-order Disable.
func TestDomainPack_DisableUnknownPack_IsNoOp(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, DomainPackDisabled{Name: "never-enabled"})
	if got := w.DomainPackSnapshot(); len(got) != 0 {
		t.Fatalf("DomainPackSnapshot() = %+v, want empty", got)
	}
}

// TestDomainPack_ReEnable_OverwritesVersion proves enabling an
// already-enabled pack again (e.g. a version bump) replaces its state
// wholesale rather than merging — matching ADR-0033 decision 4's
// "version-pinned for replay": only the most recently enabled version's
// content is ever live.
func TestDomainPack_ReEnable_OverwritesVersion(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, DomainPackEnabled{Name: "main", Version: 1, Predicates: map[string]string{"a": "old"}})
	Reduce(w, DomainPackEnabled{Name: "main", Version: 2, Predicates: map[string]string{"b": "new"}})

	got := w.DomainPackSnapshot()
	if len(got) != 1 || got[0].Version != 2 {
		t.Fatalf("DomainPackSnapshot() = %+v, want version 2 only", got)
	}
	if _, ok := w.DomainPackPredicate("a"); ok {
		t.Fatal("the old version's predicate must not survive a re-enable")
	}
	if _, ok := w.DomainPackPredicate("b"); !ok {
		t.Fatal("the new version's predicate must be live")
	}
}

// TestDomainPack_SnapshotRoundTrips proves a hydrate-on-restart (snapshot +
// restore) reproduces the tenant's enabled packs — mirroring
// TestFlightRecorder_SnapshotRoundTrips. Missing this would silently drop a
// tenant's enabled Domain Packs across a snapshot+trim cycle (the same
// gibson#341-shaped hazard VoIPlans documents).
func TestDomainPack_SnapshotRoundTrips(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, DomainPackEnabled{
		Name:                      "main",
		Version:                   3,
		TaxonomyNodeLabels:        []string{"Container"},
		TaxonomyRelationshipTypes: []string{"RUNS_ON"},
		Predicates:                map[string]string{"privilege_escalation": "true"},
	})

	restored, err := RestoreWorld(SnapshotWorld(w, "seq-1"), "t")
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got, want := restored.DomainPackSnapshot(), w.DomainPackSnapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("DomainPacks did not round-trip:\n got %+v\nwant %+v", got, want)
	}
	if !restored.IsDomainPackEnabled("main") {
		t.Fatal("tenant's enabled pack must survive a snapshot restore")
	}
}

// TestDomainPack_MutatingSnapshotNeverAliasesWorldState proves
// DomainPackSnapshot returns defensive copies: mutating the returned slices
// must never corrupt the World's own state, matching the copy discipline
// every other *Snapshot accessor in this package follows.
func TestDomainPack_MutatingSnapshotNeverAliasesWorldState(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, DomainPackEnabled{
		Name:               "main",
		TaxonomyNodeLabels: []string{"Container"},
		Predicates:         map[string]string{"a": "expr"},
	})

	snap := w.DomainPackSnapshot()
	snap[0].TaxonomyNodeLabels[0] = "TAMPERED"
	snap[0].Predicates["a"] = "TAMPERED"

	again := w.DomainPackSnapshot()
	if again[0].TaxonomyNodeLabels[0] != "Container" {
		t.Fatalf("World state aliased through TaxonomyNodeLabels: got %q", again[0].TaxonomyNodeLabels[0])
	}
	if again[0].Predicates["a"] != "expr" {
		t.Fatalf("World state aliased through Predicates: got %q", again[0].Predicates["a"])
	}
}

// TestEngine_DomainPacks exercises the Engine-level read accessor (the
// locked-wrapper counterpart to World.DomainPackSnapshot), mirroring
// TestEngine_AgentToolCallsAndFlightRecorderPolicy.
func TestEngine_DomainPacks(t *testing.T) {
	e := NewEngine("t1")
	e.Submit(DomainPackEnabled{Name: "main", Version: 1})
	e.Tick()

	got := e.DomainPacks()
	if len(got) != 1 || got[0].Name != "main" {
		t.Fatalf("Engine.DomainPacks() = %+v, want [main]", got)
	}
}

// TestDomainPackEvents_CodecRoundTrip proves DomainPackEnabled/Disabled
// survive the durable Timeline's JSON envelope round trip (EncodeEvent/
// DecodeEvent) — required for durable persistence (ADR-0011) and for the
// codec's kind registry to stay complete.
func TestDomainPackEvents_CodecRoundTrip(t *testing.T) {
	events := []Event{
		DomainPackEnabled{
			Name:                      "main",
			Version:                   1,
			TaxonomyNodeLabels:        []string{"Container"},
			TaxonomyRelationshipTypes: []string{"RUNS_ON"},
			Predicates:                map[string]string{"a": "expr"},
		},
		DomainPackDisabled{Name: "main"},
	}
	for _, ev := range events {
		t.Run(ev.Kind(), func(t *testing.T) {
			b, err := EncodeEvent(ev)
			if err != nil {
				t.Fatalf("EncodeEvent: %v", err)
			}
			decoded, err := DecodeEvent(b)
			if err != nil {
				t.Fatalf("DecodeEvent: %v", err)
			}
			if !reflect.DeepEqual(decoded, ev) {
				t.Fatalf("round trip: got %#v (%T), want %#v", decoded, decoded, ev)
			}
		})
	}
}
