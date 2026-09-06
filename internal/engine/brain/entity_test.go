// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"reflect"
	"testing"
)

// TestEntityObserved_MergesByLabelAndKey: a second sighting of the same
// (Label, Key) enriches the entity it already holds rather than adding a
// second one. That is what makes one CVE across four Applications one
// Vulnerability node (gibson#1656).
func TestEntityObserved_MergesByLabelAndKey(t *testing.T) {
	w := NewWorld("t")

	Reduce(w, EntityObserved{
		Label: "Vulnerability", Key: "CVE-2025-1234", ScopeID: "s", MissionID: "m1",
		Props: map[string]string{"severity": "high"},
	})
	Reduce(w, EntityObserved{
		Label: "Vulnerability", Key: "CVE-2025-1234", ScopeID: "s", MissionID: "m2",
		Props: map[string]string{"epss": "0.7"},
	})

	got := w.EntitySnapshot()
	if len(got) != 1 {
		t.Fatalf("two sightings of one CVE must be one entity, got %d: %+v", len(got), got)
	}
	want := map[string]string{"severity": "high", "epss": "0.7"}
	if !reflect.DeepEqual(got[0].Props, want) {
		t.Fatalf("properties must overlay:\n got %+v\nwant %+v", got[0].Props, want)
	}
	// The first sighting's mission is the one that observed it into being.
	if got[0].MissionID != "m1" {
		t.Fatalf("mission id must not be overwritten by a later sighting: %q", got[0].MissionID)
	}
}

// TestEntityObserved_DistinctLabelsAndKeysStayDistinct: identity is the pair,
// so neither half alone collapses two entities.
func TestEntityObserved_DistinctLabelsAndKeysStayDistinct(t *testing.T) {
	w := NewWorld("t")

	Reduce(w, EntityObserved{Label: "Package", Key: "lodash@4.17.20"})
	Reduce(w, EntityObserved{Label: "Package", Key: "lodash@4.17.21"})
	// Same key, different label: an Image digest and a Repository could collide
	// on a key string without the label in the identity.
	Reduce(w, EntityObserved{Label: "Image", Key: "shared-key"})
	Reduce(w, EntityObserved{Label: "Repository", Key: "shared-key"})

	if got := w.EntitySnapshot(); len(got) != 4 {
		t.Fatalf("identity is (label, key); want 4 entities, got %d: %+v", len(got), got)
	}
}

// TestEntityObserved_EdgesUnionAndNeverDuplicate: re-observing the same edge
// adds nothing, so re-projection cannot duplicate a relationship.
func TestEntityObserved_EdgesUnionAndNeverDuplicate(t *testing.T) {
	w := NewWorld("t")
	edge := EntityEdge{Type: "CONTAINS", TargetLabel: "Package", TargetKey: "lodash@4.17.20"}
	other := EntityEdge{Type: "BUILT_FROM", TargetLabel: "Repository", TargetKey: "gitlab.com/examplebank/customer-portal"}

	Reduce(w, EntityObserved{Label: "Image", Key: "sha256:abc", Edges: []EntityEdge{edge}})
	Reduce(w, EntityObserved{Label: "Image", Key: "sha256:abc", Edges: []EntityEdge{edge, other}})

	got := w.EntitySnapshot()
	if len(got) != 1 {
		t.Fatalf("want 1 entity, got %d", len(got))
	}
	want := []EntityEdge{edge, other}
	if !reflect.DeepEqual(got[0].Edges, want) {
		t.Fatalf("edges must union in order:\n got %+v\nwant %+v", got[0].Edges, want)
	}
}

// TestEntityObserved_IncompleteSightingsRecordNothing: an entity with no label
// or no key has no stable node to project, and a malformed edge is dropped
// rather than projected as a half-edge.
func TestEntityObserved_IncompleteSightingsRecordNothing(t *testing.T) {
	w := NewWorld("t")

	Reduce(w, EntityObserved{Label: "", Key: "k"})
	Reduce(w, EntityObserved{Label: "Application", Key: ""})
	if got := w.EntitySnapshot(); len(got) != 0 {
		t.Fatalf("an entity without both halves of its identity must record nothing, got %+v", got)
	}

	Reduce(w, EntityObserved{Label: "Application", Key: "customer-portal", Edges: []EntityEdge{
		{Type: "", TargetLabel: "Repository", TargetKey: "r"},
		{Type: "HAS_REPOSITORY", TargetLabel: "", TargetKey: "r"},
		{Type: "HAS_REPOSITORY", TargetLabel: "Repository", TargetKey: ""},
	}})
	got := w.EntitySnapshot()
	if len(got) != 1 {
		t.Fatalf("want the entity itself, got %d", len(got))
	}
	if len(got[0].Edges) != 0 {
		t.Fatalf("an edge missing any of its three parts must be dropped, got %+v", got[0].Edges)
	}
}

// TestEntitySnapshot_IsDeterministic: the snapshot orders by (label, key) so
// replay and projection are reproducible regardless of insertion order.
func TestEntitySnapshot_IsDeterministic(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, EntityObserved{Label: "Repository", Key: "z"})
	Reduce(w, EntityObserved{Label: "Application", Key: "b"})
	Reduce(w, EntityObserved{Label: "Application", Key: "a"})

	got := w.EntitySnapshot()
	want := [][2]string{{"Application", "a"}, {"Application", "b"}, {"Repository", "z"}}
	if len(got) != len(want) {
		t.Fatalf("want %d entities, got %d", len(want), len(got))
	}
	for i, w2 := range want {
		if got[i].Label != w2[0] || got[i].Key != w2[1] {
			t.Fatalf("order at %d: got (%s,%s) want (%s,%s)", i, got[i].Label, got[i].Key, w2[0], w2[1])
		}
	}
}

// TestEntityObserved_ReplayReproducesTheWorld: entities are folded from the
// Timeline like every other component, so a replay is identical.
func TestEntityObserved_ReplayReproducesTheWorld(t *testing.T) {
	tl := &Timeline{}
	w := NewWorld("t")
	apply := func(ev Event) { tl.Append(ev); Reduce(w, ev) }

	apply(EntityObserved{
		Label: "Application", Key: "customer-portal", ScopeID: "s", MissionID: "m",
		Props: map[string]string{"name": "Customer Portal"},
		Edges: []EntityEdge{{Type: "HAS_REPOSITORY", TargetLabel: "Repository", TargetKey: "r1"}},
	})
	apply(EntityObserved{Label: "Vulnerability", Key: "CVE-2025-1234"})

	want := w.EntitySnapshot()
	if got := Replay("t", tl).EntitySnapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("replay diverged:\n got %+v\nwant %+v", got, want)
	}
}

// TestSnapshotRestore_RoundTripsEntities: a World restored from a snapshot
// holds the same entities and resumes the same id counter, so ids that already
// rode to the graph are never reissued.
func TestSnapshotRestore_RoundTripsEntities(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, EntityObserved{
		Label: "Image", Key: "sha256:abc", ScopeID: "s", MissionID: "m",
		Props: map[string]string{"tag": "v1"},
		Edges: []EntityEdge{{Type: "CONTAINS", TargetLabel: "Package", TargetKey: "lodash@4.17.20"}},
	})
	Reduce(w, EntityObserved{Label: "Package", Key: "lodash@4.17.20"})

	restored, err := RestoreWorld(SnapshotWorld(w, "seq-1"), "t")
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got, want := restored.EntitySnapshot(), w.EntitySnapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("entities did not round-trip:\n got %+v\nwant %+v", got, want)
	}
	if restored.nextEntityID != w.nextEntityID {
		t.Fatalf("id counter must be restored exactly: got %d want %d",
			restored.nextEntityID, w.nextEntityID)
	}
}
