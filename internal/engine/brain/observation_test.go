// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"reflect"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
)

// TestObservationRecorded_FoldDedupReplay proves the Observation fold: identity
// is the Timeline event id, folding the same event twice is a no-op, two
// sightings of the same fact stay distinct, and the whole thing survives replay.
//
// The distinctness case is the one that matters: "seen again three weeks later"
// is signal in this domain, so a content-hash identity — the obvious wrong
// choice — would silently collapse the input Sensing needs to promote a shape
// (ADR-0012).
func TestObservationRecorded_FoldDedupReplay(t *testing.T) {
	tl := &Timeline{}
	w := NewWorld("t")
	apply := func(ev Event) { tl.Append(ev); Reduce(w, ev) }

	payload := map[string]string{"tool": "nuclei", "note": "novel shape"}

	apply(ObservationRecorded{EventID: "e1", ScopeID: "s", MissionID: "m", Shape: "weird_thing", Payload: payload, ObservedAt: 100})
	apply(ObservationRecorded{EventID: "e1", ScopeID: "s", MissionID: "m", Shape: "weird_thing", Payload: payload, ObservedAt: 100}) // replay of the same event
	apply(ObservationRecorded{EventID: "e2", ScopeID: "s", MissionID: "m", Shape: "weird_thing", Payload: payload, ObservedAt: 200}) // seen again later
	apply(ObservationRecorded{EventID: "", ScopeID: "s", Shape: "no_identity"})                                                      // no Timeline id: records nothing

	got := w.ObservationSnapshot()
	if len(got) != 2 {
		t.Fatalf("observations: got %d, want 2 (dedupe by event id, distinct sightings kept): %+v", len(got), got)
	}
	if got[0].EventID != "e1" || got[1].EventID != "e2" {
		t.Fatalf("observations are not in deterministic event-id order: %+v", got)
	}
	if got[0].ID == got[1].ID {
		t.Fatalf("two sightings share a world id %d — they must be distinct nodes", got[0].ID)
	}
	if got[0].ContentHash == "" || got[0].ContentHash != got[1].ContentHash {
		t.Fatalf("same fact must carry the same content hash for recurrence detection: %q vs %q",
			got[0].ContentHash, got[1].ContentHash)
	}
	if got[0].ContentHash != taxonomy.ContentHash("weird_thing", payload) {
		t.Fatalf("content hash is not the taxonomy hash of the shape+payload: %q", got[0].ContentHash)
	}
	if got[0].ObservedAt != 100 || got[1].ObservedAt != 200 {
		t.Fatalf("sighting times not preserved: %+v", got)
	}

	r := Replay("t", tl)
	if !reflect.DeepEqual(r.ObservationSnapshot(), got) {
		t.Fatalf("replay diverged:\n got %+v\nwant %+v", r.ObservationSnapshot(), got)
	}

	// The snapshot must not hand out the World's own payload map.
	got[0].Payload["tool"] = "mutated"
	if again := w.ObservationSnapshot(); again[0].Payload["tool"] != "nuclei" {
		t.Fatalf("ObservationSnapshot aliased the stored payload: %+v", again[0].Payload)
	}

	// The reducer must not alias the caller's map either.
	payload["tool"] = "caller-mutated"
	if again := w.ObservationSnapshot(); again[0].Payload["tool"] != "nuclei" {
		t.Fatalf("applyObservationRecorded aliased the event payload: %+v", again[0].Payload)
	}
}

// TestObservationRecorded_SnapshotRestore proves observations survive the
// snapshot/restore path with identity and id counters intact — the projector
// keys on the event id, so a restore that renumbered or dropped them would
// re-project the same fact as a new node.
func TestObservationRecorded_SnapshotRestore(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, ObservationRecorded{EventID: "e2", ScopeID: "s", Shape: "b", Payload: map[string]string{"k": "v"}, ObservedAt: 2})
	Reduce(w, ObservationRecorded{EventID: "e1", ScopeID: "s", Shape: "a", ObservedAt: 1})

	restored, err := RestoreWorld(SnapshotWorld(w, "5-0"), "t")
	if err != nil {
		t.Fatalf("RestoreWorld: %v", err)
	}
	if !reflect.DeepEqual(restored.ObservationSnapshot(), w.ObservationSnapshot()) {
		t.Fatalf("restore diverged:\n got %+v\nwant %+v", restored.ObservationSnapshot(), w.ObservationSnapshot())
	}

	// A further observation must not reuse an id the restored world already holds.
	Reduce(w, ObservationRecorded{EventID: "e3", Shape: "c"})
	Reduce(restored, ObservationRecorded{EventID: "e3", Shape: "c"})
	if !reflect.DeepEqual(restored.ObservationSnapshot(), w.ObservationSnapshot()) {
		t.Fatalf("id counter not restored:\n got %+v\nwant %+v", restored.ObservationSnapshot(), w.ObservationSnapshot())
	}
}

// TestObservationRecorded_CodecRoundTrip proves observation.recorded survives
// the Timeline wire codec. Without registration, a restart would decode the
// durable event as nothing and the Observation would vanish from the World.
func TestObservationRecorded_CodecRoundTrip(t *testing.T) {
	ev := ObservationRecorded{EventID: "e1", ScopeID: "s", MissionID: "m", Shape: "weird_thing",
		Payload: map[string]string{"k": "v"}, ObservedAt: 42}

	b, err := EncodeEvent(ev)
	if err != nil {
		t.Fatalf("EncodeEvent: %v", err)
	}
	decoded, err := DecodeEvent(b)
	if err != nil {
		t.Fatalf("DecodeEvent: %v", err)
	}
	if got, ok := decoded.(ObservationRecorded); !ok || !reflect.DeepEqual(got, ev) {
		t.Fatalf("round trip: got %#v (%T), want %#v", decoded, decoded, ev)
	}
	if ev.Kind() != "observation.recorded" {
		t.Fatalf("kind: got %q", ev.Kind())
	}
}

// TestEngineObservations exposes the engine-level read the projector consumes.
func TestEngineObservations(t *testing.T) {
	e := NewEngine("t")
	if got := e.Observations(); len(got) != 0 {
		t.Fatalf("fresh engine: got %d observations, want 0", len(got))
	}
	Reduce(e.World, ObservationRecorded{EventID: "e1", Shape: "weird_thing"})
	got := e.Observations()
	if len(got) != 1 || got[0].EventID != "e1" {
		t.Fatalf("Engine.Observations: got %+v", got)
	}
}
