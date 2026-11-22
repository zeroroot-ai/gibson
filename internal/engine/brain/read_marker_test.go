// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"reflect"
	"testing"
)

// A marker is read back only by the identity that wrote it, for the Connector
// that it names. Another identity reads nothing (gibson#1569).
func TestReadMarker_OneIdentityReadsOnlyItsOwnMarker(t *testing.T) {
	w := NewWorld("acme")
	Reduce(w, ReadMarkerWritten{Subject: "spiffe://a", Connector: "edr", Cursor: "10", ResultIDs: []string{"r1"}, RecordedAtUnixNano: 1})
	Reduce(w, ReadMarkerWritten{Subject: "spiffe://b", Connector: "edr", Cursor: "99", RecordedAtUnixNano: 2})
	Reduce(w, ReadMarkerWritten{Subject: "spiffe://a", Connector: "siem", Cursor: "5", RecordedAtUnixNano: 3})

	a, ok := w.LastReadMarker("spiffe://a", "edr")
	if !ok || a.Cursor != "10" || !reflect.DeepEqual(a.ResultIDs, []string{"r1"}) {
		t.Fatalf("a/edr = %+v, %v", a, ok)
	}
	b, ok := w.LastReadMarker("spiffe://b", "edr")
	if !ok || b.Cursor != "99" {
		t.Fatalf("b/edr = %+v, %v", b, ok)
	}
	if _, ok := w.LastReadMarker("spiffe://c", "edr"); ok {
		t.Error("an identity that wrote no marker read one")
	}
	if _, ok := w.LastReadMarker("spiffe://b", "siem"); ok {
		t.Error("a marker of another Connector was returned")
	}
}

// The last write wins, and a write with no subject or no Connector is dropped.
func TestReadMarker_LastWriteWins(t *testing.T) {
	w := NewWorld("acme")
	Reduce(w, ReadMarkerWritten{Subject: "s", Connector: "c", Cursor: "1", RecordedAtUnixNano: 1})
	Reduce(w, ReadMarkerWritten{Subject: "s", Connector: "c", Cursor: "2", RecordedAtUnixNano: 2})
	Reduce(w, ReadMarkerWritten{Subject: "", Connector: "c", Cursor: "x", RecordedAtUnixNano: 3})
	Reduce(w, ReadMarkerWritten{Subject: "s", Connector: "", Cursor: "x", RecordedAtUnixNano: 3})
	if m, _ := w.LastReadMarker("s", "c"); m.Cursor != "2" {
		t.Fatalf("cursor = %q, want 2", m.Cursor)
	}
}

// A restart keeps the marker: it survives the codec, a replay and a snapshot.
func TestReadMarker_SurvivesARestart(t *testing.T) {
	events := []Event{
		ReadMarkerWritten{Subject: "s1", Connector: "c", Cursor: "1", ResultIDs: []string{"a", "b"}, RecordedAtUnixNano: 10},
		ReadMarkerWritten{Subject: "s2", Connector: "c", Cursor: "7", RecordedAtUnixNano: 11},
	}
	tl := &Timeline{}
	for _, ev := range events {
		data, err := EncodeEvent(ev)
		if err != nil {
			t.Fatalf("EncodeEvent: %v", err)
		}
		back, err := DecodeEvent(data)
		if err != nil {
			t.Fatalf("DecodeEvent: %v", err)
		}
		tl.Append(back)
	}
	w := Replay("acme", tl)
	if m, ok := w.LastReadMarker("s1", "c"); !ok || m.Cursor != "1" {
		t.Fatalf("a replay lost the marker: %+v, %v", m, ok)
	}
	restored, err := RestoreWorld(SnapshotWorld(w, "seq-1"), "acme")
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got, want := restored.ReadMarkerSnapshot(), w.ReadMarkerSnapshot(); !reflect.DeepEqual(got, want) || len(got) != 2 {
		t.Fatalf("markers did not round-trip:\n got %+v\nwant %+v", got, want)
	}
}

// A write that the Timeline replays out of order does not move the marker
// back, and the Engine reads the marker of a subject (gibson#1569).
func TestReadMarker_OldWriteDoesNotMoveTheMarkerBack(t *testing.T) {
	w := NewWorld("acme")
	Reduce(w, ReadMarkerWritten{Subject: "s", Connector: "c", Cursor: "new", RecordedAtUnixNano: 20})
	Reduce(w, ReadMarkerWritten{Subject: "s", Connector: "c", Cursor: "old", RecordedAtUnixNano: 10})
	if m, _ := w.LastReadMarker("s", "c"); m.Cursor != "new" {
		t.Fatalf("cursor = %q, want new", m.Cursor)
	}
	if w.ReadMarkerSnapshot() == nil {
		t.Fatal("the snapshot is empty")
	}
	if got := NewWorld("empty").ReadMarkerSnapshot(); got != nil {
		t.Fatalf("an empty World snapshot = %v, want nil", got)
	}
}

// The Engine folds a write and reads the marker back. The snapshot orders the
// markers of one subject by Connector.
func TestReadMarker_EngineReadsTheFoldedMarker(t *testing.T) {
	e := newTestEngine()
	e.Submit(ReadMarkerWritten{Subject: "s", Connector: "b", Cursor: "2", RecordedAtUnixNano: 2})
	e.Submit(ReadMarkerWritten{Subject: "s", Connector: "a", Cursor: "1", RecordedAtUnixNano: 1})
	e.Tick()
	m, ok := e.LastReadMarker("s", "a")
	if !ok || m.Cursor != "1" {
		t.Fatalf("marker = %+v, %v", m, ok)
	}
	if _, ok := e.LastReadMarker("s", "none"); ok {
		t.Fatal("a Connector with no marker returned one")
	}
	snap := e.World.ReadMarkerSnapshot()
	if len(snap) != 2 || snap[0].Connector != "a" || snap[1].Connector != "b" {
		t.Fatalf("snapshot = %+v, want a then b", snap)
	}
}
