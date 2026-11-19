// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"reflect"
	"testing"
)

func outsideCallEvents() []Event {
	return []Event{
		OutsideAgentCalled{
			CallID: "gw-t-s1", MissionID: "m1", TaskID: "task-1", Subject: "user:u1", Target: "partner-scout",
			Method: "SendMessage", StartUnixNano: 100, EndUnixNano: 200, Status: "ok", HTTPStatus: 200,
			RecordedAtUnixNano: 300,
		},
		OutsideAgentCalled{
			CallID: "gw-t-s2", MissionID: "m1", Target: "partner-scout", StartUnixNano: 400, EndUnixNano: 450,
			Status: "error", HTTPStatus: 502, RecordedAtUnixNano: 500,
		},
	}
}

// One span gives one call. A second delivery of the same call ID keeps one call.
func TestOutsideAgentCalled_TheWorldShowsEachCallOnce(t *testing.T) {
	w := NewWorld("acme")
	for _, ev := range outsideCallEvents() {
		Reduce(w, ev)
	}
	Reduce(w, outsideCallEvents()[0])
	calls := w.OutsideAgentCalls()
	if len(calls) != 2 {
		t.Fatalf("calls = %d, want 2", len(calls))
	}
	if calls[0].Target != "partner-scout" || calls[0].MissionID != "m1" || calls[0].Status != "ok" ||
		calls[1].Status != "error" || calls[1].HTTPStatus != 502 {
		t.Errorf("calls = %+v", calls)
	}
	calls[0].Target = "changed"
	if w.OutsideAgentCalls()[0].Target != "partner-scout" {
		t.Error("OutsideAgentCalls returned the slice of the World")
	}
}

func TestOutsideAgentCalled_ReplaysThroughTheCodecAndTheSnapshot(t *testing.T) {
	tl := &Timeline{}
	for _, ev := range outsideCallEvents() {
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
	if len(w.OutsideAgentCalls()) != 2 {
		t.Fatalf("a replay of the decoded events gave %d calls, want 2", len(w.OutsideAgentCalls()))
	}
	restored, err := RestoreWorld(SnapshotWorld(w, "seq-1"), "acme")
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got, want := restored.OutsideAgentCalls(), w.OutsideAgentCalls(); !reflect.DeepEqual(got, want) {
		t.Fatalf("calls did not round-trip:\n got %+v\nwant %+v", got, want)
	}
}
