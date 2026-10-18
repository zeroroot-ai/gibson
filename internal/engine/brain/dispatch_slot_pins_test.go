// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"reflect"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
)

// The LLM slot pins of an agent node (gibson#1203) go from the projection to
// the dispatch request, the same way the network scope does.

func TestDispatchHandler_CarriesTheSlotPinsOfTheNode(t *testing.T) {
	pins := map[string]agent.SlotConfig{"fast": {Provider: "fast-p", Model: "f-large"}}

	rec := &recordingDispatcher{}
	h := NewDispatchHandler(rec)
	e := NewEngine("t1", &memTimelineStore{})
	e.AddSystem(SchedulerSystem)
	e.Subscribe(h.Tap)
	e.Submit(MissionProjected{ID: "m1", Nodes: []WorkNode{
		{ID: "pinned", Kind: "agent", Target: "recon", SlotPins: pins},
		{ID: "plain", Kind: "agent", Target: "recon"},
	}})
	e.Tick()
	h.Drain()

	got := map[string]map[string]agent.SlotConfig{}
	for _, r := range rec.reqs {
		got[r.WorkID] = r.SlotPins
	}
	if len(got) != 2 {
		t.Fatalf("want 2 dispatches, got %d", len(rec.reqs))
	}
	if !reflect.DeepEqual(got[WorkID("m1", "pinned")], pins) {
		t.Errorf("pinned node: SlotPins = %+v, want %+v", got[WorkID("m1", "pinned")], pins)
	}
	if p := got[WorkID("m1", "plain")]; p != nil {
		t.Errorf("node with no pin: SlotPins = %+v, want nil", p)
	}
}

// A snapshot restore re-creates each item through WorkDispatched. It must hand
// the same pins back.
func TestRestoreWorld_KeepsTheSlotPinsOfTheNode(t *testing.T) {
	pins := map[string]agent.SlotConfig{"fast": {Provider: "fast-p"}}
	w := NewWorld("t1")
	Reduce(w, MissionProjected{ID: "m1", Nodes: []WorkNode{{ID: "a", Kind: "agent", Target: "recon", SlotPins: pins}}})

	restored, err := RestoreWorld(SnapshotWorld(w, "1"), "t1")
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	work := restored.WorkSnapshot()
	if len(work) != 1 || !reflect.DeepEqual(work[0].SlotPins, pins) {
		t.Fatalf("restored work = %+v, want the pins %+v", work, pins)
	}
}

// The Timeline stores WorkDispatched as JSON. The pins survive the codec.
func TestWorkDispatched_SlotPinsSurviveTheCodec(t *testing.T) {
	ev := WorkDispatched{ID: "m1/a", MissionID: "m1", ItemKind: "agent",
		SlotPins: map[string]agent.SlotConfig{"fast": {Provider: "fast-p", Model: "f-large"}}}
	b, err := EncodeEvent(ev)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	back, err := DecodeEvent(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !reflect.DeepEqual(back, ev) {
		t.Fatalf("decoded = %+v, want %+v", back, ev)
	}
}
