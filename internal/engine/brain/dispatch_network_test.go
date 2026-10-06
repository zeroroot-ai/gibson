// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"reflect"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
)

// The network scope of a mission node (owner decision S6, gibson#865) goes
// from the projection to the dispatch request. Before this, the request had no
// such field, so the scope never reached the sandbox launcher.

func TestDispatchHandler_CarriesTheNetworkScopeOfTheNode(t *testing.T) {
	scope := &agent.NodeNetwork{Research: true, Targets: []string{"https://app.example.com", "10.0.0.0/24"}}

	rec := &recordingDispatcher{}
	h := NewDispatchHandler(rec)
	e := NewEngine("t1", &memTimelineStore{})
	e.AddSystem(SchedulerSystem)
	e.Subscribe(h.Tap)
	e.Submit(MissionProjected{ID: "m1", Nodes: []WorkNode{
		{ID: "scoped", Kind: "agent", Target: "recon", Network: scope},
		{ID: "plain", Kind: "agent", Target: "recon"},
	}})
	e.Tick()
	h.Drain()

	got := map[string]*agent.NodeNetwork{}
	for _, r := range rec.reqs {
		got[r.WorkID] = r.Network
	}
	if len(got) != 2 {
		t.Fatalf("want 2 dispatches, got %d", len(rec.reqs))
	}
	if !reflect.DeepEqual(got[WorkID("m1", "scoped")], scope) {
		t.Errorf("scoped node: Network = %+v, want %+v", got[WorkID("m1", "scoped")], scope)
	}
	if n := got[WorkID("m1", "plain")]; n != nil {
		t.Errorf("node with no scope: Network = %+v, want nil", n)
	}
}

// A snapshot restore re-creates each item through WorkDispatched. It must hand
// the same scope back, as it does the timeout.
func TestRestoreWorld_KeepsTheNetworkScopeOfTheNode(t *testing.T) {
	scope := &agent.NodeNetwork{Targets: []string{"app.example.com:8443"}}
	w := NewWorld("t1")
	Reduce(w, MissionProjected{ID: "m1", Nodes: []WorkNode{{ID: "a", Kind: "agent", Target: "recon", Network: scope}}})

	restored, err := RestoreWorld(SnapshotWorld(w, "1"), "t1")
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	work := restored.WorkSnapshot()
	if len(work) != 1 || !reflect.DeepEqual(work[0].Network, scope) {
		t.Fatalf("restored work = %+v, want the scope %+v", work, scope)
	}
}

// The Timeline stores WorkDispatched as JSON. The scope survives the codec.
func TestWorkDispatched_NetworkScopeSurvivesTheCodec(t *testing.T) {
	ev := WorkDispatched{ID: "m1/a", MissionID: "m1", ItemKind: "agent", Network: &agent.NodeNetwork{Research: true}}
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
