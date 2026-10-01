// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/principal"
)

// A created mission is in the World before it runs: pending, with its
// metadata and creator, so ListMissions serves it (hosted#205). The start
// moves the same entity to running and keeps the creator; a start for an
// unknown id still creates a running mission, as before; a World snapshot
// restore keeps a pending mission pending.
func TestMissionCreated_PendingUntilStarted(t *testing.T) {
	creator := principal.Principal{Kind: principal.User, ID: "123456789012345678"}
	w := NewWorld("t")
	Reduce(w, MissionCreated{ID: "m1", Name: "scan", Description: "d", TargetID: "tg", TenantID: "t", CreatedBy: creator})

	ms := w.MissionSnapshot()
	if len(ms) != 1 || ms[0].Status != MissionPending || ms[0].CreatedBy != creator || ms[0].Name != "scan" {
		t.Fatalf("after creation: %+v, want one pending mission by %+v", ms, creator)
	}

	// A second creation of the same id is a replay and changes nothing.
	Reduce(w, MissionCreated{ID: "m1", Name: "other"})
	if ms := w.MissionSnapshot(); len(ms) != 1 || ms[0].Name != "scan" {
		t.Fatalf("replayed creation must be ignored: %+v", ms)
	}

	// The run starts: same entity, now running; the start's goal, name,
	// description, target, tenant and creator are taken when present.
	other := principal.Principal{Kind: principal.Service, ID: "scheduler"}
	Reduce(w, MissionStarted{ID: "m1", Goal: "find it", BeliefModel: "bm-1", Name: "scan-run", Description: "d2", TargetID: "tg2", TenantID: "t", CreatedBy: other})
	ms = w.MissionSnapshot()
	if len(ms) != 1 || ms[0].Status != MissionRunning || ms[0].Goal != "find it" || ms[0].Name != "scan-run" || ms[0].Description != "d2" || ms[0].TargetID != "tg2" || ms[0].CreatedBy != other {
		t.Fatalf("after start: %+v, want one running mission carrying the start's fields", ms)
	}

	// A start on a mission that already runs is a replay and changes nothing.
	Reduce(w, MissionStarted{ID: "m1", Goal: "again"})
	if ms := w.MissionSnapshot(); ms[0].Goal != "find it" {
		t.Fatalf("replayed start must be ignored: %+v", ms)
	}

	// A start that names nothing keeps what creation recorded.
	Reduce(w, MissionCreated{ID: "m3", Name: "kept", Description: "kd", TargetID: "ktg", TenantID: "t", CreatedBy: creator})
	Reduce(w, MissionStarted{ID: "m3"})
	for _, m := range w.MissionSnapshot() {
		if m.ID == "m3" && (m.Status != MissionRunning || m.Name != "kept" || m.Description != "kd" || m.TargetID != "ktg" || m.TenantID != "t" || m.CreatedBy != creator) {
			t.Fatalf("empty start must keep creation's fields: %+v", m)
		}
	}

	// A start for a mission the World never saw created still creates it.
	Reduce(w, MissionStarted{ID: "m2", Goal: "g2", CreatedBy: creator})
	if ms := w.MissionSnapshot(); len(ms) != 3 {
		t.Fatalf("a start for an unknown id must create the mission: %+v", ms)
	}
}

func TestMissionCreated_SurvivesRestoreAsPending(t *testing.T) {
	creator := principal.Principal{Kind: principal.User, ID: "123456789012345678"}
	w := NewWorld("t")
	Reduce(w, MissionCreated{ID: "m1", Name: "scan", TenantID: "t", CreatedBy: creator})
	Reduce(w, MissionCreated{ID: "m2", Name: "ran", TenantID: "t", CreatedBy: creator})
	Reduce(w, MissionStarted{ID: "m2", Goal: "g"})

	restored, err := RestoreWorld(SnapshotWorld(w, "1"), "t")
	if err != nil {
		t.Fatalf("RestoreWorld: %v", err)
	}
	got := map[string]MissionSnapshot{}
	for _, m := range restored.MissionSnapshot() {
		got[m.ID] = m
	}
	if got["m1"].Status != MissionPending || got["m1"].CreatedBy != creator || got["m1"].Name != "scan" {
		t.Fatalf("restored m1 = %+v, want pending with creator and name", got["m1"])
	}
	if got["m2"].Status != MissionRunning || got["m2"].CreatedBy != creator {
		t.Fatalf("restored m2 = %+v, want running with creator", got["m2"])
	}
}

// The event round-trips through the timeline codec, so a restarted engine
// re-folds it.
func TestMissionCreated_CodecRoundTrip(t *testing.T) {
	creator := principal.Principal{Kind: principal.User, ID: "123456789012345678"}
	in := MissionCreated{ID: "m1", Name: "scan", TenantID: "t", CreatedBy: creator}
	raw, err := EncodeEvent(in)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	out, err := DecodeEvent(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got, ok := out.(MissionCreated); !ok || got != in {
		t.Fatalf("round trip = %#v, want %#v", out, in)
	}
}

// A mission's slice of the timeline includes its creation and not another
// mission's.
func TestMissionCreated_InMissionSlice(t *testing.T) {
	events := []Event{
		MissionCreated{ID: "m1", Name: "mine"},
		MissionCreated{ID: "m2", Name: "theirs"},
		MissionStarted{ID: "m1", Goal: "g"},
	}
	got := MissionSlice(events, "m1")
	if len(got) != 2 {
		t.Fatalf("slice = %+v, want m1's creation and start only", got)
	}
	if c, ok := got[0].(MissionCreated); !ok || c.ID != "m1" {
		t.Fatalf("first event = %#v, want m1's MissionCreated", got[0])
	}
}
