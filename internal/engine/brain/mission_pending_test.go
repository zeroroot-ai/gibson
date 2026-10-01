// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/principal"
)

var testCreator = principal.Principal{Kind: principal.User, ID: "123456789012345678"}

func missionByID(w *World, id string) (MissionSnapshot, bool) {
	for _, m := range w.MissionSnapshot() {
		if m.ID == id {
			return m, true
		}
	}
	return MissionSnapshot{}, false
}

// A created mission is in the World before it runs: pending, with its
// metadata and creator, so ListMissions serves it (hosted#205). A second
// creation of the same id is a replay.
func TestMissionCreated_PendingWithCreator(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, MissionCreated{ID: "m1", Name: "scan", Description: "d", TargetID: "tg", TenantID: "t", CreatedBy: testCreator})
	Reduce(w, MissionCreated{ID: "m1", Name: "other"})

	m, ok := missionByID(w, "m1")
	if !ok || m.Status != MissionPending || m.CreatedBy != testCreator || m.Name != "scan" || len(w.MissionSnapshot()) != 1 {
		t.Fatalf("after creation: %+v (found %v), want one pending mission named scan by %+v", m, ok, testCreator)
	}
}

// The start moves the created entity to running and takes the start's
// fields when present; a start on a running mission is a replay.
func TestMissionStarted_MovesPendingToRunning(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, MissionCreated{ID: "m1", Name: "scan", TenantID: "t", CreatedBy: testCreator})
	other := principal.Principal{Kind: principal.Service, ID: "scheduler"}
	Reduce(w, MissionStarted{ID: "m1", Goal: "find it", BeliefModel: "bm-1", Name: "scan-run", Description: "d2", TargetID: "tg2", TenantID: "t", CreatedBy: other})

	m, _ := missionByID(w, "m1")
	if m.Status != MissionRunning || m.Goal != "find it" || m.Name != "scan-run" || m.Description != "d2" || m.TargetID != "tg2" || m.CreatedBy != other {
		t.Fatalf("after start: %+v, want running with the start's fields", m)
	}

	Reduce(w, MissionStarted{ID: "m1", Goal: "again"})
	if m, _ := missionByID(w, "m1"); m.Goal != "find it" {
		t.Fatalf("replayed start must be ignored: %+v", m)
	}
}

// A start that names nothing keeps what creation recorded.
func TestMissionStarted_EmptyStartKeepsCreation(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, MissionCreated{ID: "m3", Name: "kept", Description: "kd", TargetID: "ktg", TenantID: "t", CreatedBy: testCreator})
	Reduce(w, MissionStarted{ID: "m3"})

	m, _ := missionByID(w, "m3")
	if m.Status != MissionRunning || m.Name != "kept" || m.Description != "kd" || m.TargetID != "ktg" || m.TenantID != "t" || m.CreatedBy != testCreator {
		t.Fatalf("empty start must keep creation's fields: %+v", m)
	}
}

// A start for a mission the World never saw created still creates it.
func TestMissionStarted_UnknownIDCreates(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, MissionStarted{ID: "m2", Goal: "g2", CreatedBy: testCreator})

	m, ok := missionByID(w, "m2")
	if !ok || m.Status != MissionRunning || m.CreatedBy != testCreator {
		t.Fatalf("start for an unknown id: %+v (found %v), want a running mission by the creator", m, ok)
	}
}

func TestMissionCreated_SurvivesRestoreAsPending(t *testing.T) {
	creator := testCreator
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
