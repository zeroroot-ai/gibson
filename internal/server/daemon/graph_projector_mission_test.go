// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/platform/principal"
)

// The gap gibson#551 left open: :Mission.status was written only by the two
// eager writers, and both run when a mission STARTS. Nothing moved it off "running", so
// GetGraphSummary — a registered RPC that reads `m.status` — reported every
// mission as running for as long as the graph lived.

// waitForMissionStatus folds the submitted events and returns once the World
// reports the wanted status, so the test asserts on a settled World rather than
// on a race.
func waitForMissionStatus(t *testing.T, eng *brain.Engine, id string, want brain.MissionStatus) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, m := range eng.Missions() {
			if m.ID == id && m.Status == want {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	var got []string
	for _, m := range eng.Missions() {
		got = append(got, m.ID+"="+string(m.Status))
	}
	t.Fatalf("mission %s never reached %s in the World; saw %v", id, want, got)
}

// TestGraphProjector_ProjectsAMissionsTerminalStatus is the regression: a
// mission that finished must project as finished.
func TestGraphProjector_ProjectsAMissionsTerminalStatus(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)

	eng := reg.For("acme")
	eng.Submit(brain.MissionStarted{
		ID: "m1", Name: "sweep", Description: "Sweep the fleet.",
		TargetID: "t1", TenantID: "acme", CreatedBy: principal.Principal{Kind: principal.User, ID: "u1"},
	})
	waitForMissionStatus(t, eng, "m1", brain.MissionRunning)

	writer := newFakeGraphWriter()
	p := NewGraphProjector(reg, writer, time.Hour, nil)
	p.project(ctx)

	writer.mu.Lock()
	running := append([]MissionProjection(nil), writer.missions["acme"]...)
	writer.mu.Unlock()
	if len(running) != 1 {
		t.Fatalf("projected %d missions while running, want 1", len(running))
	}
	if running[0].Status != string(brain.MissionRunning) {
		t.Errorf("status while running = %q, want running", running[0].Status)
	}

	// The mission finishes. The next tick must carry the terminal status.
	eng.Submit(brain.MissionDone{ID: "m1", Outcome: brain.MissionCompleted, Reason: "all work complete"})
	waitForMissionStatus(t, eng, "m1", brain.MissionCompleted)

	p.project(ctx)

	writer.mu.Lock()
	defer writer.mu.Unlock()
	got := writer.missions["acme"]
	if len(got) != 2 {
		t.Fatalf("projected %d missions over two ticks, want 2", len(got))
	}
	last := got[1]
	if last.Status != string(brain.MissionCompleted) {
		t.Errorf("status after completion = %q, want completed — the graph still reports this mission as running", last.Status)
	}
	if last.ID != "m1" {
		t.Errorf("ID = %q, want m1", last.ID)
	}
	if last.Name != "sweep" {
		t.Errorf("Name = %q, want sweep", last.Name)
	}
	if last.TargetID != "t1" {
		t.Errorf("TargetID = %q, want t1", last.TargetID)
	}
	if last.CreatedBy != "user:u1" {
		t.Errorf("CreatedBy = %q, want user:u1", last.CreatedBy)
	}
}

// TestMissionProjectionOf_LeavesWhatTheWorldDoesNotKnowEmpty is the other half
// of the contract. The tick has no objective, no definition source and no start
// time; those come from the create RPC and the run bootstrap. They must arrive
// empty so the Cypher's keep-the-stored-value guard leaves them alone. A tick
// that invented a value here would erase the real one every five seconds.
func TestMissionProjectionOf_LeavesWhatTheWorldDoesNotKnowEmpty(t *testing.T) {
	p := missionProjectionOf(brain.MissionSnapshot{
		ID: "m1", Name: "sweep", Description: "Sweep the fleet.",
		TargetID: "t1", Status: brain.MissionCompleted,
	})
	if p.Objective != "" {
		t.Errorf("Objective = %q, want empty — the World does not know it", p.Objective)
	}
	if p.YAMLSource != "" {
		t.Errorf("YAMLSource = %q, want empty — the World does not know it", p.YAMLSource)
	}
	if p.StartedAt != nil {
		t.Errorf("StartedAt = %v, want nil — the World does not know it", p.StartedAt)
	}
	// And it must carry what the World does know.
	if p.Status != "completed" || p.Name != "sweep" || p.TargetID != "t1" {
		t.Errorf("the World's own fields did not carry through: %+v", p)
	}
}

// failingMissionWriter is a fakeGraphWriter whose mission upsert always fails,
// so the projector's best-effort contract can be asserted rather than assumed.
type failingMissionWriter struct {
	*fakeGraphWriter
	attempts int
}

func (f *failingMissionWriter) UpsertMission(context.Context, string, MissionProjection) error {
	f.attempts++
	return errors.New("neo4j is down")
}

// TestGraphProjector_AMissionUpsertFailureDoesNotStopTheTick: projection is
// best-effort and self-heals on the next pass (the package doc says so), so one
// failing write must not abandon the rest. Before the missions loop existed
// there was nothing here to abandon; now there is, and the loop runs last, so a
// hard return would have cost nothing visible in a test that only checked
// hosts.
func TestGraphProjector_AMissionUpsertFailureDoesNotStopTheTick(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)

	eng := reg.For("acme")
	eng.Submit(brain.MissionStarted{ID: "m1", Name: "one", TenantID: "acme"})
	eng.Submit(brain.MissionStarted{ID: "m2", Name: "two", TenantID: "acme"})
	eng.Submit(brain.HostObserved{ScopeID: "m1", Address: "10.0.0.5", OpenPorts: []int{22}})
	waitForMissionStatus(t, eng, "m2", brain.MissionRunning)

	writer := &failingMissionWriter{fakeGraphWriter: newFakeGraphWriter()}
	p := NewGraphProjector(reg, writer, time.Hour, nil)
	p.project(ctx)

	// Every mission is still attempted: the loop logs and continues.
	if writer.attempts != 2 {
		t.Errorf("attempted %d mission upserts, want 2 — a failure stopped the loop", writer.attempts)
	}
	// And the host projected in the same pass still landed.
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if got := len(writer.hosts["acme"]); got != 1 {
		t.Errorf("projected %d hosts, want 1 — a mission failure took the rest of the tick with it", got)
	}
}
