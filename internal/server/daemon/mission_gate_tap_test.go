// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/brain/braintest"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

// gateRecorder is a missionGateWriter that records each write. failNext makes
// the next n writes fail.
type gateRecorder struct {
	mu       sync.Mutex
	writes   []authz.ConditionalTuple
	failNext int
}

func (g *gateRecorder) UpdateConditionalTuple(_ context.Context, t authz.ConditionalTuple) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.failNext > 0 {
		g.failNext--
		return errors.New("fga down")
	}
	g.writes = append(g.writes, t)
	return nil
}

func (g *gateRecorder) actives() []bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]bool, 0, len(g.writes))
	for _, w := range g.writes {
		out = append(out, w.ConditionContext[authz.ConditionParamActive].(bool))
	}
	return out
}

func (g *gateRecorder) count() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.writes)
}

func newGateEngine(t *testing.T, w missionGateWriter) *brain.Engine {
	t.Helper()
	eng := brain.NewEngine("acme", braintest.NewMemTimelineStore())
	tap := &missionGateTap{
		tenant:  "acme",
		eng:     eng,
		writer:  w,
		logger:  slog.New(slog.DiscardHandler),
		backoff: func(int) time.Duration { return time.Millisecond },
		last:    map[string]bool{},
	}
	eng.Subscribe(tap.apply)
	return eng
}

func waitWrites(t *testing.T, g *gateRecorder, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for g.count() < want {
		if time.Now().After(deadline) {
			t.Fatalf("got %d gate writes, want %d: %v", g.count(), want, g.actives())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func equalBools(a, b []bool) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// A mission that works is active. A pause closes the gate. A resume opens it.
// A terminal state closes it.
func TestMissionGate_FollowsTheLifecycle(t *testing.T) {
	g := &gateRecorder{}
	eng := newGateEngine(t, g)

	eng.Submit(brain.MissionProjected{ID: "m1", RunID: "r1"})
	eng.Tick()
	waitWrites(t, g, 1)
	g.mu.Lock()
	first := g.writes[0]
	g.mu.Unlock()
	if first.User != "tenant:acme" || first.Relation != "active" || first.Object != "mission:m1" ||
		first.ConditionName != "mission_active" {
		t.Errorf("first write = %+v, want tenant:acme active mission:m1 with mission_active", first)
	}

	eng.Submit(brain.MissionPauseRequested{ID: "m1", RunID: "r1"})
	eng.Tick()
	waitWrites(t, g, 2)
	eng.Submit(brain.MissionResumed{ID: "m1", RunID: "r1"})
	eng.Tick()
	waitWrites(t, g, 3)
	eng.Submit(brain.MissionDone{ID: "m1", RunID: "r1", Outcome: brain.MissionCanceled})
	eng.Tick()
	waitWrites(t, g, 4)

	if got, want := g.actives(), []bool{true, false, true, false}; !equalBools(got, want) {
		t.Errorf("gate values = %v, want %v", got, want)
	}
}

// A mission that waits for input is still active: ADR-0132 says the fleet keeps
// working. The gate does not change.
func TestMissionGate_InputRequiredStaysOpen(t *testing.T) {
	g := &gateRecorder{}
	eng := newGateEngine(t, g)
	eng.Submit(brain.MissionProjected{ID: "m1", RunID: "r1"})
	eng.Tick()
	waitWrites(t, g, 1)

	eng.Submit(brain.DestructiveActionRequested{HypothesisID: "h1", MissionID: "m1", Tenant: "acme"})
	eng.Tick()
	var status brain.MissionStatus
	for _, m := range eng.Missions() {
		status = m.Status
	}
	if status != brain.MissionInputRequired {
		t.Fatalf("mission status = %s, want input_required", status)
	}
	// Another lifecycle event gives the tap the chance to write again.
	eng.Submit(brain.MissionResumed{ID: "m1", RunID: "r1"})
	eng.Tick()
	time.Sleep(50 * time.Millisecond)
	if g.count() != 1 {
		t.Errorf("gate writes = %v, want only the first one", g.actives())
	}
}

// The tap reads the World, so an event of an old run cannot close the gate of a
// new run.
func TestMissionGate_AnEventOfAnOldRunChangesNothing(t *testing.T) {
	g := &gateRecorder{}
	eng := newGateEngine(t, g)
	eng.Submit(brain.MissionProjected{ID: "m1", RunID: "run-2"})
	eng.Tick()
	waitWrites(t, g, 1)

	eng.Submit(brain.MissionDone{ID: "m1", RunID: "run-1", Outcome: brain.MissionFailed})
	eng.Tick()
	time.Sleep(50 * time.Millisecond)
	if g.count() != 1 {
		t.Errorf("gate writes = %v, want only the first one", g.actives())
	}
}

// A write that fails is tried again. When every attempt fails, the tap forgets
// the value, so the next event of the mission writes it again.
func TestMissionGate_RetriesAndRecovers(t *testing.T) {
	t.Run("a short failure is retried", func(t *testing.T) {
		g := &gateRecorder{failNext: 2}
		eng := newGateEngine(t, g)
		eng.Submit(brain.MissionProjected{ID: "m1", RunID: "r1"})
		eng.Tick()
		waitWrites(t, g, 1)
	})
	t.Run("a long failure is written again at the next event", func(t *testing.T) {
		g := &gateRecorder{failNext: missionGateAttempts}
		eng := newGateEngine(t, g)
		eng.Submit(brain.MissionProjected{ID: "m1", RunID: "r1"})
		eng.Tick()
		time.Sleep(100 * time.Millisecond) // all attempts fail
		if g.count() != 0 {
			t.Fatalf("writes = %d, want 0 after the failed attempts", g.count())
		}
		eng.Submit(brain.MissionPauseRequested{ID: "m1", RunID: "r1"})
		eng.Tick()
		eng.Submit(brain.MissionResumed{ID: "m1", RunID: "r1"})
		eng.Tick()
		waitWrites(t, g, 1)
	})
}

func TestMissionIDOf(t *testing.T) {
	if got := missionIDOf(brain.MissionDone{ID: "m9"}); got != "m9" {
		t.Errorf("missionIDOf(MissionDone) = %q, want m9", got)
	}
	if got := missionIDOf(brain.WorkCompleted{ID: "w1"}); got != "" {
		t.Errorf("missionIDOf(WorkCompleted) = %q, want empty", got)
	}
}

// A mission that is only submitted has no tuple. An absent tuple refuses a model
// call (the ext-authz test TestModelCall_ASubmittedMissionIsRefused).
func TestMissionGate_ASubmittedMissionGetsNoTuple(t *testing.T) {
	g := &gateRecorder{}
	eng := newGateEngine(t, g)
	eng.Submit(brain.MissionCreated{ID: "m1", Name: "draft"})
	eng.Tick()
	time.Sleep(50 * time.Millisecond)
	if g.count() != 0 {
		t.Errorf("gate writes = %v, want none for a submitted mission", g.actives())
	}
	// It becomes active at its start, and then it gets the tuple.
	eng.Submit(brain.MissionStarted{ID: "m1", RunID: "r1"})
	eng.Tick()
	waitWrites(t, g, 1)
	if got := g.actives(); !equalBools(got, []bool{true}) {
		t.Errorf("gate values = %v, want [true]", got)
	}
}

// The sweep writes the right value for each mission that the World holds, and
// nothing for a submitted one.
func TestMissionGate_SweepWritesTheTupleOfEachMission(t *testing.T) {
	eng := brain.NewEngine("acme", braintest.NewMemTimelineStore())
	eng.Submit(brain.MissionCreated{ID: "submitted", Name: "s"})
	eng.Submit(brain.MissionProjected{ID: "working", RunID: "r1"})
	eng.Submit(brain.MissionProjected{ID: "paused", RunID: "r2"})
	eng.Submit(brain.MissionProjected{ID: "done", RunID: "r3"})
	eng.Submit(brain.MissionProjected{ID: "canceled", RunID: "r4"})
	eng.Tick()
	eng.Submit(brain.MissionPauseRequested{ID: "paused", RunID: "r2"})
	eng.Submit(brain.MissionDone{ID: "done", RunID: "r3", Outcome: brain.MissionCompleted})
	eng.Submit(brain.MissionDone{ID: "canceled", RunID: "r4", Outcome: brain.MissionCanceled})
	eng.Tick()

	g := &gateRecorder{}
	InstallMissionGate("acme", eng, g, slog.New(slog.DiscardHandler))
	waitWrites(t, g, 4)

	got := map[string]bool{}
	g.mu.Lock()
	for _, w := range g.writes {
		got[w.Object] = w.ConditionContext[authz.ConditionParamActive].(bool)
	}
	g.mu.Unlock()
	want := map[string]bool{
		"mission:working": true, "mission:paused": false, "mission:done": false, "mission:canceled": false,
	}
	if len(got) != len(want) {
		t.Fatalf("writes = %v, want %v", got, want)
	}
	for obj, v := range want {
		if gv, ok := got[obj]; !ok || gv != v {
			t.Errorf("%s = %v (present %v), want %v", obj, gv, ok, v)
		}
	}
	if _, ok := got["mission:submitted"]; ok {
		t.Error("the sweep wrote a tuple for a submitted mission")
	}
}
