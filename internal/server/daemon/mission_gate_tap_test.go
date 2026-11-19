// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/brain/braintest"
)

// gateWrite is one call of SetMissionGate.
type gateWrite struct {
	tenant, mission string
	active          bool
}

// gateRecorder is a missionGateWriter that records each write. failNext makes
// the next n writes fail. When block is not nil, each write waits for it to be
// closed before it returns, and started gets one value when a write starts.
type gateRecorder struct {
	mu       sync.Mutex
	writes   []gateWrite
	failNext int
	block    chan struct{}
	started  chan struct{}
}

func (g *gateRecorder) SetMissionGate(_ context.Context, tenant, mission string, active bool) error {
	if g.started != nil {
		select {
		case g.started <- struct{}{}:
		default:
		}
	}
	if g.block != nil {
		<-g.block
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.failNext > 0 {
		g.failNext--
		return errors.New("fga down")
	}
	g.writes = append(g.writes, gateWrite{tenant: tenant, mission: mission, active: active})
	return nil
}

func (g *gateRecorder) actives() []bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]bool, 0, len(g.writes))
	for _, w := range g.writes {
		out = append(out, w.active)
	}
	return out
}

func (g *gateRecorder) count() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.writes)
}

func newGateTap(eng *brain.Engine, w missionGateWriter) *missionGateTap {
	tap := &missionGateTap{
		ctx:     context.Background(),
		tenant:  "acme",
		eng:     eng,
		writer:  w,
		logger:  slog.New(slog.DiscardHandler),
		backoff: func(int) time.Duration { return time.Millisecond },
		states:  map[string]*gateState{},
		notify:  make(chan struct{}),
	}
	eng.Subscribe(tap.apply)
	return tap
}

func newGateEngine(t *testing.T, w missionGateWriter) *brain.Engine {
	t.Helper()
	eng := brain.NewEngine("acme", braintest.NewMemTimelineStore())
	newGateTap(eng, w)
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
	if first.tenant != "acme" || first.mission != "m1" || !first.active {
		t.Errorf("first write = %+v, want tenant acme, mission m1, active", first)
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
	InstallMissionGate(t.Context(), "acme", eng, g, slog.New(slog.DiscardHandler))
	waitWrites(t, g, 4)

	got := map[string]bool{}
	g.mu.Lock()
	for _, w := range g.writes {
		got["mission:"+w.mission] = w.active
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

// The gate of a new mission must be confirmed before a work item starts. A work
// item gets its task grant when it starts, and its agent calls a gateway at
// once. AwaitOpen blocks until the write returned. With the old order (write in
// the background, work dispatched at once) the wait would not exist.
func TestMissionGate_AwaitOpenWaitsForTheConfirmedWrite(t *testing.T) {
	g := &gateRecorder{block: make(chan struct{}), started: make(chan struct{}, 1)}
	eng := brain.NewEngine("acme", braintest.NewMemTimelineStore())
	tap := newGateTap(eng, g)
	eng.Submit(brain.MissionProjected{ID: "m1", RunID: "r1"})
	eng.Tick()
	<-g.started // the write is on its way and is not confirmed

	done := make(chan error, 1)
	go func() { done <- tap.AwaitOpen(context.Background(), "m1") }()
	select {
	case err := <-done:
		t.Fatalf("AwaitOpen returned (%v) before the write was confirmed", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(g.block)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("AwaitOpen: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("AwaitOpen did not return after the write was confirmed")
	}
	if g.count() != 1 {
		t.Errorf("gate writes = %v, want the one write", g.actives())
	}
}

// A mission whose gate cannot be written must not start work, and the error says
// why.
func TestMissionGate_AwaitOpenReturnsTheErrorOfAFailedWrite(t *testing.T) {
	g := &gateRecorder{failNext: missionGateAttempts}
	eng := brain.NewEngine("acme", braintest.NewMemTimelineStore())
	tap := newGateTap(eng, g)
	eng.Submit(brain.MissionProjected{ID: "m1", RunID: "r1"})
	eng.Tick()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := tap.AwaitOpen(ctx, "m1")
	if err == nil || !strings.Contains(err.Error(), "fga down") || !strings.Contains(err.Error(), "m1") {
		t.Fatalf("AwaitOpen = %v, want an error that names the mission and the cause", err)
	}
}

// A gate that is closed (a paused mission, an ended mission) or unknown does not
// make a work item wait: ext-authz refuses its call, which is the right answer.
func TestMissionGate_AwaitOpenDoesNotWaitOnAClosedGate(t *testing.T) {
	g := &gateRecorder{}
	eng := newGateEngine(t, g)
	tap := newGateTap(brain.NewEngine("acme", braintest.NewMemTimelineStore()), g)
	if err := tap.AwaitOpen(context.Background(), "unknown"); err != nil {
		t.Fatalf("an unknown mission: %v", err)
	}
	eng.Submit(brain.MissionProjected{ID: "m1", RunID: "r1"})
	eng.Tick()
	waitWrites(t, g, 1)
	eng.Submit(brain.MissionPauseRequested{ID: "m1", RunID: "r1"})
	eng.Tick()
	waitWrites(t, g, 2)
}

// A resume opens the gate in the same order: the work that the resume lets run
// waits for the confirmed write.
func TestMissionGate_ResumeHasTheSameOrder(t *testing.T) {
	g := &gateRecorder{}
	eng := brain.NewEngine("acme", braintest.NewMemTimelineStore())
	tap := newGateTap(eng, g)
	eng.Submit(brain.MissionProjected{ID: "m1", RunID: "r1"})
	eng.Tick()
	waitWrites(t, g, 1)
	eng.Submit(brain.MissionPauseRequested{ID: "m1", RunID: "r1"})
	eng.Tick()
	waitWrites(t, g, 2)

	g.block = make(chan struct{})
	g.started = make(chan struct{}, 1)
	eng.Submit(brain.MissionResumed{ID: "m1", RunID: "r1"})
	eng.Tick()
	<-g.started
	done := make(chan error, 1)
	go func() { done <- tap.AwaitOpen(context.Background(), "m1") }()
	select {
	case <-done:
		t.Fatal("AwaitOpen returned before the write of the resume was confirmed")
	case <-time.After(100 * time.Millisecond):
	}
	close(g.block)
	if err := <-done; err != nil {
		t.Fatalf("AwaitOpen after the resume: %v", err)
	}
	if got, want := g.actives(), []bool{true, false, true}; !equalBools(got, want) {
		t.Errorf("gate values = %v, want %v", got, want)
	}
}

// The brain executor starts no work item before the gate is open. A work item of
// an unknown kind fails at once when it starts, so it shows when the start
// happens.
func TestBrainExecutor_DispatchWaitsForTheGate(t *testing.T) {
	g := &gateRecorder{block: make(chan struct{}), started: make(chan struct{}, 1)}
	eng := brain.NewEngine("acme", braintest.NewMemTimelineStore())
	tap := newGateTap(eng, g)
	eng.Submit(brain.MissionProjected{ID: "m1", RunID: "r1"})
	eng.Tick()
	<-g.started

	b := newBrainExecutor(nil, slog.New(slog.DiscardHandler))
	b.gate = func(string) MissionGateAwaiter { return tap }
	b.register("m1", &missionBinding{ctx: context.Background(), runID: "r1", eng: eng, slot: "primary"})

	eng.Submit(brain.WorkDispatched{ID: "w1", MissionID: "m1", RunID: "r1", ItemKind: "bogus", Target: "x"})
	eng.Tick()
	b.Dispatch(brain.DispatchRequest{MissionID: "m1", RunID: "r1", WorkID: "w1", Kind: "bogus", Target: "x"})
	time.Sleep(150 * time.Millisecond)
	eng.Tick()
	if hasWorkCompleted(eng, "w1") {
		t.Fatal("the work item started before the gate write was confirmed")
	}
	close(g.block)
	deadline := time.Now().Add(2 * time.Second)
	for !hasWorkCompleted(eng, "w1") {
		if time.Now().After(deadline) {
			t.Fatal("the work item never started after the gate was confirmed")
		}
		eng.Tick()
		time.Sleep(10 * time.Millisecond)
	}
}

// A mission whose gate cannot be written fails its work item with the reason.
func TestBrainExecutor_DispatchFailsTheWorkWhenTheGateCannotOpen(t *testing.T) {
	g := &gateRecorder{failNext: missionGateAttempts}
	eng := brain.NewEngine("acme", braintest.NewMemTimelineStore())
	tap := newGateTap(eng, g)
	eng.Submit(brain.MissionProjected{ID: "m1", RunID: "r1"})
	eng.Tick()

	b := newBrainExecutor(nil, slog.New(slog.DiscardHandler))
	b.gate = func(string) MissionGateAwaiter { return tap }
	b.register("m1", &missionBinding{ctx: context.Background(), runID: "r1", eng: eng, slot: "primary"})
	eng.Submit(brain.WorkDispatched{ID: "w1", MissionID: "m1", RunID: "r1", ItemKind: "agent", Target: "x"})
	eng.Tick()
	b.Dispatch(brain.DispatchRequest{MissionID: "m1", RunID: "r1", WorkID: "w1", Kind: "agent", Target: "x"})

	deadline := time.Now().Add(3 * time.Second)
	for {
		eng.Tick()
		for _, w := range eng.Work() {
			if w.ID == "w1" && strings.Contains(w.Err, "gate of mission m1 could not be opened") {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("the work item did not fail with the reason of the gate")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func hasWorkCompleted(eng *brain.Engine, id string) bool {
	for _, w := range eng.Work() {
		if w.ID == id && w.Err != "" {
			return true
		}
	}
	return false
}
