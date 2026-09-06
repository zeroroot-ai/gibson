// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"log/slog"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
)

// TestLifecycleProjector_DoesNotDeadlockTheTick is the regression for
// gibson#1206.
//
// The projector's tap runs inside Engine.Tick, which holds the engine's write
// lock. It resolved a WorkCompleted's owning mission by calling eng.Work() —
// a locking accessor. sync.RWMutex is not reentrant, so the tick goroutine took
// its own read lock and blocked forever: no panic, no log, no restart. The
// tenant's engine stopped ticking the first time any work item completed, and
// from then on every mission in that tenant bootstrapped and hung with no
// status and no failure.
//
// The tick is run in a goroutine with a deadline, because the failure mode is a
// hang: asserted directly, a broken projector would wedge the test binary
// instead of failing it.
func TestLifecycleProjector_DoesNotDeadlockTheTick(t *testing.T) {
	eng := brain.NewEngine("acme")
	InstallLifecycleProjector("acme", eng, nil, nil, slog.Default())

	eng.Submit(brain.MissionProjected{ID: "m1", Nodes: []brain.WorkNode{
		{ID: "probe", Kind: "tool", Target: "http", Input: `{"url":"https://example.test"}`},
	}})
	eng.Submit(brain.MissionStarted{ID: "m1"})
	tickOrFail(t, eng)

	// Take the work id from the World rather than constructing one, so the test
	// holds whatever id scheme the projection uses.
	workID := onlyWorkID(t, eng)
	eng.Submit(brain.WorkDispatched{ID: workID, MissionID: "m1", ItemKind: "tool", Target: "http"})
	// The event that used to wedge it: the tap resolves the owning mission here.
	eng.Submit(brain.WorkCompleted{ID: workID, Result: `{"status":200}`})

	done := make(chan int, 1)
	go func() { done <- eng.Tick() }()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Tick did not return: the lifecycle projector's tap deadlocked the engine " +
			"(a tap must read eng.World, never a locking accessor — gibson#1206)")
	}
}

// tickOrFail ticks with a deadline; the failure mode under test is a hang.
func tickOrFail(t *testing.T, eng *brain.Engine) {
	t.Helper()
	done := make(chan struct{})
	go func() { eng.Tick(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("engine stopped ticking")
	}
}

func onlyWorkID(t *testing.T, eng *brain.Engine) string {
	t.Helper()
	work := eng.Work()
	if len(work) != 1 {
		t.Fatalf("want exactly one work item, got %d", len(work))
	}
	return work[0].ID
}

// TestLifecycleProjector_KeepsTickingAfterWorkCompletes proves the tenant is
// still live afterwards — the symptom that made the deadlock so hard to read was
// not the first mission failing, but every LATER mission silently doing nothing.
func TestLifecycleProjector_KeepsTickingAfterWorkCompletes(t *testing.T) {
	eng := brain.NewEngine("acme")
	InstallLifecycleProjector("acme", eng, nil, nil, slog.Default())

	eng.Submit(brain.MissionProjected{ID: "m1", Nodes: []brain.WorkNode{{ID: "probe", Kind: "tool", Target: "http"}}})
	tickOrFail(t, eng)

	workID := onlyWorkID(t, eng)
	eng.Submit(brain.WorkDispatched{ID: workID, MissionID: "m1", ItemKind: "tool", Target: "http"})
	eng.Submit(brain.WorkCompleted{ID: workID, Result: "ok"})
	tickOrFail(t, eng)

	// A second mission, after the completion: this is what used to vanish.
	eng.Submit(brain.MissionProjected{ID: "m2", Nodes: []brain.WorkNode{{ID: "probe2", Kind: "tool", Target: "http"}}})
	tickOrFail(t, eng)

	var found bool
	for _, m := range eng.Missions() {
		if m.ID == "m2" {
			found = true
		}
	}
	if !found {
		t.Fatal("the mission submitted after a work completion never reached the World")
	}
}
