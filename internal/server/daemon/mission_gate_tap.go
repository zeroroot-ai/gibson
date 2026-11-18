// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

// The mission gate (gibson#1389, ADR-0172).
//
// ext-authz refuses a model call of a mission that is not active. It reads one
// FGA tuple with a condition, the same pattern as the session revocation
// (gibson#627):
//
//	tenant:<id> | active | mission:<id>   condition mission_active{active: bool}
//
// This tap keeps the tuple true to the World. After each mission lifecycle event
// it reads the status of the mission in the World. When "active" changed, it
// writes the new value. A working mission and a mission that waits for input are
// active (brain.MissionStatus.IsActive). A paused mission and a mission that
// ended are not. The daemon writes no marker to Redis.

var missionGateWriteFailedTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "gibson_mission_gate_write_failed_total",
	Help: "Mission gate FGA writes that failed after all attempts.",
})

// missionGateWriter writes one conditioned tuple. authz.ConditionalWriter
// satisfies it.
type missionGateWriter interface {
	UpdateConditionalTuple(ctx context.Context, t authz.ConditionalTuple) error
}

const (
	missionGateAttempts     = 5
	missionGateWriteTimeout = 10 * time.Second
)

type missionGateWrite struct {
	mission string
	active  bool
}

// missionGateTap is an engine tap. It runs inside the tick, so it reads the
// World directly and never calls a locking accessor of the engine (see the note
// on lifecycleProjectorTap.apply, gibson#1206). It does no I/O in the tick. One
// drainer goroutine writes the queue in order.
type missionGateTap struct {
	tenant string
	eng    *brain.Engine
	writer missionGateWriter
	logger *slog.Logger

	// backoff is the wait before attempt n+1 (n starts at 1). A test injects a
	// short one.
	backoff func(attempt int) time.Duration

	mu       sync.Mutex
	last     map[string]bool // mission id -> the value that was queued last
	queue    []missionGateWrite
	draining bool
}

// missionIDOf returns the mission of a lifecycle event that can change whether
// the mission is active, and "" for any other event.
func missionIDOf(ev brain.Event) string {
	switch e := ev.(type) {
	case brain.MissionProjected:
		return e.ID
	case brain.MissionStarted:
		return e.ID
	case brain.MissionPauseRequested:
		return e.ID
	case brain.MissionResumed:
		return e.ID
	case brain.MissionDone:
		return e.ID
	}
	return ""
}

func (t *missionGateTap) apply(ev brain.Event) {
	id := missionIDOf(ev)
	if id == "" {
		return
	}
	// The status comes from the World, not from the event. The reducer drops an
	// event of an old run, so a late event cannot close the gate of a new run.
	var status brain.MissionStatus
	var found bool
	for _, m := range t.eng.World.MissionSnapshot() {
		if m.ID == id {
			status, found = m.Status, true
			break
		}
	}
	if !found {
		return
	}
	active := status.IsActive()

	t.mu.Lock()
	if prev, ok := t.last[id]; ok && prev == active {
		t.mu.Unlock()
		return
	}
	t.last[id] = active
	t.queue = append(t.queue, missionGateWrite{mission: id, active: active})
	start := !t.draining
	if start {
		t.draining = true
	}
	t.mu.Unlock()
	if start {
		go t.drain()
	}
}

func (t *missionGateTap) drain() {
	for {
		t.mu.Lock()
		if len(t.queue) == 0 {
			t.draining = false
			t.mu.Unlock()
			return
		}
		w := t.queue[0]
		t.queue = t.queue[1:]
		t.mu.Unlock()
		t.write(w)
	}
}

// write sends one value to FGA with a few attempts. When all fail, it forgets
// the value that it queued, so the next event of the mission writes again.
func (t *missionGateTap) write(w missionGateWrite) {
	tuple := authz.MissionActiveTuple(t.tenant, w.mission, w.active)
	var err error
	for attempt := 1; attempt <= missionGateAttempts; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), missionGateWriteTimeout)
		err = t.writer.UpdateConditionalTuple(ctx, tuple)
		cancel()
		if err == nil {
			t.logger.Debug("mission gate written", "mission", w.mission, "active", w.active)
			return
		}
		if attempt < missionGateAttempts {
			time.Sleep(t.backoff(attempt))
		}
	}
	missionGateWriteFailedTotal.Inc()
	t.logger.Error("mission gate write failed", "mission", w.mission, "active", w.active, "error", err)
	t.mu.Lock()
	delete(t.last, w.mission)
	t.mu.Unlock()
}

// InstallMissionGate registers the mission gate tap on a tenant engine. It is
// called once for each engine, from brain.Registry.OnEngine, before the tick
// loop starts.
func InstallMissionGate(tenant string, eng *brain.Engine, writer missionGateWriter, logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}
	tap := &missionGateTap{
		tenant:  tenant,
		eng:     eng,
		writer:  writer,
		logger:  logger.With("component", "mission-gate", "tenant", tenant),
		backoff: func(attempt int) time.Duration { return time.Duration(attempt) * 200 * time.Millisecond },
		last:    map[string]bool{},
	}
	eng.Subscribe(tap.apply)
}
