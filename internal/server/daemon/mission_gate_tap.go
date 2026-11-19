// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
)

// The mission gate (gibson#1389, ADR-0172).
//
// ext-authz refuses a model call or an A2A call of a mission that is not active.
// It reads one FGA tuple with a condition, the same pattern as the session
// revocation (gibson#627):
//
//	tenant:<id> | active | mission:<id>   condition mission_active{active: true}
//
// The gate is open while the tuple exists. An absent tuple is closed. This tap
// keeps the tuple true to the World. After each mission lifecycle event it reads
// the status of the mission in the World. A working mission and a mission that
// waits for input are active (brain.MissionStatus.IsActive). A paused mission
// and a mission that ended are not. The daemon writes no marker to Redis.
//
// Order. A work item of a mission gets a task grant, and the agent then calls a
// gateway at once. So the gate must be open and confirmed BEFORE the work item
// is dispatched. The brain executor calls AwaitOpen before it starts any work
// item (brainExecutor.Dispatch). AwaitOpen returns when the write of the open
// gate is confirmed, and it returns the error when the write failed. A work item
// of a mission whose gate cannot be written fails with that reason and does not
// start.
//
// Pause and resume. A pause closes the gate: the tuple is deleted, and ext-authz
// refuses the next call at once. A resume opens it again with the same write and
// the same order: work items that the resume lets run wait for the confirmed
// tuple. A work item that was dispatched before the pause gets no new wait.
//
// The write never removes an open gate that is correct. Opening a gate that is
// open sends no write. Closing is one delete (authz.MissionGateWriter).

var missionGateWriteFailedTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "gibson_mission_gate_write_failed_total",
	Help: "Mission gate FGA writes that failed after all attempts.",
})

// missionGateWriter opens or closes the gate of a mission.
// authz.MissionGateWriter satisfies it.
type missionGateWriter interface {
	SetMissionGate(ctx context.Context, tenant, mission string, active bool) error
}

const (
	missionGateAttempts     = 5
	missionGateWriteTimeout = 10 * time.Second
	// missionGateAwaitTimeout bounds the wait of a work item for the gate. It is
	// longer than all attempts of one write, at their longest.
	missionGateAwaitTimeout = 90 * time.Second
)

type missionGateWrite struct {
	mission string
	active  bool
	seq     uint64
}

// gateState is what the tap knows about the gate of one mission.
type gateState struct {
	// desired is the value that was queued last, and seq is its number. known is
	// false after a write failed, so the next event of the mission writes again.
	desired bool
	seq     uint64
	known   bool
	// doneSeq is the number of the last write that is confirmed. err is the error
	// of a write that failed after all attempts, for the write that holds seq.
	doneSeq uint64
	err     error
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
	states   map[string]*gateState
	nextSeq  uint64
	notify   chan struct{} // closed and replaced when a write ends
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

// sweep writes the right tuple for each mission that the World holds. It runs
// once, when the engine is created, after the World is rebuilt from the Timeline
// and before the tick loop starts. A replay fires no tap, so a crash between a
// state change and its write would leave a wrong tuple for ever. The sweep
// closes that gap. A mission that is only submitted is not active for a model
// call, and it gets no tuple: an absent tuple refuses the call.
func (t *missionGateTap) sweep() {
	snapshot := t.eng.World.MissionSnapshot()
	t.mu.Lock()
	for _, m := range snapshot {
		if m.Status == brain.MissionSubmitted {
			continue
		}
		t.queueLocked(m.ID, m.Status.IsActive())
	}
	start := len(t.queue) > 0 && !t.draining
	if start {
		t.draining = true
	}
	t.mu.Unlock()
	if start {
		go t.drain()
	}
}

// queueLocked records the value for a mission and queues its write. The caller
// holds t.mu.
func (t *missionGateTap) queueLocked(id string, active bool) {
	st := t.states[id]
	if st == nil {
		st = &gateState{}
		t.states[id] = st
	}
	t.nextSeq++
	st.desired, st.seq, st.known, st.err = active, t.nextSeq, true, nil
	t.queue = append(t.queue, missionGateWrite{mission: id, active: active, seq: st.seq})
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
	// A submitted mission is not active for a model call and has no tuple.
	if !found || status == brain.MissionSubmitted {
		return
	}
	active := status.IsActive()

	t.mu.Lock()
	if st, ok := t.states[id]; ok && st.known && st.desired == active {
		t.mu.Unlock()
		return
	}
	t.queueLocked(id, active)
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

// write sends one value to FGA with a few attempts. When all fail, it keeps the
// error for the waiters and forgets the value, so the next event of the mission
// writes again.
func (t *missionGateTap) write(w missionGateWrite) {
	var err error
	for attempt := 1; attempt <= missionGateAttempts; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), missionGateWriteTimeout)
		err = t.writer.SetMissionGate(ctx, t.tenant, w.mission, w.active)
		cancel()
		if err == nil {
			t.logger.Debug("mission gate written", "mission", w.mission, "active", w.active)
			t.finish(w, nil)
			return
		}
		if attempt < missionGateAttempts {
			time.Sleep(t.backoff(attempt))
		}
	}
	missionGateWriteFailedTotal.Inc()
	t.logger.Error("mission gate write failed", "mission", w.mission, "active", w.active, "error", err)
	t.finish(w, err)
}

// finish records the end of a write and wakes the waiters. A write that a later
// value replaced changes nothing for the later value.
func (t *missionGateTap) finish(w missionGateWrite, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if st := t.states[w.mission]; st != nil {
		if err == nil && w.seq > st.doneSeq {
			st.doneSeq = w.seq
		}
		if err != nil && st.seq == w.seq {
			st.err, st.known = err, false
		}
	}
	close(t.notify)
	t.notify = make(chan struct{})
}

// AwaitOpen returns when the gate of the mission is confirmed, if the World says
// that the mission is active. It returns at once when the tap holds no open
// value for the mission: a gate that is closed or unknown refuses a call at
// ext-authz, so a work item that starts then is refused there (fail closed). It
// returns the error of the write when the write failed, and the error of ctx
// when the wait ends.
func (t *missionGateTap) AwaitOpen(ctx context.Context, mission string) error {
	for {
		t.mu.Lock()
		st := t.states[mission]
		switch {
		case st == nil || !st.desired:
			t.mu.Unlock()
			return nil
		case st.err != nil:
			err := st.err
			t.mu.Unlock()
			return fmt.Errorf("the gate of mission %s could not be opened: %w", mission, err)
		case st.doneSeq >= st.seq:
			t.mu.Unlock()
			return nil
		}
		wait := t.notify
		t.mu.Unlock()
		select {
		case <-wait:
		case <-ctx.Done():
			return fmt.Errorf("wait for the gate of mission %s: %w", mission, ctx.Err())
		}
	}
}

// missionGateAwaiter is what the brain executor needs of the gate.
type missionGateAwaiter interface {
	AwaitOpen(ctx context.Context, mission string) error
}

// InstallMissionGate registers the mission gate tap on a tenant engine and
// returns it. It is called once for each engine, from brain.Registry.OnEngine,
// before the tick loop starts.
func InstallMissionGate(tenant string, eng *brain.Engine, writer missionGateWriter, logger *slog.Logger) *missionGateTap {
	if logger == nil {
		logger = slog.Default()
	}
	tap := &missionGateTap{
		tenant:  tenant,
		eng:     eng,
		writer:  writer,
		logger:  logger.With("component", "mission-gate", "tenant", tenant),
		backoff: func(attempt int) time.Duration { return time.Duration(attempt) * 200 * time.Millisecond },
		states:  map[string]*gateState{},
		notify:  make(chan struct{}),
	}
	tap.sweep()
	eng.Subscribe(tap.apply)
	return tap
}
