// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package liveagents holds the daemon's in-memory registry of running agent
// instances and their live structured-event feeds (ADR-0016 S11, gibson#1599).
//
// While a sandboxed agent runs, the launcher tees the agent's structured
// output (opencode NDJSON) into this registry. A read-only surface
// (AgentConsoleService) lists the caller-tenant's running instances and
// subscribes to one instance's live events. Every entry is keyed by the
// CUSTOMER tenant that owns the mission run, so a subscriber can only ever see
// its own tenant's instances. The registry never parses the event bytes; it
// fans them out unchanged.
//
// The registry is a tap on the existing S4 log tee, not a new transport: the
// launcher already streams the sandbox log to a ring buffer and the daemon
// logger, and this adds one more sink alongside them.
//
// Each instance keeps a bounded backlog of its most recent chunks, numbered
// by a per-instance sequence. A subscriber passes the last sequence it saw
// and receives the backlog after it, then the live feed, with no gap and no
// duplicate between the two (dashboard#1148). A console tile that scrolls
// back into view backfills its tail from here instead of reconnecting blind.
package liveagents

import (
	"log/slog"
	"sort"
	"sync"
	"time"
)

// defaultSubscriberBuffer bounds each subscriber's channel. A slow subscriber
// does not block the launcher's log drain or the other subscribers: when its
// buffer is full the registry drops the chunk for that subscriber only. A live
// console tolerates a dropped chunk far better than a stalled sandbox stream.
const defaultSubscriberBuffer = 256

// defaultBacklogChunks and defaultBacklogBytes bound each instance's backlog.
// The backlog keeps at most this many chunks and at most this many bytes,
// whichever fills first; the oldest chunks drop. One agent turn is a few
// kilobytes of NDJSON, so a megabyte holds many turns of tail. The bounds
// are fixed: a console tail is a diagnostic window, not a store.
const (
	defaultBacklogChunks = 2048
	defaultBacklogBytes  = 1 << 20
)

// Event is one chunk of an instance's structured output. Seq is the
// per-instance sequence number, starting at 1 and never reused, so a
// subscriber can resume after the last Seq it saw. At is when the registry
// received the chunk.
type Event struct {
	Seq  uint64
	At   time.Time
	Data []byte
}

// Instance is the public metadata of one running agent instance. It carries no
// tenant field: the tenant is the enumeration key and is never returned to the
// caller, which already knows its own tenant.
type Instance struct {
	// RunID uniquely identifies this running instance within the tenant.
	RunID string
	// AgentName is the dispatched agent's name.
	AgentName string
	// SandboxID is the setec sandbox backing this run, for operator diagnostics.
	SandboxID string
	// SandboxClass is the setec SandboxClass the run was launched under
	// (ADR-0016 decision 4). It names the isolation posture, so a viewer can
	// see what a run is confined by, not only that it is confined.
	SandboxClass string
	// ComponentKind is what kind of component is running: "agent" or "tool".
	ComponentKind string
	// StartedAt is when the instance was registered (dispatch start).
	StartedAt time.Time
	// MissionID and MissionRunID are the mission and the mission run this
	// instance serves, so a console can link the run to its mission and stop
	// it through the mission surface. Empty for a run outside a mission.
	MissionID    string
	MissionRunID string
}

// Registry is the tenant-keyed set of running agent instances. It is safe for
// concurrent use.
type Registry struct {
	mu       sync.RWMutex
	byTenant map[string]map[string]*instanceState
	subBuf   int
	logger   *slog.Logger
}

// Option configures a Registry.
type Option func(*Registry)

// WithSubscriberBuffer overrides the per-subscriber channel buffer. A value of
// zero or less keeps the default.
func WithSubscriberBuffer(n int) Option {
	return func(r *Registry) {
		if n > 0 {
			r.subBuf = n
		}
	}
}

// WithLogger sets the registry logger. A nil logger keeps slog.Default.
func WithLogger(l *slog.Logger) Option {
	return func(r *Registry) {
		if l != nil {
			r.logger = l
		}
	}
}

// NewRegistry constructs an empty Registry.
func NewRegistry(opts ...Option) *Registry {
	r := &Registry{
		byTenant: make(map[string]map[string]*instanceState),
		subBuf:   defaultSubscriberBuffer,
		logger:   slog.Default(),
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// RegisterInstance records a running agent instance for the given tenant and
// returns two functions: publish tees one event chunk to every current
// subscriber, and finish deregisters the instance and closes every subscriber
// stream (call it exactly once, at the run's terminal state).
//
// An empty tenant or RunID registers nothing and returns no-op functions, so a
// dispatch with no scope never creates an unreachable entry. It satisfies
// sandboxed.EventPublisher.
func (r *Registry) RegisterInstance(tenant string, inst Instance) (publish func([]byte), finish func()) {
	if tenant == "" || inst.RunID == "" {
		return func([]byte) {}, func() {}
	}
	runID := inst.RunID
	st := &instanceState{
		info:          inst,
		subs:          make(map[int]chan Event),
		subBuf:        r.subBuf,
		backlogChunks: defaultBacklogChunks,
		backlogBytes:  defaultBacklogBytes,
	}
	r.mu.Lock()
	tenantRuns := r.byTenant[tenant]
	if tenantRuns == nil {
		tenantRuns = make(map[string]*instanceState)
		r.byTenant[tenant] = tenantRuns
	}
	// A duplicate runID replaces the old entry; close the old feed so its
	// subscribers do not hang on a stream that will never advance again.
	if old := tenantRuns[runID]; old != nil {
		old.close()
	}
	tenantRuns[runID] = st
	r.mu.Unlock()

	return st.publish, func() { r.deregister(tenant, runID, st) }
}

// deregister removes the instance from the tenant index and closes its feed.
func (r *Registry) deregister(tenant, runID string, st *instanceState) {
	r.mu.Lock()
	if tenantRuns := r.byTenant[tenant]; tenantRuns != nil {
		// Only remove the entry if it is still the one we registered; a
		// duplicate-runID re-register may have replaced it already.
		if tenantRuns[runID] == st {
			delete(tenantRuns, runID)
			if len(tenantRuns) == 0 {
				delete(r.byTenant, tenant)
			}
		}
	}
	r.mu.Unlock()
	st.close()
}

// List returns the running instances for one tenant, sorted by start time then
// run id for a stable order. A tenant with nothing running returns an empty
// slice. The result never includes another tenant's instances.
func (r *Registry) List(tenant string) []Instance {
	r.mu.RLock()
	tenantRuns := r.byTenant[tenant]
	out := make([]Instance, 0, len(tenantRuns))
	for _, st := range tenantRuns {
		out = append(out, st.info)
	}
	r.mu.RUnlock()

	sort.Slice(out, func(i, j int) bool {
		if out[i].StartedAt.Equal(out[j].StartedAt) {
			return out[i].RunID < out[j].RunID
		}
		return out[i].StartedAt.Before(out[j].StartedAt)
	})
	return out
}

// Subscribe returns the backlog after sinceSeq (oldest first), a receive-only
// channel of the live events that follow it, and a cancel function the caller
// must call when it stops reading. Backlog and channel are cut at the same
// instant under the instance lock, so no event is missed or repeated between
// them. sinceSeq zero means "everything the backlog still holds". The channel
// closes when the instance reaches its terminal state.
//
// A runID that the tenant does not own returns ErrInstanceNotFound. This is the
// server-enforced isolation boundary: a foreign run id is indistinguishable
// from one that never existed, so the surface never leaks another tenant's run
// ids.
// Publish appends one event to a running instance's feed from outside the
// launcher: the daemon's own job and member-status lines (ADR-0019,
// gibson#1716). A console reading the member's stream sees them in order with
// the agent's own output. ErrInstanceNotFound when the run is not live.
func (r *Registry) Publish(tenant, runID string, data []byte) error {
	r.mu.RLock()
	tenantRuns := r.byTenant[tenant]
	var st *instanceState
	if tenantRuns != nil {
		st = tenantRuns[runID]
	}
	r.mu.RUnlock()
	if st == nil {
		return ErrInstanceNotFound
	}
	st.publish(data)
	return nil
}

func (r *Registry) Subscribe(tenant, runID string, sinceSeq uint64) (backlog []Event, events <-chan Event, cancel func(), err error) {
	r.mu.RLock()
	tenantRuns := r.byTenant[tenant]
	var st *instanceState
	if tenantRuns != nil {
		st = tenantRuns[runID]
	}
	r.mu.RUnlock()

	if st == nil {
		return nil, nil, nil, ErrInstanceNotFound
	}
	backlog, ch, cancel := st.addSubscriber(sinceSeq)
	return backlog, ch, cancel, nil
}

// instanceState holds one running instance's metadata and its fan-out
// subscribers.
type instanceState struct {
	info          Instance
	subBuf        int
	backlogChunks int
	backlogBytes  int

	mu      sync.Mutex
	subs    map[int]chan Event
	nextID  int
	closed  bool
	nextSeq uint64
	// backlog holds the most recent events, oldest first, bounded by
	// backlogChunks and backlogBytes.
	backlog     []Event
	backlogSize int
}

// publish copies the chunk, records it in the backlog, and offers it to every
// subscriber without blocking. A subscriber whose buffer is full misses this
// chunk on the live feed; it does not stall the tee or the other subscribers,
// and it can backfill the miss from the backlog by sequence.
func (s *instanceState) publish(chunk []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	cp := make([]byte, len(chunk))
	copy(cp, chunk)
	s.nextSeq++
	ev := Event{Seq: s.nextSeq, At: time.Now(), Data: cp}
	s.record(ev)
	for _, ch := range s.subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

// record appends one event to the backlog and drops the oldest events until
// the backlog fits its chunk and byte bounds again. Caller holds s.mu.
func (s *instanceState) record(ev Event) {
	s.backlog = append(s.backlog, ev)
	s.backlogSize += len(ev.Data)
	drop := 0
	for drop < len(s.backlog)-1 &&
		(len(s.backlog)-drop > s.backlogChunks || s.backlogSize > s.backlogBytes) {
		s.backlogSize -= len(s.backlog[drop].Data)
		drop++
	}
	if drop > 0 {
		// Reslice into a fresh array so the dropped chunks can be collected.
		kept := make([]Event, len(s.backlog)-drop, s.backlogChunks)
		copy(kept, s.backlog[drop:])
		s.backlog = kept
	}
}

// since returns the backlog events after seq, oldest first. Caller holds s.mu.
func (s *instanceState) since(seq uint64) []Event {
	i := sort.Search(len(s.backlog), func(i int) bool { return s.backlog[i].Seq > seq })
	if i >= len(s.backlog) {
		return nil
	}
	out := make([]Event, len(s.backlog)-i)
	copy(out, s.backlog[i:])
	return out
}

// addSubscriber cuts the backlog after sinceSeq and registers a new subscriber
// channel in one step, and returns both with a cancel function. If the
// instance is already closed, it returns the backlog and an already-closed
// channel so the caller's read loop ends at once.
func (s *instanceState) addSubscriber(sinceSeq uint64) (backlog []Event, events <-chan Event, cancel func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	backlog = s.since(sinceSeq)
	if s.closed {
		ch := make(chan Event)
		close(ch)
		return backlog, ch, func() {}
	}
	id := s.nextID
	s.nextID++
	ch := make(chan Event, s.subBuf)
	s.subs[id] = ch
	return backlog, ch, func() { s.removeSubscriber(id) }
}

// removeSubscriber drops one subscriber. It is idempotent and safe to call
// after close.
func (s *instanceState) removeSubscriber(id int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ch, ok := s.subs[id]; ok {
		delete(s.subs, id)
		close(ch)
	}
}

// close marks the instance terminal and closes every subscriber channel. It is
// idempotent.
func (s *instanceState) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	for id, ch := range s.subs {
		delete(s.subs, id)
		close(ch)
	}
}
