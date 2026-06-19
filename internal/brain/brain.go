// Package brain is the ECS-native mission brain (epic ecs-brain, gibson#745).
//
// The brain is an Entity-Component-System (ark) per ADR-0001. Its core invariant
// is log-first event sourcing: a per-tenant append-only Timeline of domain events
// is the system of record, and the Tenant World is a fold of that Timeline. A
// single-writer reducer is the only thing that mutates the World; everything else
// emits events and reads snapshots. Replaying the Timeline into a fresh World
// reproduces state exactly — which is what powers crash-resume and the Scroller.
//
// This file establishes that spine end-to-end for one event type (HostObserved).
// Subsequent slices generalize it: scope-relative identity resolution (gibson#746),
// the emit bus + worker contract (sdk#341), and components codegen'd from
// taxonomy/v1 (sdk#340) replace the hand-written Host component below.
package brain

import (
	"sort"

	"github.com/mlange-42/ark/ecs"
)

// Host is a minimal component for the world-engine tracer bullet.
//
// Identity is (ScopeID, Address) — the scope-relative coordinate from ADR-0002.
// Ports is volatile state (updated-on-match, never compared). This struct is a
// placeholder; sdk#340 will codegen the real components from taxonomy/v1.
type Host struct {
	ScopeID string // identity
	Address string // identity (within scope)
	Ports   []int  // volatile
}

// World is a single tenant's in-memory ECS world (ADR-0001: one World per tenant,
// never shared; no cross-tenant anything). Only the reducer mutates it.
type World struct {
	Tenant string
	ecs    *ecs.World
	hosts  *ecs.Map1[Host]
}

// NewWorld returns an empty Tenant World.
func NewWorld(tenant string) *World {
	w := ecs.NewWorld()
	return &World{Tenant: tenant, ecs: w, hosts: ecs.NewMap1[Host](w)}
}

// findHost returns the entity for the host at (scope, address) if present.
// This is a deliberately trivial linear match; gibson#746 replaces it with the
// general scoped loop-compare resolution over identity signals.
func (w *World) findHost(scope, addr string) (ecs.Entity, bool) {
	q := ecs.NewFilter1[Host](w.ecs).Query()
	for q.Next() {
		h := q.Get()
		if h.ScopeID == scope && h.Address == addr {
			e := q.Entity()
			q.Close()
			return e, true
		}
	}
	return ecs.Entity{}, false
}

// HostSnapshot is a stable, comparable view of a Host for assertions/inspection.
type HostSnapshot struct {
	ScopeID string
	Address string
	Ports   []int
}

// Snapshot returns the current hosts in deterministic order — the materialized
// state derived from the fold so far.
func (w *World) Snapshot() []HostSnapshot {
	var out []HostSnapshot
	q := ecs.NewFilter1[Host](w.ecs).Query()
	for q.Next() {
		h := q.Get()
		ports := append([]int(nil), h.Ports...)
		out = append(out, HostSnapshot{ScopeID: h.ScopeID, Address: h.Address, Ports: ports})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ScopeID != out[j].ScopeID {
			return out[i].ScopeID < out[j].ScopeID
		}
		return out[i].Address < out[j].Address
	})
	return out
}

// Event is a domain event on the Timeline. Acting = emitting an event (the write).
type Event interface{ Kind() string }

// HostObserved records that a host was seen at (scope, address) with a set of
// open ports.
type HostObserved struct {
	ScopeID string
	Address string
	Ports   []int
}

func (HostObserved) Kind() string { return "host.observed" }

// Reduce folds one event into the World. It is the ONLY thing that mutates the
// World, and must be driven by a single goroutine (the engine tick).
func Reduce(w *World, ev Event) {
	switch e := ev.(type) {
	case HostObserved:
		if ent, ok := w.findHost(e.ScopeID, e.Address); ok {
			h := w.hosts.Get(ent)
			h.Ports = append([]int(nil), e.Ports...) // volatile: updated on match
			return
		}
		w.hosts.NewEntity(&Host{
			ScopeID: e.ScopeID,
			Address: e.Address,
			Ports:   append([]int(nil), e.Ports...),
		})
	}
}

// Timeline is the per-tenant append-only event log — the system of record.
// In-memory here; a durable append-only store backs it in a later slice.
type Timeline struct{ events []Event }

// Append adds an event to the end of the log.
func (t *Timeline) Append(e Event) { t.events = append(t.events, e) }

// Events returns the ordered events.
func (t *Timeline) Events() []Event { return t.events }

// Len is the number of events recorded.
func (t *Timeline) Len() int { return len(t.events) }

// Replay rebuilds a World by folding the whole Timeline. World == fold(Timeline),
// so Replay(t).Snapshot() equals the live World's Snapshot at the same head.
func Replay(tenant string, t *Timeline) *World {
	w := NewWorld(tenant)
	for _, ev := range t.Events() {
		Reduce(w, ev)
	}
	return w
}
