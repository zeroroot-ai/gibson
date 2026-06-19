// Package brain is the ECS-native mission brain (epic ecs-brain).
//
// The brain is an Entity-Component-System (ark) per ADR-0001. Its core invariant
// is log-first event sourcing: a per-tenant append-only Timeline of domain events
// is the system of record, and the Tenant World is a fold of that Timeline. A
// single-writer reducer is the only thing that mutates the World; everything else
// emits events and reads snapshots. Replaying the Timeline into a fresh World
// reproduces state exactly.
//
// Entity identity is scope-relative (ADR-0002, gibson#746): the coordinate of a
// host is (ScopeID, Address), and resolution is a scope-partitioned loop-compare
// over strong identity signals — see identity.go.
package brain

import (
	"sort"

	"github.com/mlange-42/ark/ecs"
)

// Host is the host component. Identity is the (ScopeID, Address) coordinate plus
// optional strong signals (SSHHostKey, CloudID) that identify the host across
// addresses. Ports is volatile state (updated-on-match, never compared).
// Placeholder shape; sdk#340 will codegen components from taxonomy/v1.
type Host struct {
	ID         uint64 // stable, replay-deterministic id (assigned at creation) for event references
	ScopeID    string // identity (coordinate)
	Address    string // identity (coordinate, within scope)
	SSHHostKey string // strong identity signal (stable across addresses)
	CloudID    string // strong identity signal
	Ports      []PortObservation
	Belief     Belief // attack-path belief (derived; ADR-0005)
}

// Surprise marks an entity the model did not expect — here, an identity
// contradiction (an address reused by a different host). It is the input to the
// attention/anomaly signal (ADR-0005/0006); it is not itself a separate entity.
type Surprise struct {
	Reason string
}

// World is a single tenant's in-memory ECS world (ADR-0001: one World per tenant,
// never shared). Only the reducer mutates it.
type World struct {
	Tenant    string
	ecs       *ecs.World
	hosts     *ecs.Map1[Host]
	surprises *ecs.Map1[Surprise]
	work      *ecs.Map1[WorkItem]
	missions  *ecs.Map1[Mission]
	findings  *ecs.Map1[Finding]

	// nextHostID is a monotonic, replay-deterministic counter for assigning stable
	// host ids (incremented in the single-writer reducer, so replay reproduces ids).
	nextHostID uint64
}

// newHostID returns the next stable host id (single-writer; deterministic on replay).
func (w *World) newHostID() uint64 {
	w.nextHostID++
	return w.nextHostID
}

// NewWorld returns an empty Tenant World.
func NewWorld(tenant string) *World {
	w := ecs.NewWorld()
	return &World{
		Tenant:    tenant,
		ecs:       w,
		hosts:     ecs.NewMap1[Host](w),
		surprises: ecs.NewMap1[Surprise](w),
		work:      ecs.NewMap1[WorkItem](w),
		missions:  ecs.NewMap1[Mission](w),
		findings:  ecs.NewMap1[Finding](w),
	}
}

// HostSnapshot is a stable, comparable view of a Host for assertions/inspection.
type HostSnapshot struct {
	ScopeID    string
	Address    string
	SSHHostKey string
	CloudID    string
	OpenPorts  []int               // currently-open port numbers, ascending
	Services   map[int]ServiceInfo // service detail by port, for open ports that carry it
	Surprise   string              // non-empty if the entity carries a Surprise
	Belief     Belief              // attack-path belief (zero until a BeliefSystem scores it)
	Attention  float64             // derived: belief.Juicy + surprise boost (ADR-0005/0006)
}

// Snapshot returns the current hosts in deterministic order — the materialized
// state derived from the fold so far.
func (w *World) Snapshot() []HostSnapshot {
	// First collect entities carrying a Surprise (separate query; drains fully).
	surprised := map[ecs.Entity]string{}
	sq := ecs.NewFilter1[Surprise](w.ecs).Query()
	for sq.Next() {
		surprised[sq.Entity()] = sq.Get().Reason
	}

	var out []HostSnapshot
	q := ecs.NewFilter1[Host](w.ecs).Query()
	for q.Next() {
		h := q.Get()
		var open []int
		var svcs map[int]ServiceInfo
		for _, p := range h.Ports {
			if p.Open {
				open = append(open, p.Number)
				if (p.Service != ServiceInfo{}) {
					if svcs == nil {
						svcs = map[int]ServiceInfo{}
					}
					svcs[p.Number] = p.Service
				}
			}
		}
		sort.Ints(open)
		out = append(out, HostSnapshot{
			ScopeID:    h.ScopeID,
			Address:    h.Address,
			SSHHostKey: h.SSHHostKey,
			CloudID:    h.CloudID,
			OpenPorts:  open,
			Services:   svcs,
			Surprise:   surprised[q.Entity()],
			Belief:     h.Belief,
			Attention:  attentionScore(h.Belief.Juicy, surprised[q.Entity()] != ""),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ScopeID != out[j].ScopeID {
			return out[i].ScopeID < out[j].ScopeID
		}
		if out[i].Address != out[j].Address {
			return out[i].Address < out[j].Address
		}
		return out[i].SSHHostKey < out[j].SSHHostKey
	})
	return out
}

// Event is a domain event on the Timeline. Acting = emitting an event (the write).
type Event interface{ Kind() string }

// HostObserved records that a host was seen at (ScopeID, Address), optionally
// with strong identity signals, the set of ports observed open in this scan, and
// optional per-port service detail. Services is keyed by port number; a port may
// appear in OpenPorts without a Services entry (a bare open port) — service detail
// is enriched progressively across observations (ADR-0007).
type HostObserved struct {
	ScopeID    string
	Address    string
	SSHHostKey string
	CloudID    string
	OpenPorts  []int
	Services   map[int]ServiceInfo
}

func (HostObserved) Kind() string { return "host.observed" }

// Reduce folds one event into the World. It is the ONLY thing that mutates the
// World, and must be driven by a single goroutine (the engine tick).
func Reduce(w *World, ev Event) {
	switch e := ev.(type) {
	case HostObserved:
		applyHostObserved(w, e)
	case WorkDispatched:
		applyWorkDispatched(w, e)
	case WorkCompleted:
		applyWorkCompleted(w, e)
	case MissionStarted:
		applyMissionStarted(w, e)
	case MissionDone:
		applyMissionDone(w, e)
	case BeliefScored:
		applyBeliefScored(w, e)
	case FindingRaised:
		applyFindingRaised(w, e)
	}
}

// Timeline is the per-tenant append-only event log — the system of record.
type Timeline struct{ events []Event }

// Append adds an event to the end of the log.
func (t *Timeline) Append(e Event) { t.events = append(t.events, e) }

// Events returns the ordered events.
func (t *Timeline) Events() []Event { return t.events }

// Len is the number of events recorded.
func (t *Timeline) Len() int { return len(t.events) }

// Replay rebuilds a World by folding the whole Timeline. World == fold(Timeline).
func Replay(tenant string, t *Timeline) *World {
	w := NewWorld(tenant)
	for _, ev := range t.Events() {
		Reduce(w, ev)
	}
	return w
}
