package brain

import "github.com/mlange-42/ark/ecs"

// PortObservation is a port's state on a host. Open is volatile: a port no longer
// observed is closed (Open=false), not deleted — the record (and thus history) is
// kept (ADR-0002: associations are time-bounded, never deleted).
type PortObservation struct {
	Number int
	Open   bool
}

// findHostByID returns the host entity with the given stable id, if present.
func findHostByID(w *World, id uint64) (ecs.Entity, bool) {
	q := ecs.NewFilter1[Host](w.ecs).Query()
	for q.Next() {
		if q.Get().ID == id {
			e := q.Entity()
			q.Close()
			return e, true
		}
	}
	return ecs.Entity{}, false
}

// findHostByCoord returns the host entity at (scope, address), if present.
func findHostByCoord(w *World, scope, addr string) (ecs.Entity, bool) {
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

// applyHostObserved resolves an observed host to an existing entity (or creates
// one) and folds the observation in. This is the scope-relative identity model
// (ADR-0002): resolution is a scope-partitioned loop-compare over strong signals,
// with progressive identity enrichment and contradiction detection.
func applyHostObserved(w *World, e HostObserved) {
	ent, matched, contradiction := resolveHost(w, e)
	if !matched {
		h := &Host{ID: w.newHostID(), ScopeID: e.ScopeID, Address: e.Address, SSHHostKey: e.SSHHostKey, CloudID: e.CloudID}
		reconcilePorts(h, e.OpenPorts)
		ne := w.hosts.NewEntity(h)
		if contradiction {
			// Same coordinate, different strong signal: a different host now answers
			// at this address (reimage / DHCP churn / NAT / MITM). Security-relevant —
			// surface it instead of silently merging or overwriting.
			w.surprises.Add(ne, &Surprise{Reason: "address reused by a different host (strong-signal mismatch)"})
		}
		return
	}
	// Matched: progressive identity enrichment — accrete strong signals we didn't
	// have yet — plus volatile port update. Address is kept (a strong-signal match
	// at a new address means the host is multi-addressed; not clobbered here).
	h := w.hosts.Get(ent)
	if h.SSHHostKey == "" {
		h.SSHHostKey = e.SSHHostKey
	}
	if h.CloudID == "" {
		h.CloudID = e.CloudID
	}
	reconcilePorts(h, e.OpenPorts)
}

// resolveHost finds the entity for an observed host within its scope. It is
// read-only (the query fully drains, unlocking the world) so the caller may
// mutate afterwards. Match order (ADR-0002):
//  1. a strong signal (ssh host key / cloud id) anywhere in the scope — the same
//     host, even at a different address (progressive identity);
//  2. else the (scope, address) coordinate, provided no strong signal contradicts;
//  3. else no match — a new host. A coordinate hit whose strong signal differs
//     from the observation is a contradiction (returns matched=false, contradiction=true).
func resolveHost(w *World, e HostObserved) (ent ecs.Entity, matched bool, contradiction bool) {
	var strong, coord ecs.Entity
	var haveStrong, haveCoord bool
	var coordKey, coordCloud string

	q := ecs.NewFilter1[Host](w.ecs).Query()
	for q.Next() {
		h := q.Get()
		if h.ScopeID != e.ScopeID { // scope partitions the comparison set
			continue
		}
		if !haveStrong && ((e.SSHHostKey != "" && h.SSHHostKey == e.SSHHostKey) ||
			(e.CloudID != "" && h.CloudID == e.CloudID)) {
			strong, haveStrong = q.Entity(), true
		}
		if !haveCoord && h.Address == e.Address {
			coord, haveCoord = q.Entity(), true
			coordKey, coordCloud = h.SSHHostKey, h.CloudID
		}
	}
	// Query exhausted → world unlocked.

	if haveStrong {
		return strong, true, false
	}
	if haveCoord {
		mismatch := (e.SSHHostKey != "" && coordKey != "" && e.SSHHostKey != coordKey) ||
			(e.CloudID != "" && coordCloud != "" && e.CloudID != coordCloud)
		if mismatch {
			return ecs.Entity{}, false, true
		}
		return coord, true, false
	}
	return ecs.Entity{}, false, false
}

// reconcilePorts folds a scan's open-port set into a host: ports seen this scan
// are open; previously-known ports not seen are closed (kept, not removed);
// newly-seen ports are appended.
func reconcilePorts(h *Host, observedOpen []int) {
	obs := make(map[int]bool, len(observedOpen))
	for _, p := range observedOpen {
		obs[p] = true
	}
	known := make(map[int]bool, len(h.Ports))
	for i := range h.Ports {
		known[h.Ports[i].Number] = true
		h.Ports[i].Open = obs[h.Ports[i].Number]
	}
	for _, p := range observedOpen {
		if !known[p] {
			h.Ports = append(h.Ports, PortObservation{Number: p, Open: true})
			known[p] = true
		}
	}
}
