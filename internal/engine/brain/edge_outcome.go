// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import "sort"

// EdgeOutcomeObserved records one cause-active, effect-observed outcome for
// an enablement-edge TYPE (ADR-0037 decision 2): the slice that produced a
// hypothesis carried this edge type among its causes, and the bet on that
// hypothesis settled. Success is the settlement verdict. One event is folded
// per cause edge type of the settled bet, by the engine, right after the
// settlement event itself (gibson#613).
//
// It folds through the normal reducer path (ADR-0007), so replay reproduces
// the same counts, and the counts live in the World so a snapshot carries
// them and TrimTo loses nothing: the trainer (gibson#614) reads
// World.EdgeOutcomeCounts, never the event stream.
type EdgeOutcomeObserved struct {
	EdgeType  string
	Success   bool
	MissionID string
	ScopeID   string
}

// Kind identifies the edge.outcome_observed brain event.
func (EdgeOutcomeObserved) Kind() string { return "edge.outcome_observed" }

// EdgeOutcomeCount is the Beta-Bernoulli sufficient statistic for one edge
// type: Alpha successes and Beta failures observed so far. braintrain adds
// the cold-start prior at fit time, so a fresh World starts at zero here.
type EdgeOutcomeCount struct {
	Alpha float64
	Beta  float64
}

// applyEdgeOutcomeObserved folds one outcome into the World's per-edge-type
// counts. An empty EdgeType records nothing: there is no edge to learn.
func applyEdgeOutcomeObserved(w *World, e EdgeOutcomeObserved) {
	if e.EdgeType == "" {
		return
	}
	c := w.edgeOutcomes[e.EdgeType]
	if e.Success {
		c.Alpha++
	} else {
		c.Beta++
	}
	w.edgeOutcomes[e.EdgeType] = c
}

// EdgeOutcomeCounts returns a copy of the per-edge-type outcome counts.
func (w *World) EdgeOutcomeCounts() map[string]EdgeOutcomeCount {
	out := make(map[string]EdgeOutcomeCount, len(w.edgeOutcomes))
	for k, v := range w.edgeOutcomes {
		out[k] = v
	}
	return out
}

// EdgeOutcomeSnapshot is one edge type's counts in a WorldSnapshot.
type EdgeOutcomeSnapshot struct {
	EdgeType string
	Alpha    float64
	Beta     float64
}

// EdgeOutcomeSnapshot returns the counts in deterministic EdgeType order.
func (w *World) EdgeOutcomeSnapshot() []EdgeOutcomeSnapshot {
	out := make([]EdgeOutcomeSnapshot, 0, len(w.edgeOutcomes))
	for k, v := range w.edgeOutcomes {
		out = append(out, EdgeOutcomeSnapshot{EdgeType: k, Alpha: v.Alpha, Beta: v.Beta})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].EdgeType < out[j].EdgeType })
	return out
}

// EdgeOutcomeCounts returns the engine's World counts under the read lock.
func (e *Engine) EdgeOutcomeCounts() map[string]EdgeOutcomeCount {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.World.EdgeOutcomeCounts()
}

// sliceCauseEdgeTypes lists, sorted and unique, the types of the slice edges
// that feed nodeID. A slice is already ontology-filtered (DeriveAttackGraph
// keeps only enablement edges), so these are exactly the causes ADR-0037
// decision 2 learns from.
func sliceCauseEdgeTypes(slice AttackGraph, nodeID string) []string {
	seen := map[string]struct{}{}
	for _, e := range slice.Edges {
		if e.To != nodeID || e.Type == "" {
			continue
		}
		seen[e.Type] = struct{}{}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// causeEdgeTypesForHypothesis resolves the cause edge types recorded on the
// nodes a hypothesis references: a Host whose scope-relative identity
// (address, SSH host key or cloud id) matches one of the reference's id
// properties, or a non-Host node belief record keyed by the reference's
// label and id property. The union is sorted and unique.
func (w *World) causeEdgeTypesForHypothesis(h HypothesisSnapshot) []string {
	seen := map[string]struct{}{}
	add := func(types []string) {
		for _, t := range types {
			seen[t] = struct{}{}
		}
	}
	ids := map[string]struct{}{}
	for _, ref := range h.References {
		for _, v := range ref.IDProperties {
			if v != "" {
				ids[v] = struct{}{}
			}
		}
	}
	if len(ids) == 0 {
		return nil
	}
	for _, host := range w.Snapshot() {
		if host.ScopeID != h.ScopeID {
			continue
		}
		_, byAddr := ids[host.Address]
		_, byKey := ids[host.SSHHostKey]
		_, byCloud := ids[host.CloudID]
		if byAddr || byKey || byCloud {
			add(host.CauseEdgeTypes)
		}
	}
	for _, nb := range w.NodeBeliefSnapshot() {
		if _, ok := ids[nb.Ref.ID]; ok {
			add(nb.CauseEdgeTypes)
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// submitEdgeOutcomes emits one EdgeOutcomeObserved per cause edge type of the
// settled hypothesis. It runs on the engine's caller side, like the
// settlement event it follows, and reads the World under the read lock; the
// events fold on the next tick in submission order, after the settlement.
// A hypothesis the World does not know, or one whose nodes carry no cause
// edge types (every production slice is a single host until the graph wire
// carries edges), emits nothing: there is no cause to credit or blame.
func (e *Engine) submitEdgeOutcomes(hypothesisID string, success bool, missionID, scopeID string) {
	var types []string
	e.mu.RLock()
	for _, h := range e.World.HypothesisSnapshot() {
		if h.HypothesisID == hypothesisID {
			types = e.World.causeEdgeTypesForHypothesis(h)
			break
		}
	}
	e.mu.RUnlock()
	for _, t := range types {
		e.Submit(EdgeOutcomeObserved{EdgeType: t, Success: success, MissionID: missionID, ScopeID: scopeID})
	}
}
