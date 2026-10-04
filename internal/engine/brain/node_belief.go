// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"sort"

	"github.com/mlange-42/ark/ecs"
)

// node_belief.go backs BeliefSubstrate (belief_substrate.go, gibson#272) for
// every node kind that is NOT its own ECS entity: NodeKindClaim (the market
// view, ADR-0022/ADR-0029 §3 — P(claim valid)) and NodeKindTechniqueEnvironment
// (the reputation view, ADR-0029 §3 — P(technique works here)), and any
// further kind the ontology declares (belief_substrate.go's own doc comment:
// "this list is not meant to stay closed").
//
// Host stays exactly as it was (belief.go, UNCHANGED): a Host's belief lives
// on the Host component itself, scored by BeliefSystem/BeliefWorker's
// evidence-digest-gated request/response cycle, because a Host's belief is
// derived FROM its own evidence and can go stale while an async score is in
// flight (applyBeliefScored's staleness check exists for exactly that race).
//
// A Claim or TechniqueEnvironment write has no such race: it is the direct,
// synchronous result of the caller's own action (harness.PlaceBet staking a
// claim, a settlement recording an outcome, a future reputation aggregator
// recomputing a technique's track record) — there is no separate "request"
// phase it could go stale against. So this store is deliberately simpler than
// Host's: NodeBeliefSet always overwrites in full (BeliefSubstrate.SetBelief's
// own documented contract — "never blended or averaged across writes"), and
// the CALLER is responsible for its own staleness check before writing, the
// same as SetBelief's doc comment already requires.
//
// Same single-writer discipline as everywhere else in this package: NodeBeliefSet
// folds through the normal Reduce path (ADR-0001), so replay reproduces it
// exactly and WorldBeliefSubstrate.SetBelief (belief_world_substrate.go) never
// mutates the World directly — it only Submits.

// NodeBeliefRecord is the folded belief for one non-Host node, keyed by its
// NodeRef (Kind, ID) — two refs of different Kind never collide even with an
// equal ID string, matching NodeRef's own documented identity contract.
type NodeBeliefRecord struct {
	Ref            NodeRef
	Belief         Belief
	EvidenceDigest string
	CauseEdgeTypes []string
}

// NodeBeliefSet records a belief write for a non-Host node. Kind identifies
// the Timeline event; Ref addresses the node.
type NodeBeliefSet struct {
	Ref            NodeRef
	Belief         Belief
	EvidenceDigest string
	// CauseEdgeTypes mirrors NodeBelief.CauseEdgeTypes (gibson#613).
	CauseEdgeTypes []string
}

// Kind identifies the node_belief.set brain event.
func (NodeBeliefSet) Kind() string { return "node_belief.set" }

// findNodeBeliefRecord returns ref's current record entity, if one exists.
func findNodeBeliefRecord(w *World, ref NodeRef) (ecs.Entity, bool) {
	q := ecs.NewFilter1[NodeBeliefRecord](w.ecs).Query()
	for q.Next() {
		if q.Get().Ref == ref {
			e := q.Entity()
			q.Close()
			return e, true
		}
	}
	return ecs.Entity{}, false
}

// applyNodeBeliefSet folds a NodeBeliefSet event into the World. A ref with
// no Kind or no ID records nothing — there would be no addressable node.
// Otherwise the record is created on first write and overwritten in full on
// every subsequent one (never blended), mirroring
// BeliefSubstrate.SetBelief's documented contract exactly.
func applyNodeBeliefSet(w *World, e NodeBeliefSet) {
	if e.Ref.Kind == "" || e.Ref.ID == "" {
		return
	}
	ent, ok := findNodeBeliefRecord(w, e.Ref)
	if !ok {
		ent = w.nodeBeliefs.NewEntity(&NodeBeliefRecord{Ref: e.Ref})
	}
	rec := w.nodeBeliefs.Get(ent)
	rec.Belief = e.Belief
	rec.EvidenceDigest = e.EvidenceDigest
	rec.CauseEdgeTypes = append([]string(nil), e.CauseEdgeTypes...)
}

// NodeBeliefSnapshot is a stable, comparable view of a NodeBeliefRecord.
type NodeBeliefSnapshot struct {
	Ref            NodeRef
	Belief         Belief
	EvidenceDigest string
	CauseEdgeTypes []string
}

// NodeBeliefSnapshot returns every recorded non-Host node belief in
// deterministic (Kind, then ID) order.
func (w *World) NodeBeliefSnapshot() []NodeBeliefSnapshot {
	var out []NodeBeliefSnapshot
	q := ecs.NewFilter1[NodeBeliefRecord](w.ecs).Query()
	for q.Next() {
		r := q.Get()
		out = append(out, NodeBeliefSnapshot{Ref: r.Ref, Belief: r.Belief, EvidenceDigest: r.EvidenceDigest, CauseEdgeTypes: append([]string(nil), r.CauseEdgeTypes...)})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Ref.Kind != out[j].Ref.Kind {
			return out[i].Ref.Kind < out[j].Ref.Kind
		}
		return out[i].Ref.ID < out[j].Ref.ID
	})
	return out
}

// NodeBeliefs returns the current non-Host node beliefs (read-locked, safe to
// call concurrently with the tick loop — the same read-accessor contract
// every other Engine method offers, e.g. BetSettlements()).
func (e *Engine) NodeBeliefs() []NodeBeliefSnapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.World.NodeBeliefSnapshot()
}
