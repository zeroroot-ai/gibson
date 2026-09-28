// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"context"
	"fmt"
	"strconv"
)

// belief_world_substrate.go bridges BeliefSubstrate (gibson#272) to the live
// ECS World — the piece gibson#275 needed to make the
// gibson#286/#287/#288/#289 belief-engine machinery consume and mutate REAL
// daemon state instead of only a test double.
//
// Host reads are a direct, live view of Host.Belief/Host.EvidenceDigest
// (already-folded World state, the same fields HostSnapshot exposes); writes
// never touch the World directly — they Submit a BeliefScored event through
// the engine, so Reduce/applyBeliefScored (belief.go, UNCHANGED) remains the
// only thing that ever mutates Host.Belief, and its existing staleness check
// (h.EvidenceDigest != e.EvidenceDigest) applies identically whether the
// score came from the per-host evidence gate or from graph-coupled
// propagation. The two pipelines share one write path into one field; they
// cannot race each other into an inconsistent state.
//
// Claim and TechniqueEnvironment (ADR-0029 §3's market/reputation views —
// P(claim valid), P(technique works here)) are backed by node_belief.go's
// NodeBeliefRecord store (gibson#331's follow-up: "the last prerequisite for
// #333's reputation keying"): reads are a live view of that store, and writes
// Submit a NodeBeliefSet event, the exact same Submit-through-Reduce
// discipline Host uses — no staleness gate, because unlike a Host's
// evidence-scored belief, a Claim/TechniqueEnvironment write has no
// outstanding "request" it could race (see node_belief.go's file doc
// comment). This is what lets harness.PlaceBet's staked confidence, and any
// future reputation aggregate, actually be read back — previously SetBelief
// on either kind returned an error and Belief always reported "not found".

// HostNodeID is the InfraNode.ID / NodeRef.ID a Host's stable brain id maps
// to (ADR-0029's graph and slice types use string ids; Host.ID is a uint64).
// HostsToInfraGraph and WorldBeliefSubstrate both use this exact mapping, so
// a slice-gate write can always find the host it means to.
func HostNodeID(id uint64) string { return strconv.FormatUint(id, 10) }

// ParseHostNodeID reverses HostNodeID.
func ParseHostNodeID(s string) (uint64, error) {
	id, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("belief world substrate: %q is not a host node id: %w", s, err)
	}
	return id, nil
}

// HostsToInfraGraph converts a live host snapshot list into the InfraNode set
// DeriveAttackGraph consumes (gibson#286). It carries no edges: no enablement
// relationship between two Hosts exists in the current evidence model (Host
// has no field referencing another host) — this is an honest reflection of
// today's data, not a limitation of the derivation machinery, which already
// handles edges the moment a future evidence-collection slice produces them.
func HostsToInfraGraph(hosts []HostSnapshot) []InfraNode {
	nodes := make([]InfraNode, 0, len(hosts))
	for _, h := range hosts {
		nodes = append(nodes, InfraNode{ID: HostNodeID(h.ID), Kind: "Host"})
	}
	return nodes
}

// WorldBeliefSubstrate is the BeliefSubstrate backing the live per-tenant
// Engine/World for Host nodes.
type WorldBeliefSubstrate struct {
	eng *Engine
}

// NewWorldBeliefSubstrate returns a substrate reading and writing eng's World.
func NewWorldBeliefSubstrate(eng *Engine) *WorldBeliefSubstrate {
	return &WorldBeliefSubstrate{eng: eng}
}

// Belief returns ref's current belief. For NodeKindHost, an unparseable id is
// a caller error, surfaced as err rather than masked as "not found"; a Host
// id this World has never observed reports ok=false. Every other kind reads
// from the NodeBeliefRecord store (node_belief.go): a ref with no Kind or ID
// is a caller error, and a node that has never been written reports
// ok=false.
func (s *WorldBeliefSubstrate) Belief(_ context.Context, ref NodeRef) (NodeBelief, bool, error) {
	if ref.Kind == NodeKindHost {
		id, err := ParseHostNodeID(ref.ID)
		if err != nil {
			return NodeBelief{}, false, err
		}
		for _, h := range s.eng.Hosts() {
			if h.ID == id {
				return NodeBelief{Belief: h.Belief, EvidenceDigest: h.EvidenceDigest}, true, nil
			}
		}
		return NodeBelief{}, false, nil
	}
	if ref.Kind == "" || ref.ID == "" {
		return NodeBelief{}, false, fmt.Errorf("belief world substrate: ref %+v has no addressable kind/id", ref)
	}
	for _, nb := range s.eng.NodeBeliefs() {
		if nb.Ref == ref {
			return NodeBelief{Belief: nb.Belief, EvidenceDigest: nb.EvidenceDigest}, true, nil
		}
	}
	return NodeBelief{}, false, nil
}

// SetBelief Submits nb as an event through the engine — it never mutates the
// World itself, and the write only takes effect once the engine next Ticks.
// NodeKindHost Submits a BeliefScored event (belief.go's existing reducer,
// unchanged); every other kind Submits a NodeBeliefSet event (node_belief.go)
// against the general-purpose non-Host store. An unparseable Host id, or a
// non-Host ref with no Kind or ID, is a caller error.
func (s *WorldBeliefSubstrate) SetBelief(_ context.Context, ref NodeRef, nb NodeBelief) error {
	if ref.Kind == NodeKindHost {
		id, err := ParseHostNodeID(ref.ID)
		if err != nil {
			return err
		}
		s.eng.Submit(BeliefScored{HostID: id, Belief: nb.Belief, EvidenceDigest: nb.EvidenceDigest})
		return nil
	}
	if ref.Kind == "" || ref.ID == "" {
		return fmt.Errorf("belief world substrate: ref %+v has no addressable kind/id", ref)
	}
	s.eng.Submit(NodeBeliefSet{Ref: ref, Belief: nb.Belief, EvidenceDigest: nb.EvidenceDigest})
	return nil
}

var _ BeliefSubstrate = (*WorldBeliefSubstrate)(nil)
