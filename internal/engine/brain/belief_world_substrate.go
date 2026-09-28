// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"context"
	"fmt"
	"strconv"
)

// belief_world_substrate.go bridges BeliefSubstrate (gibson#272) to the live
// ECS World for Host nodes — the piece gibson#275 needed to make the
// gibson#286/#287/#288/#289 belief-engine machinery consume and mutate REAL
// daemon state instead of only a test double. Reads are a direct, live view
// of Host.Belief/Host.EvidenceDigest (already-folded World state, the same
// fields HostSnapshot exposes); writes never touch the World directly — they
// Submit a BeliefScored event through the engine, so Reduce/applyBeliefScored
// (belief.go, UNCHANGED) remains the only thing that ever mutates Host.Belief,
// and its existing staleness check (h.EvidenceDigest != e.EvidenceDigest)
// applies identically whether the score came from the per-host evidence gate
// or from graph-coupled propagation. The two pipelines share one write path
// into one field; they cannot race each other into an inconsistent state.
//
// Claim and TechniqueEnvironment (ADR-0029 §3's market/reputation views) are
// not ECS entities yet, so this substrate has nothing to read or write for
// them — Belief/SetBelief report "not found" / an error respectively. A
// substrate for those views is separate, later work.

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

// Belief returns ref's current belief. Only NodeKindHost is backed; any other
// kind, or a Host id this World has never observed, reports ok=false.
func (s *WorldBeliefSubstrate) Belief(_ context.Context, ref NodeRef) (NodeBelief, bool, error) {
	if ref.Kind != NodeKindHost {
		return NodeBelief{}, false, nil
	}
	id, err := ParseHostNodeID(ref.ID)
	if err != nil {
		return NodeBelief{}, false, nil
	}
	for _, h := range s.eng.Hosts() {
		if h.ID == id {
			return NodeBelief{Belief: h.Belief, EvidenceDigest: h.EvidenceDigest}, true, nil
		}
	}
	return NodeBelief{}, false, nil
}

// SetBelief Submits nb as a BeliefScored event for ref's host (belief.go's
// existing reducer, unchanged) — it does not mutate the World itself, and the
// write only takes effect once the engine next Ticks. Rejects any non-Host
// kind and any id that does not parse as a host node id; both are caller
// errors, not "not found".
func (s *WorldBeliefSubstrate) SetBelief(_ context.Context, ref NodeRef, nb NodeBelief) error {
	if ref.Kind != NodeKindHost {
		return fmt.Errorf("belief world substrate: node kind %q is not backed by the ECS World yet", ref.Kind)
	}
	id, err := ParseHostNodeID(ref.ID)
	if err != nil {
		return err
	}
	s.eng.Submit(BeliefScored{HostID: id, Belief: nb.Belief, EvidenceDigest: nb.EvidenceDigest})
	return nil
}

var _ BeliefSubstrate = (*WorldBeliefSubstrate)(nil)
