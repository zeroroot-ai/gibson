// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

// An agent forks at run time by originating a child mission that starts from
// its current state (ADR-0169, gibson#803). The fork of the caller sandbox
// becomes the source of the first node of the child, so the harness needs
// that node before the child runs: its id and its projected work, from which
// the network scope of the fork is built the same way the brain builds the
// scope of a dispatched node. setec gives a fork its network at the Fork call
// and a running sandbox cannot change it.

// errNoSingleEntryNode refuses a fork into a child mission that does not
// start at one agent node. A fork continues one sandbox, so it can be the
// source of one node only, and only of a node that runs an agent.
var errNoSingleEntryNode = errors.New("a fork starts a child mission at one agent node")

// entryNodeOf returns the one entry node of a projected mission: the node
// that depends on no other node. It refuses a mission with no entry node or
// with more than one, and an entry node that does not run an agent.
func entryNodeOf(proj brain.MissionProjected) (brain.WorkNode, error) {
	var entry []brain.WorkNode
	for _, n := range proj.Nodes {
		if len(n.DependsOn) == 0 {
			entry = append(entry, n)
		}
	}
	if len(entry) != 1 {
		return brain.WorkNode{}, fmt.Errorf("%w: mission %q has %d entry nodes", errNoSingleEntryNode, proj.ID, len(entry))
	}
	if entry[0].Kind != "agent" {
		return brain.WorkNode{}, fmt.Errorf("%w: the entry node %q of mission %q is a %s node", errNoSingleEntryNode, entry[0].ID, proj.ID, entry[0].Kind)
	}
	return entry[0], nil
}

// childFirstNode returns the first node of the child mission missionID, as
// the run of that mission will project it: the stored definition bound to
// its target, expanded over its target set. The mission record in the store
// does not change.
func (m *missionManager) childFirstNode(ctx context.Context, missionID types.ID) (brain.WorkNode, error) {
	tenant, err := tenantFromCtx(ctx)
	if err != nil {
		return brain.WorkNode{}, err
	}
	store, release, err := m.missionStoreFor(ctx, tenant)
	if err != nil {
		return brain.WorkNode{}, err
	}
	if store == nil {
		return brain.WorkNode{}, errors.New("child mission: the data-plane pool is not up")
	}
	defer release()
	stored, err := store.Get(ctx, missionID)
	if err != nil {
		return brain.WorkNode{}, fmt.Errorf("child mission %s: %w", missionID, err)
	}
	rec := *stored
	def, err := m.bindStoredDefinition(ctx, &rec)
	if err != nil {
		return brain.WorkNode{}, err
	}
	targets, err := m.resolveForEachTargets(ctx, &activeMission{mission: &rec})
	if err != nil {
		return brain.WorkNode{}, fmt.Errorf("child mission %s: %w", missionID, err)
	}
	return firstNodeOfDefinition(def, missionGoal(&rec), targets)
}

// firstNodeOfDefinition projects def over targets and returns its entry node.
func firstNodeOfDefinition(def *missionpb.MissionDefinition, goal string, targets []forEachTarget) (brain.WorkNode, error) {
	proj, _, err := missionDefinitionToProjected(def, goal, targets)
	if err != nil {
		return brain.WorkNode{}, fmt.Errorf("project the child mission: %w", err)
	}
	return entryNodeOf(proj)
}
