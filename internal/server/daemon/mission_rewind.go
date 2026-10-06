// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/mission"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

// mission_rewind.go is the daemon half of a rewind (ADR-0170, gibson#804).
//
// A checkpoint is the end of a node in a mission run. The tenant World holds
// each end already: the work item of the node is done or failed, and the
// Timeline holds the WorkCompleted event that ended it. Nothing else stores a
// checkpoint.
//
// A rewind starts a NEW mission at the node of a checkpoint. The new mission
// runs that node and every node after it. The earlier run stays in the World
// as it was, and its knowledge stays there for the new run to read. The new
// mission records the earlier run and the checkpoint as its parent, as a
// Timeline event (brain.MissionRewound).
//
// This is the state mode. A sandbox snapshot at the end of a node (the
// sandbox mode) waits for gibson#802. Until then no checkpoint has a
// snapshot, and the node of a rewind starts in a fresh sandbox with the files
// of the workspace, as the ADR states for a checkpoint without a snapshot.

// rewindNamespace scopes the deterministic ids of rewound missions.
var rewindNamespace = uuid.MustParse("7d3b0c64-2a8e-4f0e-9a4f-5f2d8f0a1c70")

// missionCheckpoints returns the node ends of one mission, in the order the
// nodes ended. eng is the engine of the caller's tenant, so a mission of
// another tenant has no work items here and returns nothing.
func missionCheckpoints(eng *brain.Engine, missionID string) []api.MissionCheckpoint {
	prefix := missionID + "/"
	var ended []brain.WorkSnapshot
	for _, w := range eng.Work() {
		if w.MissionID != missionID || !strings.HasPrefix(w.ID, prefix) {
			continue
		}
		if w.State == brain.WorkDone || w.State == brain.WorkFailed {
			ended = append(ended, w)
		}
	}
	if len(ended) == 0 {
		return nil
	}
	sort.SliceStable(ended, func(i, j int) bool { return ended[i].CompletedSeq < ended[j].CompletedSeq })

	// The position is that of the last WorkCompleted of the item in the
	// mission slice, plus one: the frame at that position holds the end. A
	// retried node completes more than once, and its last completion is the
	// end of the node.
	position := make(map[string]uint64, len(ended))
	for i, ev := range eng.MissionEvents(missionID) {
		if c, ok := ev.(brain.WorkCompleted); ok {
			position[c.ID] = uint64(i) + 1
		}
	}

	out := make([]api.MissionCheckpoint, 0, len(ended))
	for _, w := range ended {
		node := strings.TrimPrefix(w.ID, prefix)
		out = append(out, api.MissionCheckpoint{
			CheckpointID:     node,
			NodeID:           node,
			TimelinePosition: position[w.ID],
		})
	}
	return out
}

// rewoundMissionID returns the id of the mission that a rewind starts. With an
// idempotency key the id is derived from the request, so a retry of the same
// request names the same mission and starts no second run. Without a key each
// rewind gets a new id.
func rewoundMissionID(tenant, parentID, checkpointID, key string) types.ID {
	if key == "" {
		return types.NewID()
	}
	name := strings.Join([]string{tenant, parentID, checkpointID, key}, "\x00")
	return types.ID(uuid.NewSHA1(rewindNamespace, []byte(name)).String())
}

// rewindDefinition returns the definition of the new run: the node of the
// checkpoint and each node after it. A link to a node that the new run does
// not hold is removed, because that node ended in the earlier run.
//
// The constraints, the targets and the scope of the definition stay as they
// are, so the new run gets the budget that the definition gives (ADR-0170).
//
// instruction, when not nil, replaces the goal of the task of the start node.
// The start node must be an agent node for that.
func rewindDefinition(def *missionpb.MissionDefinition, startNode string, instruction *string) (*missionpb.MissionDefinition, error) {
	if _, ok := def.GetNodes()[startNode]; !ok {
		return nil, status.Errorf(codes.FailedPrecondition,
			"checkpoint %q is inside a for_each or a parallel group; rewind to the group node instead", startNode)
	}
	keep := downstreamOf(def, startNode)

	out, ok := cloneDefinition(def)
	if !ok {
		return nil, status.Error(codes.Internal, "copy the mission definition")
	}
	for id := range out.GetNodes() {
		if !keep[id] {
			delete(out.Nodes, id)
		}
	}
	for id, n := range out.GetNodes() {
		n.Dependencies = filterKept(n.GetDependencies(), keep)
		if jc := n.GetJoinConfig(); jc != nil {
			jc.WaitFor = filterKept(jc.GetWaitFor(), keep)
			if len(jc.WaitFor) == 0 {
				return nil, status.Errorf(codes.FailedPrecondition,
					"join node %q waits only for nodes before the checkpoint; rewind to a node it waits for", id)
			}
		}
		if cc := n.GetConditionConfig(); cc != nil {
			cc.TrueBranch = filterKept(cc.GetTrueBranch(), keep)
			cc.FalseBranch = filterKept(cc.GetFalseBranch(), keep)
		}
	}
	edges := out.GetEdges()[:0]
	for _, e := range out.GetEdges() {
		if keep[e.GetFrom()] && keep[e.GetTo()] {
			edges = append(edges, e)
		}
	}
	out.Edges = edges
	out.EntryPoints = []string{startNode}
	out.ExitPoints = filterKept(out.GetExitPoints(), keep)

	if instruction != nil {
		agent := out.GetNodes()[startNode].GetAgentConfig()
		if agent == nil {
			return nil, status.Errorf(codes.InvalidArgument,
				"node %q is not an agent node, so it has no instruction to change", startNode)
		}
		if agent.Task == nil {
			return nil, status.Errorf(codes.InvalidArgument, "agent node %q has no task to change", startNode)
		}
		agent.Task.Goal = *instruction
	}
	return out, nil
}

// downstreamOf returns the start node and each node that runs after it: the
// nodes that depend on it, through a dependency, an edge, a join or a branch
// of a condition, and so on.
func downstreamOf(def *missionpb.MissionDefinition, start string) map[string]bool {
	next := make(map[string][]string)
	for id, n := range def.GetNodes() {
		for _, d := range n.GetDependencies() {
			next[d] = append(next[d], id)
		}
		for _, w := range n.GetJoinConfig().GetWaitFor() {
			next[w] = append(next[w], id)
		}
		next[id] = append(next[id], n.GetConditionConfig().GetTrueBranch()...)
		next[id] = append(next[id], n.GetConditionConfig().GetFalseBranch()...)
	}
	for _, e := range def.GetEdges() {
		next[e.GetFrom()] = append(next[e.GetFrom()], e.GetTo())
	}
	keep := map[string]bool{start: true}
	queue := []string{start}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		for _, n := range next[id] {
			if _, ok := def.GetNodes()[n]; ok && !keep[n] {
				keep[n] = true
				queue = append(queue, n)
			}
		}
	}
	return keep
}

func filterKept(ids []string, keep map[string]bool) []string {
	var out []string
	for _, id := range ids {
		if keep[id] {
			out = append(out, id)
		}
	}
	return out
}

// cloneDefinition copies a definition through its canonical JSON, the same
// form the mission record stores.
func cloneDefinition(def *missionpb.MissionDefinition) (*missionpb.MissionDefinition, bool) {
	b, err := mission.MarshalDefinitionJSON(def)
	if err != nil {
		return nil, false
	}
	out, err := mission.UnmarshalDefinitionJSON(b)
	if err != nil {
		return nil, false
	}
	return out, true
}

// rewindStore is the part of the mission store that a rewind uses.
type rewindStore interface {
	Get(ctx context.Context, id types.ID) (*mission.Mission, error)
	Save(ctx context.Context, m *mission.Mission) error
}

// missionRewinder creates the mission of a rewind and starts it. Its parts
// are fields so that a test can drive it without Redis.
type missionRewinder struct {
	tenant string
	eng    *brain.Engine
	store  rewindStore
	start  func(ctx context.Context, missionID string) (string, error)
}

// rewind validates the request, saves the new mission, records its parent on
// the Timeline and starts it.
func (r missionRewinder) rewind(ctx context.Context, req api.RewindRequest) (string, error) {
	parentID, err := types.ParseID(req.MissionID)
	if err != nil {
		return "", status.Errorf(codes.InvalidArgument, "mission_id %q is not a mission id", req.MissionID)
	}
	if !hasCheckpoint(missionCheckpoints(r.eng, req.MissionID), req.CheckpointID) {
		return "", status.Errorf(codes.NotFound,
			"checkpoint %q not found for mission %s", req.CheckpointID, req.MissionID)
	}

	newID := rewoundMissionID(r.tenant, req.MissionID, req.CheckpointID, req.IdempotencyKey)
	if req.IdempotencyKey != "" {
		existing, getErr := r.store.Get(ctx, newID)
		switch {
		case getErr == nil && existing != nil:
			return newID.String(), nil
		case getErr != nil && !mission.IsNotFoundError(getErr):
			return "", fmt.Errorf("rewind: look up mission %s: %w", newID, getErr)
		}
	}

	parent, err := r.store.Get(ctx, parentID)
	if err != nil {
		if mission.IsNotFoundError(err) {
			return "", status.Errorf(codes.NotFound, "mission %s not found", req.MissionID)
		}
		return "", fmt.Errorf("rewind: get mission %s: %w", req.MissionID, err)
	}
	if parent.MissionDefinitionJSON == "" {
		return "", status.Errorf(codes.FailedPrecondition, "mission %s has no definition", req.MissionID)
	}
	def, err := mission.UnmarshalDefinitionJSON([]byte(parent.MissionDefinitionJSON))
	if err != nil {
		return "", fmt.Errorf("rewind: parse definition of mission %s: %w", req.MissionID, err)
	}
	newDef, err := rewindDefinition(def, req.CheckpointID, req.Instruction)
	if err != nil {
		return "", err
	}
	child, err := rewoundMission(parent, newID, newDef)
	if err != nil {
		return "", err
	}
	if err := r.store.Save(ctx, child); err != nil {
		return "", fmt.Errorf("rewind: save mission %s: %w", newID, err)
	}

	// The parent goes on the Timeline before the new mission starts, so the
	// slice of the new mission opens with where it came from.
	r.eng.Submit(brain.MissionRewound{
		MissionID:          newID.String(),
		ParentMissionID:    req.MissionID,
		ParentCheckpointID: req.CheckpointID,
	})
	return r.start(ctx, newID.String())
}

func hasCheckpoint(cps []api.MissionCheckpoint, id string) bool {
	for _, cp := range cps {
		if cp.CheckpointID == id {
			return true
		}
	}
	return false
}

// rewoundMission builds the record of the new mission from its parent. It
// keeps the name, the targets, the constraints and the creator of the parent,
// and it holds the definition of the nodes that are left.
func rewoundMission(parent *mission.Mission, id types.ID, def *missionpb.MissionDefinition) (*mission.Mission, error) {
	defJSON, err := mission.MarshalDefinitionJSON(def)
	if err != nil {
		return nil, fmt.Errorf("rewind: serialize definition: %w", err)
	}
	now := mission.NewUnixTimeNow()
	meta := make(map[string]any, len(parent.Metadata))
	for k, v := range parent.Metadata {
		meta[k] = v
	}
	return &mission.Mission{
		ID:                    id,
		TenantID:              parent.TenantID,
		Name:                  parent.Name,
		Description:           parent.Description,
		Status:                mission.MissionStatusPending,
		TargetID:              parent.TargetID,
		AdditionalTargetIDs:   append([]types.ID(nil), parent.AdditionalTargetIDs...),
		MissionDefinitionID:   parent.MissionDefinitionID,
		MissionDefinitionJSON: string(defJSON),
		Constraints:           parent.Constraints,
		Metrics:               &mission.MissionMetrics{TotalNodes: len(def.GetNodes())},
		Metadata:              meta,
		MemoryContinuity:      parent.MemoryContinuity,
		Depth:                 parent.Depth,
		CreatedBy:             parent.CreatedBy,
		CreatedAt:             now,
		UpdatedAt:             now,
	}, nil
}

// Checkpoints returns the node ends of a mission of the caller's tenant.
func (m *missionManager) Checkpoints(ctx context.Context, missionID string) ([]api.MissionCheckpoint, error) {
	tenant, err := tenantFromCtx(ctx)
	if err != nil {
		return nil, err
	}
	if missionID == "" {
		return nil, status.Error(codes.InvalidArgument, "mission_id is required")
	}
	eng := m.brainRegistry.For(tenant.String())
	if engErr := eng.Err(); engErr != nil {
		return nil, status.Errorf(codes.Unavailable, "the World of the tenant is stopped: %v", engErr)
	}
	cps := missionCheckpoints(eng, missionID)
	if cps == nil {
		cps = []api.MissionCheckpoint{}
	}
	return cps, nil
}

// Rewind starts a new mission at a checkpoint of an earlier run of the
// caller's tenant and returns the id of the new mission.
func (m *missionManager) Rewind(ctx context.Context, req api.RewindRequest) (string, error) {
	tenant, err := tenantFromCtx(ctx)
	if err != nil {
		return "", err
	}
	if req.MissionID == "" || req.CheckpointID == "" {
		return "", status.Error(codes.InvalidArgument, "mission_id and checkpoint_id are required")
	}
	eng := m.brainRegistry.For(tenant.String())
	if engErr := eng.Err(); engErr != nil {
		return "", status.Errorf(codes.Unavailable, "the World of the tenant is stopped: %v", engErr)
	}
	store, release, err := m.missionStoreFor(ctx, tenant)
	if err != nil {
		return "", fmt.Errorf("rewind: acquire mission store: %w", err)
	}
	defer release()
	if store == nil {
		return "", status.Error(codes.Unavailable, "mission store not initialized (pool not configured)")
	}
	return missionRewinder{
		tenant: tenant.String(),
		eng:    eng,
		store:  store,
		start:  m.RunExisting,
	}.rewind(ctx, req)
}
