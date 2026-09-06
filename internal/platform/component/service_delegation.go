// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/capname"
	agentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/agent/v1"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// defaultDelegateTimeout bounds how long DelegateToAgent waits for the target
// agent's result when the delegated task carries no timeout of its own.
// Mirrors CallTool's fallback (service.go) — long enough for a single
// delegated task, short enough that a synchronous caller does not hang
// forever on a dead target.
const defaultDelegateTimeout = 5 * time.Minute

// agentDelegateWorkType is the WorkType a delegated task is enqueued under.
// MUST match internal/engine/harness/implementation.go's
// dispatchWorkAndWait(..., "agent", ..., "agent_execute", ...) call in
// delegateToAgentViaWorkQueue: the target agent is the same physical
// component whichever path dispatched to it, and it parses every "agent"-kind
// work item's payload as a protojson-encoded agentpb.ExecuteRequest regardless
// of who enqueued it.
const agentDelegateWorkType = "agent_execute"

// DelegateToAgent hands a sub-task to another enrolled agent WITHIN the
// caller's current mission and returns its result (gibson#1186 slice C).
//
// This is the lower-trust half of the slice: unlike mission origination
// (capname.MissionOriginate, wired in service_missions.go — gibson#1358),
// delegation reserves no new budget and claims no new target scope. It is peer work dispatch through the exact registry+queue
// CallTool already uses for tools (service.go), targeting kind="agent"
// instead of kind="tool": discover a live instance, enqueue a work item, wait
// for the result. Nothing about a "mission" is created here — the child task
// runs under the calling component's own tenant, and its only recorded
// lineage is the source work_id already carried in the work item context,
// the same shape CallTool already uses.
//
// The target agent receives the SAME wire contract the in-cluster harness's
// delegateToAgentViaWorkQueue already dispatches: WorkType "agent_execute", a
// protojson-encoded agentpb.ExecuteRequest payload, and a protojson-encoded
// agentpb.ExecuteResponse result. An agent that already serves in-cluster
// delegation (gibson#1197) needs no change to also serve this off-cluster
// path — "an agent serving either transport implements one thing"
// (implementation.go's own words for the identical invariant on the tool
// side).
//
// Authorization: gated by capname.MissionDelegate, checked against the
// caller's capability grant (see capability_gate.go) — never a standing FGA
// tuple, per the gibson#1186 slice C owner decision. Checked here, in the
// handler, not at ext-authz: the decision needs the resolved grant row from
// Postgres, which ext-authz never queries, and it must reflect a revocation
// that happened after the caller's CG-JWT was minted.
//
// Known gap, documented rather than silently absent: the in-cluster
// delegation path additionally mints a task-scoped capability-grant JWT so
// the delegated agent's OWN harness callbacks (LLM/tool/finding calls it
// makes while running the task) attribute to the parent mission's budget
// (dispatchWorkAndWait's mintCGForWork). ComponentServiceServer has no CG
// minter wired, so this handler does not do that — the delegated agent runs
// under its own enrollment identity for its own calls; only the delegation
// result flows back to the caller here. Tracked alongside the mission
// origination follow-up, which needs the same minting machinery for a
// different reason (lineage recording).
func (s *ComponentServiceServer) DelegateToAgent(ctx context.Context, req *componentpb.DelegateToAgentRequest) (*componentpb.DelegateToAgentResponse, error) {
	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "tenant not found in context")
	}

	if req.GetAgentName() == "" {
		return nil, status.Error(codes.InvalidArgument, "agent_name is required")
	}
	if len(req.GetTaskJson()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "task_json is required")
	}

	// The grant id is the origination path's business (gibson#1358 lineage);
	// delegation creates no mission to attribute, so it only needs the
	// allow/deny half of the same single lookup.
	if _, err := s.requireCapability(ctx, tenant, capname.MissionDelegate); err != nil {
		return nil, err
	}

	var task agent.Task
	if err := json.Unmarshal(req.GetTaskJson(), &task); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid task_json: %v", err)
	}
	if task.ID == "" {
		task.ID = types.NewID()
	}

	// Discover the target agent: tenant-scoped first, then the _system
	// fallback (handled by Discover) — identical resolution CallTool uses.
	instances, err := s.registry.Discover(ctx, tenant, "agent", req.GetAgentName())
	if err != nil {
		s.logger.ErrorContext(ctx, "delegate to agent: discovery failed",
			slog.String("tenant", tenant),
			slog.String("agent_name", req.GetAgentName()),
			slog.String("error", err.Error()),
		)
		return nil, status.Errorf(codes.Internal, "agent discovery failed: %v", err)
	}
	if len(instances) == 0 {
		return nil, status.Errorf(codes.NotFound, "agent %q not available for tenant %q", req.GetAgentName(), tenant)
	}

	execReq := &agentpb.ExecuteRequest{
		Task:      agent.TaskToProto(task),
		TimeoutMs: task.Timeout.Milliseconds(),
	}
	payload, marshalErr := protojson.Marshal(execReq)
	if marshalErr != nil {
		return nil, status.Errorf(codes.Internal, "failed to marshal delegated task: %v", marshalErr)
	}

	// Best-effort lineage: resolve the caller's own mission (from its own
	// work_id) so the delegated work item's context carries it, mirroring
	// dispatchWorkAndWait's workCtx["mission_id"]. A resolver miss or nil
	// resolver never blocks dispatch — CallTool's work item context has the
	// same "best-effort" shape for source_work_id.
	workCtx := map[string]string{
		"source_work_id": req.GetWorkId(),
		"caller_tenant":  tenant,
	}
	if s.missionCtx != nil && req.GetWorkId() != "" {
		if missionID, _, resolveErr := s.missionCtx.ResolveMissionForWork(ctx, req.GetWorkId(), tenant); resolveErr == nil && missionID != "" {
			workCtx["mission_id"] = missionID
		}
	}

	workID := uuid.New().String()
	workItem := WorkItem{
		WorkID:   workID,
		WorkType: agentDelegateWorkType,
		Payload:  payload,
		Context:  workCtx,
	}

	if _, enqueueErr := s.queue.Enqueue(ctx, tenant, "agent", req.GetAgentName(), workItem); enqueueErr != nil {
		s.logger.ErrorContext(ctx, "delegate to agent: enqueue failed",
			slog.String("tenant", tenant),
			slog.String("agent_name", req.GetAgentName()),
			slog.String("error", enqueueErr.Error()),
		)
		return nil, status.Errorf(codes.Internal, "failed to enqueue agent delegation: %v", enqueueErr)
	}

	timeout := task.Timeout
	if timeout <= 0 {
		timeout = defaultDelegateTimeout
	}

	s.logger.DebugContext(ctx, "delegate to agent: waiting for result",
		slog.String("tenant", tenant),
		slog.String("agent_name", req.GetAgentName()),
		slog.String("work_id", workID),
		slog.Duration("timeout", timeout),
	)

	result, waitErr := s.queue.WaitForResult(ctx, workID, timeout)
	if waitErr != nil {
		s.logger.ErrorContext(ctx, "delegate to agent: wait for result failed",
			slog.String("tenant", tenant),
			slog.String("agent_name", req.GetAgentName()),
			slog.String("work_id", workID),
			slog.String("error", waitErr.Error()),
		)
		return nil, status.Errorf(codes.DeadlineExceeded, "agent delegation timed out or failed: %v", waitErr)
	}

	agentResult := agent.NewResult(task.ID)
	switch {
	case result.Error != nil:
		// The target reported a queue-level failure via SubmitResult's error
		// path (e.g. it could not parse or start the task). There is no
		// dedicated error field on DelegateToAgentResponse — the proto
		// carries only result_json — so this folds into agent.Result.Error,
		// the same place a business-level execution failure lands below. The
		// RPC itself still succeeds: the caller's own agent.Result.Status
		// tells it the delegation failed, exactly as CallTool's
		// ComponentError does for tool failures.
		agentResult.Fail(fmt.Errorf("[%s] %s", result.Error.Code, result.Error.Message))
	default:
		execResp := &agentpb.ExecuteResponse{}
		if unmarshalErr := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(result.Result, execResp); unmarshalErr != nil {
			return nil, status.Errorf(codes.Internal, "failed to decode agent result: %v", unmarshalErr)
		}
		if e := execResp.GetError(); e != nil && (e.GetMessage() != "" || e.GetCode() != "") {
			agentResult.Fail(fmt.Errorf("[%s] %s", e.GetCode(), e.GetMessage()))
		} else {
			agentResult = agent.ProtoToResult(execResp.GetResult())
			agentResult.TaskID = task.ID
		}
	}

	resultJSON, marshalRespErr := json.Marshal(agentResult)
	if marshalRespErr != nil {
		return nil, status.Errorf(codes.Internal, "failed to encode delegation result: %v", marshalRespErr)
	}

	s.logger.InfoContext(ctx, "delegate to agent: result received",
		slog.String("tenant", tenant),
		slog.String("agent_name", req.GetAgentName()),
		slog.String("work_id", workID),
		slog.String("status", string(agentResult.Status)),
	)

	return &componentpb.DelegateToAgentResponse{ResultJson: resultJSON}, nil
}
