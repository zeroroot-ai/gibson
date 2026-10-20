// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
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

// WorkTypeAgentExecute is the work type of an agent dispatch on the component
// work queue (ADR-0111). It is the one definition. The harness uses it for a
// mission node, and this service uses it for a delegated task. The target
// agent is the same component on each path, and it reads the payload of each
// item of this type as a protojson `agentpb.ExecuteRequest`.
const WorkTypeAgentExecute = "agent_execute"

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
// delegateToAgentViaWorkQueue already dispatches: WorkTypeAgentExecute, a
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

	// Bind the delegated work item to the mission of the caller, then take its
	// run. The work id comes from the caller, so a caller that names the work
	// item of another mission gets no run. The run goes in the request, so the
	// agent sends it on every callback (gibson#1235). The agent run of the
	// request stays empty: it is the caller's agent run, and a delegation
	// starts a new one.
	sourceMission, sourceRun, bindErr := s.bindSourceWork(ctx, tenant, req.GetWorkId())
	if bindErr != nil {
		return nil, bindErr
	}
	execReq := &agentpb.ExecuteRequest{
		Task:         agent.TaskToProto(task),
		TimeoutMs:    task.Timeout.Milliseconds(),
		MissionRunId: sourceRun,
	}
	payload, marshalErr := protojson.Marshal(execReq)
	if marshalErr != nil {
		return nil, status.Errorf(codes.Internal, "failed to marshal delegated task: %v", marshalErr)
	}

	workCtx := map[string]string{
		"source_work_id": req.GetWorkId(),
		"caller_tenant":  tenant,
	}
	if sourceMission != "" {
		workCtx["mission_id"] = sourceMission
	}
	// The delegated agent acts for the mission run of its caller, so its own
	// Authorize resolves to that run (D86). Without it every Authorize of a
	// delegated agent is refused.
	for k, v := range authzContextEntry(sourceRun) {
		workCtx[k] = v
	}

	workID := uuid.New().String()
	workItem := WorkItem{
		WorkID:   workID,
		WorkType: WorkTypeAgentExecute,
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

// bindSourceWork binds the work item that the caller names to the mission of
// the caller. It returns the mission and the mission run of that work item.
//
// The work id arrives from the caller and only the tenant is checked against
// its owner, so a same-tenant agent could name the work item of another
// mission. The task grant that the caller presents, verified by the daemon,
// names its mission and its run. A work item of another mission, or of another
// run, is refused. A delegation that names a work item without a verified task
// grant is refused. A delegation with no work item is not bound.
func (s *ComponentServiceServer) bindSourceWork(ctx context.Context, tenant, sourceWorkID string) (mission, run string, err error) {
	if sourceWorkID == "" {
		return "", "", nil
	}
	grantMission, grantRun, err := s.callerTaskGrant(ctx, tenant)
	if err != nil {
		return "", "", err
	}
	if s.missionCtx != nil {
		var resolveErr error
		mission, resolveErr = s.missionCtx.ResolveMissionForWork(ctx, sourceWorkID, tenant)
		if resolveErr != nil {
			s.logger.WarnContext(ctx, "delegate to agent: mission of the work item not resolved",
				"work_id", sourceWorkID, "error", resolveErr)
		}
	}
	if mission != "" && grantMission != mission {
		return "", "", status.Error(codes.PermissionDenied, "the work item belongs to another mission")
	}
	run = s.sourceWorkRun(ctx, tenant, sourceWorkID)
	if run != "" && grantRun != "" && grantRun != run {
		return "", "", status.Error(codes.PermissionDenied, "the work item belongs to another run")
	}
	if mission == "" {
		// The work item names no mission, so nothing binds its run to the grant.
		run = ""
	}
	return mission, run, nil
}

// sourceWorkRun returns the mission run of the work item that the caller names
// as its own, when the owner recorded at enqueue is the caller tenant. It
// returns an empty string when the work item is not the caller's or has no run.
func (s *ComponentServiceServer) sourceWorkRun(ctx context.Context, tenant, sourceWorkID string) string {
	// resolveWorkOwner refuses when no work-context registry is wired.
	if _, err := s.resolveWorkOwner(ctx, tenant, sourceWorkID); err != nil {
		return ""
	}
	runID, err := s.workContext.WorkRun(ctx, sourceWorkID)
	if err != nil {
		if !errors.Is(err, ErrWorkRunUnknown) {
			s.logger.WarnContext(ctx, "delegate to agent: cannot read the run of the source work item",
				slog.String("work_id", sourceWorkID), slog.String("error", err.Error()))
		}
		return ""
	}
	return runID
}

// authzContextEntry is the work item context entry for a run. When the caller
// has no run, the entry is absent and the delegated agent has no run, so its
// Authorize is refused (fail closed). Delegation itself is not blocked.
func authzContextEntry(runID string) map[string]string {
	if runID == "" {
		return nil
	}
	ac, err := json.Marshal(map[string]any{"run_id": runID, "issued_at": time.Now().Unix(), "ttl_seconds": authz.DefaultWorkTTLSeconds})
	if err != nil {
		return nil
	}
	return map[string]string{authz.AuthzContextWorkKey: string(ac)}
}
