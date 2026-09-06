// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// rewind.go — relocated from internal/orchestrator (retired, gibson#851).
//
// Implements the orchestrator-side rewind dispatcher that the daemon's
// Mission.Resume(target_checkpoint_id) flow drives into. Spec 4 R16.4 +
// R6 runtime — for each in-flight tool at checkpoint time, the
// dispatcher reads the tool's declared idempotency mode and applies
// one of: cancel-and-mark-failed (AT_MOST_ONCE), re-execute on resume
// (AT_LEAST_ONCE), or resume-with-token (EXACTLY_ONCE).
//
// The dispatcher is a thin coordinator: it does NOT load checkpoint
// payloads itself (that's the daemon's `GetMissionCheckpointPayload`
// path). It receives the in-flight summary and the resolved
// idempotency mode, decides the action, and emits the per-tool
// `mission.rewind.tool_cancelled` audit hint via its emitter callback.
//
// Spec: mission-checkpointing R6.3-R6.6, R16.4.
package api

import (
	"context"
	"fmt"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	manifestpb "github.com/zeroroot-ai/sdk/api/gen/gibson/manifest/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// IdempotencyAction is the runtime decision returned by the dispatcher
// per in-flight tool at rewind / resume time.
type IdempotencyAction int

const (
	// IdempotencyActionUnspecified is the zero value; should never be
	// returned in practice.
	IdempotencyActionUnspecified IdempotencyAction = iota

	// IdempotencyActionSkipFailed marks the in-flight node failed and
	// does NOT re-execute. Returned for AT_MOST_ONCE tools.
	IdempotencyActionSkipFailed

	// IdempotencyActionRetry re-executes the node from scratch.
	// Returned for AT_LEAST_ONCE and unspecified-defaults-to-AT_LEAST_ONCE.
	IdempotencyActionRetry

	// IdempotencyActionResumeWithToken passes the captured resumption
	// token to the tool's resume API. Returned for EXACTLY_ONCE when a
	// resumption_token is present.
	IdempotencyActionResumeWithToken

	// IdempotencyActionFailMission terminates the mission with a
	// canonical error. Returned for EXACTLY_ONCE without a resumption
	// token.
	IdempotencyActionFailMission
)

// String returns the canonical string form for audit / log emission.
func (a IdempotencyAction) String() string {
	switch a {
	case IdempotencyActionSkipFailed:
		return "skip_failed"
	case IdempotencyActionRetry:
		return "retry"
	case IdempotencyActionResumeWithToken:
		return "resume_with_token"
	case IdempotencyActionFailMission:
		return "fail_mission"
	}
	return "unspecified"
}

// InFlightTool describes a single tool whose call was in flight when
// the target checkpoint was captured. Driven from the daemon's
// `CheckpointData.InFlight*` fields.
type InFlightTool struct {
	// NodeID identifies the mission node whose tool was in flight.
	NodeID string

	// ResumptionToken is the EXACTLY_ONCE handshake token captured at
	// the tool's last side-effecting step. Empty for AT_MOST_ONCE /
	// AT_LEAST_ONCE.
	ResumptionToken string

	// Idempotency is the mode declared by the tool's manifest. May be
	// UNSPECIFIED — the dispatcher treats UNSPECIFIED as
	// AT_LEAST_ONCE (R6.6).
	Idempotency manifestpb.ToolIdempotency
}

// DispatchInFlightTool computes the runtime action for a single
// in-flight tool, applying the idempotency contract. Pure function —
// no state mutation, no I/O. Spec: R6.3-R6.6.
func DispatchInFlightTool(t InFlightTool) IdempotencyAction {
	mode := t.Idempotency
	// UNSPECIFIED defaults to AT_LEAST_ONCE per R6.6.
	if mode == manifestpb.ToolIdempotency_TOOL_IDEMPOTENCY_UNSPECIFIED {
		mode = manifestpb.ToolIdempotency_TOOL_IDEMPOTENCY_AT_LEAST_ONCE
	}
	switch mode {
	case manifestpb.ToolIdempotency_TOOL_IDEMPOTENCY_AT_MOST_ONCE:
		return IdempotencyActionSkipFailed
	case manifestpb.ToolIdempotency_TOOL_IDEMPOTENCY_AT_LEAST_ONCE:
		return IdempotencyActionRetry
	case manifestpb.ToolIdempotency_TOOL_IDEMPOTENCY_EXACTLY_ONCE:
		if t.ResumptionToken != "" {
			return IdempotencyActionResumeWithToken
		}
		return IdempotencyActionFailMission
	}
	// Unreachable in practice; default to retry as the safest correctness fallback.
	return IdempotencyActionRetry
}

// RewindEmitter is the audit-hint sink invoked once per in-flight
// tool dispatch decision. The daemon's `RewindMission` audit emitter
// implements this. May be nil; when nil, dispatch decisions are
// applied silently.
type RewindEmitter interface {
	// OnToolDispatch is called once per in-flight tool with the
	// resolved action. Implementations should NOT block — they may
	// fan out to async pipelines (postgres audit) but the
	// orchestrator continues regardless.
	OnToolDispatch(ctx context.Context, missionID, toolNodeID string, mode manifestpb.ToolIdempotency, action IdempotencyAction)
}

// RewindDispatcher is the orchestrator-side coordinator the daemon
// invokes after validating the rewind request. It applies the
// per-tool idempotency contract, optionally cancels in-flight nodes,
// and emits audit hints via its emitter.
type RewindDispatcher struct {
	emitter RewindEmitter
}

// NewRewindDispatcher returns a RewindDispatcher that emits audit
// hints via the given emitter. Pass nil for emitter to skip emission.
func NewRewindDispatcher(emitter RewindEmitter) *RewindDispatcher {
	return &RewindDispatcher{emitter: emitter}
}

// Rewind dispatches all in-flight tools at the target checkpoint.
// Returns the canonical rewind error when any tool's contract demands
// FailMission (EXACTLY_ONCE without resumption token); otherwise
// returns nil and the orchestrator proceeds with the resume.
//
// The in-flight tool list is typically a 0- or 1-element slice (one
// active tool per super-step boundary), but the API takes a slice for
// future parallel-group support where multiple tools may be in flight.
func (d *RewindDispatcher) Rewind(
	ctx context.Context,
	missionID string,
	inFlight []InFlightTool,
) error {
	for _, t := range inFlight {
		action := DispatchInFlightTool(t)
		if d.emitter != nil {
			d.emitter.OnToolDispatch(ctx, missionID, t.NodeID, t.Idempotency, action)
		}
		if action == IdempotencyActionFailMission {
			return fmt.Errorf("rewind: tool %s declares EXACTLY_ONCE without resumption token; cannot resume safely", t.NodeID)
		}
	}
	return nil
}

// ResolveIdempotencyFromString maps a string-form idempotency mode
// (the daemon's CheckpointData.InFlightIdempotency) to the proto enum.
// Returns UNSPECIFIED for unknown / empty input — the caller's
// dispatch logic then treats that as AT_LEAST_ONCE (R6.6).
func ResolveIdempotencyFromString(s string) manifestpb.ToolIdempotency {
	switch s {
	case "AT_MOST_ONCE":
		return manifestpb.ToolIdempotency_TOOL_IDEMPOTENCY_AT_MOST_ONCE
	case "AT_LEAST_ONCE":
		return manifestpb.ToolIdempotency_TOOL_IDEMPOTENCY_AT_LEAST_ONCE
	case "EXACTLY_ONCE":
		return manifestpb.ToolIdempotency_TOOL_IDEMPOTENCY_EXACTLY_ONCE
	}
	return manifestpb.ToolIdempotency_TOOL_IDEMPOTENCY_UNSPECIFIED
}

// applyRewindIdempotency runs the orchestrator-side rewind dispatcher
// for the in-flight tool captured at the target checkpoint. When the
// target carries no in-flight tool, this is a no-op. Emits per-tool
// `mission.rewind.tool_cancelled` audit hints. Returns a
// FailedPrecondition gRPC error when the contract demands FailMission
// (EXACTLY_ONCE without resumption token).
//
// Spec: mission-checkpointing R6.3-R6.6, R16.4.
func (s *DaemonServer) applyRewindIdempotency(ctx context.Context, missionID, targetCheckpointID string) error {
	payload, err := s.daemon.GetMissionCheckpointPayload(ctx, missionID, targetCheckpointID)
	if err != nil || payload == nil {
		return nil //nolint:nilerr // best effort — without payload visibility, fall through and let the orchestrator's resume loop apply default semantics
	}
	if payload.InFlightNodeID == "" {
		// Nothing was in flight at the target; resume cleanly.
		return nil
	}
	dispatcher := NewRewindDispatcher(&serverRewindEmitter{server: s})
	tool := InFlightTool{
		NodeID:          payload.InFlightNodeID,
		ResumptionToken: payload.ResumptionToken,
		Idempotency:     ResolveIdempotencyFromString(payload.InFlightIdempotency),
	}
	if rerr := dispatcher.Rewind(ctx, missionID, []InFlightTool{tool}); rerr != nil {
		return status_grpc.Errorf(codes.FailedPrecondition, "rewind blocked by idempotency contract: %v", rerr)
	}
	return nil
}

// serverRewindEmitter implements RewindEmitter against
// the DaemonServer's audit writer + structured logger. Caller identity
// comes from the request context the dispatcher forwards to
// OnToolDispatch — the same context applyRewindIdempotency drives
// Rewind with.
type serverRewindEmitter struct {
	server *DaemonServer
}

func (e *serverRewindEmitter) OnToolDispatch(ctx context.Context, missionID, nodeID string, mode manifestpb.ToolIdempotency, action IdempotencyAction) {
	tenantID := auth.TenantStringFromContext(ctx)
	subject := ""
	if id, err := auth.IdentityFromContext(ctx); err == nil {
		subject = id.Subject
	}
	e.server.logger.Info("audit: mission.rewind.tool_cancelled",
		"event_kind", "mission.rewind.tool_cancelled",
		"tenant_id", tenantID,
		"mission_id", missionID,
		"node_id", nodeID,
		"idempotency_mode", mode.String(),
		"action", action.String(),
		"caller_subject", subject,
	)
	if e.server.tenantAdminAuditWriter != nil {
		meta := fmt.Sprintf(
			`{"mission_id":%q,"node_id":%q,"idempotency_mode":%q,"action":%q}`,
			missionID, nodeID, mode.String(), action.String(),
		)
		e.server.tenantAdminAuditWriter.Log(audit.Event{
			TenantID:   tenantID,
			ActorID:    subject,
			ActorType:  "user",
			Action:     "mission.rewind.tool_cancelled",
			TargetType: "mission",
			TargetID:   missionID,
			Metadata:   []byte(meta),
		})
	}
}
