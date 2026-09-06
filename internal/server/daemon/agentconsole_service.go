// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package daemon — agentconsole_service.go
//
// agentConsoleServer implements gibson.daemon.agentconsole.v1.AgentConsoleService:
// the daemon's read-only, tenant-scoped view of the agents running right now and
// their live structured events (ADR-0016 S11, gibson#1599). It reads from the
// in-memory liveagents.Registry that the sandboxed agent launcher tees each run
// into. The dashboard's live agent console (S12) reads through here over
// Envoy + ext-authz.
//
// It resolves the caller's tenant from context and reads only that tenant's
// instances. Enumeration and each per-instance stream are scoped to that
// tenant; a run id owned by another tenant returns codes.NotFound, never data.
// This mirrors logsServer / worldServer: daemon-local, tenant-scoped
// observability, with no input/write path.
package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/bank"
	agentconsolev1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/agentconsole/v1"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/liveagents"
	bankpb "github.com/zeroroot-ai/sdk/api/gen/gibson/bank/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// agentConsoleServer serves the read-only running-agent surface over the shared
// liveagents.Registry.
type agentConsoleServer struct {
	agentconsolev1.UnimplementedAgentConsoleServiceServer

	registry *liveagents.Registry
	members  MemberSource
	logger   *slog.Logger
}

// MemberSource resolves which bank member a running instance is, from the
// member run id the instance was launched under (ADR-0019, gibson#1716). The
// daemon backs it with the bank store. bank.ErrNotFound means the instance is
// not a member, which is what every one-shot dispatch answers.
type MemberSource interface {
	MemberByRun(ctx context.Context, tenantID, runID string) (*bank.Member, error)
}

// noMembers is the default: a console with no bank surface sees no members.
type noMembers struct{}

func (noMembers) MemberByRun(context.Context, string, string) (*bank.Member, error) {
	return nil, bank.ErrNotFound
}

// AgentConsoleOption configures the console server.
type AgentConsoleOption func(*agentConsoleServer)

// WithMemberSource wires where the console learns which instance is a member.
func WithMemberSource(m MemberSource) AgentConsoleOption {
	return func(s *agentConsoleServer) { s.members = m }
}

// NewAgentConsoleServer constructs the AgentConsoleService backed by the live
// running-agent registry.
func NewAgentConsoleServer(registry *liveagents.Registry, logger *slog.Logger, opts ...AgentConsoleOption) agentconsolev1.AgentConsoleServiceServer {
	if registry == nil {
		panic("agent console server: registry cannot be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	s := &agentConsoleServer{registry: registry, members: noMembers{}, logger: logger}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// tenant resolves the caller's tenant from context. It is the ONLY scope the
// request can read; the client never supplies it. Cross-tenant access is
// structurally impossible.
func (s *agentConsoleServer) tenant(ctx context.Context) (string, error) {
	t, ok := auth.TenantFromContext(ctx)
	if !ok {
		return "", status.Errorf(codes.PermissionDenied, "no tenant in context")
	}
	return t.String(), nil
}

// ListRunningAgents enumerates the caller-tenant's running agent instances.
func (s *agentConsoleServer) ListRunningAgents(ctx context.Context, _ *agentconsolev1.ListRunningAgentsRequest) (*agentconsolev1.ListRunningAgentsResponse, error) {
	tenant, err := s.tenant(ctx)
	if err != nil {
		return nil, err
	}
	instances := s.registry.List(tenant)
	agents := make([]*agentconsolev1.RunningAgent, 0, len(instances))
	for _, inst := range instances {
		row := &agentconsolev1.RunningAgent{
			RunId:            inst.RunID,
			AgentName:        inst.AgentName,
			SandboxId:        inst.SandboxID,
			StartedUnixNanos: inst.StartedAt.UnixNano(),
			MissionId:        inst.MissionID,
			MissionRunId:     inst.MissionRunID,
			SandboxClass:     inst.SandboxClass,
			ComponentKind:    inst.ComponentKind,
		}
		s.decorateMember(ctx, tenant, inst, row)
		agents = append(agents, row)
	}
	return &agentconsolev1.ListRunningAgentsResponse{Agents: agents}, nil
}

// StreamAgentEvents streams one running instance's live events by run id. It
// ends when the run reaches a terminal state (the feed closes) or when the
// client disconnects. A run id the tenant does not own returns codes.NotFound —
// indistinguishable from a run id that never existed, so the surface never
// leaks another tenant's run ids.
func (s *agentConsoleServer) StreamAgentEvents(req *agentconsolev1.StreamAgentEventsRequest, stream agentconsolev1.AgentConsoleService_StreamAgentEventsServer) error {
	ctx := stream.Context()
	tenant, err := s.tenant(ctx)
	if err != nil {
		return err
	}
	if req.GetRunId() == "" {
		return status.Errorf(codes.InvalidArgument, "run_id is required")
	}

	keep := jobFilter(req.GetJobId())
	backlog, events, cancel, err := s.registry.Subscribe(tenant, req.GetRunId(), req.GetSinceSeq())
	if err != nil {
		if errors.Is(err, liveagents.ErrInstanceNotFound) {
			return status.Errorf(codes.NotFound, "no such running agent")
		}
		return status.Errorf(codes.Internal, "subscribe to agent events: %v", err)
	}
	defer cancel()

	// The backlog after since_seq first, so a resumed client backfills its
	// tail; then the live feed, cut at the same instant as the backlog.
	for _, ev := range backlog {
		if !keep(ev) {
			continue
		}
		if err := stream.Send(toAgentEvent(ev)); err != nil {
			return fmt.Errorf("send agent event: %w", err)
		}
	}

	for {
		select {
		case <-ctx.Done():
			// The client went away; end the stream without error.
			return nil
		case ev, ok := <-events:
			if !ok {
				// The run reached a terminal state; the feed is closed.
				return nil
			}
			if sendErr := stream.Send(toAgentEvent(ev)); sendErr != nil {
				return fmt.Errorf("send agent event: %w", sendErr)
			}
		}
	}
}

// decorateMember fills the member fields of a row when the instance is a bank
// member. A one-shot dispatch is not, and stays as it was. A store outage is
// logged and the row still lists: the console must not go dark because the
// bank tables did.
func (s *agentConsoleServer) decorateMember(ctx context.Context, tenant string, inst liveagents.Instance, row *agentconsolev1.RunningAgent) {
	if inst.MissionRunID == "" {
		return
	}
	m, err := s.members.MemberByRun(ctx, tenant, inst.MissionRunID)
	if errors.Is(err, bank.ErrNotFound) {
		return
	}
	if err != nil {
		s.logger.WarnContext(ctx, "agent console: member lookup failed", "run_id", inst.RunID, "error", err)
		return
	}
	row.BankId = m.BankID
	row.MemberId = m.ID
	if !m.LastHeartbeat.IsZero() {
		row.Member = &bankpb.MemberStatus{
			State:         memberStateToProto(m.State),
			JobsInFlight:  m.JobsInFlight,
			Cap:           m.JobCap,
			ActiveJobIds:  m.ActiveJobIDs,
			ClaudeVersion: m.ClaudeVersion,
		}
	}
}

// jobFilter returns the predicate a job_id narrows a stream with. With no
// job id every event passes. With one, only a line that parses as JSON and
// names that job passes: the agent's own output carries no job id.
func jobFilter(jobID string) func(liveagents.Event) bool {
	if jobID == "" {
		return func(liveagents.Event) bool { return true }
	}
	return func(ev liveagents.Event) bool {
		var line struct {
			JobID string `json:"job_id"`
		}
		if err := json.Unmarshal(ev.Data, &line); err != nil {
			return false
		}
		return line.JobID == jobID
	}
}

// toAgentEvent maps one registry event to the wire message.
func toAgentEvent(ev liveagents.Event) *agentconsolev1.AgentEvent {
	return &agentconsolev1.AgentEvent{
		UnixNanos: ev.At.UnixNano(),
		Data:      ev.Data,
		Seq:       ev.Seq,
	}
}
