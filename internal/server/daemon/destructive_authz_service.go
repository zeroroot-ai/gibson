// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package daemon — destructive_authz_service.go
//
// destructiveAuthzServer implements
// gibson.daemon.destructiveauthz.v1.DestructiveAuthorizationService: the
// daemon API backing the dashboard's destructive-action authorization queue
// (dashboard#99, gibson#336). It is a thin read/decide surface over each
// tenant's brain.DestructiveAuthorizationQueue (internal/engine/brain,
// destructive_authz.go) — the concrete DestructiveProofAuthorizer that
// enqueues a pending request and blocks only that one action (ADR-0028)
// until this service's Approve/Deny resolves it. It mirrors worldServer
// exactly: daemon-local, tenant-scoped, backed by the per-tenant brain
// registry.
package daemon

import (
	"context"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	destructiveauthzv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/destructiveauthz/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

type destructiveAuthzServer struct {
	destructiveauthzv1.UnimplementedDestructiveAuthorizationServiceServer

	registry *brain.Registry
	logger   *slog.Logger
}

// NewDestructiveAuthorizationServer constructs the DestructiveAuthorizationService
// backed by the per-tenant brain registry.
func NewDestructiveAuthorizationServer(registry *brain.Registry, logger *slog.Logger) destructiveauthzv1.DestructiveAuthorizationServiceServer {
	if registry == nil {
		panic("destructive authorization server: registry cannot be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &destructiveAuthzServer{registry: registry, logger: logger}
}

// queue resolves the caller's tenant from context and returns its
// DestructiveAuthorizationQueue (the tenant's engine is created on first
// use, the same lazy fault-in every other per-tenant read/write in this
// package relies on). Cross-tenant access is structurally impossible — a
// caller only ever reaches its own tenant's queue.
func (s *destructiveAuthzServer) queue(ctx context.Context) (*brain.DestructiveAuthorizationQueue, error) {
	t, ok := auth.TenantFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "no tenant in context")
	}
	return s.registry.For(t.String()).DestructiveAuthorizationQueue(), nil
}

// toPendingDestructiveActionPB converts a brain.DestructiveActionSnapshot
// into its wire representation. BlastRadius/Reversibility are left at their
// zero values: ADR-0028 decision 1's Domain Pack risk-tier signal is not
// built yet (see the .proto's Reversibility doc comment) — every action
// reaching this queue is already known destructive via
// BetSettlementRequest.Destructive alone, which is why it is here at all.
func toPendingDestructiveActionPB(a brain.DestructiveActionSnapshot) *destructiveauthzv1.PendingDestructiveAction {
	return &destructiveauthzv1.PendingDestructiveAction{
		ActionId:          a.HypothesisID,
		HypothesisId:      a.HypothesisID,
		ScopeId:           a.ScopeID,
		MissionId:         a.MissionID,
		Technique:         a.Technique,
		PredicateType:     a.PredicateType,
		RequestedAtUnixMs: a.RequestedAtUnixMS,
	}
}

// ListPendingDestructiveActions returns every destructive action for the
// caller's tenant still awaiting a human decision.
func (s *destructiveAuthzServer) ListPendingDestructiveActions(
	ctx context.Context,
	_ *destructiveauthzv1.ListPendingDestructiveActionsRequest,
) (*destructiveauthzv1.ListPendingDestructiveActionsResponse, error) {
	q, err := s.queue(ctx)
	if err != nil {
		return nil, err
	}
	resp := &destructiveauthzv1.ListPendingDestructiveActionsResponse{}
	for _, a := range q.Pending() {
		resp.Actions = append(resp.Actions, toPendingDestructiveActionPB(a))
	}
	return resp, nil
}

// requireActingUser resolves the human acting on behalf of the tenant-admin
// caller. Unlike world_service.go's SubmitLabel (where a missing acting-user
// is provenance-only and tolerable), a destructive-action decision is
// exactly the accountability record ADR-0028 exists for: proceeding with an
// empty/unknown identity when resolution fails is the privileged-fallback
// pattern (silently treating "we don't know who this is" as "proceed
// anyway"). Refuse instead.
func requireActingUser(ctx context.Context) (string, error) {
	userID, ok := auth.ActingUserFromContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "no acting user in context")
	}
	return userID, nil
}

// ApproveDestructiveAction authorizes the named pending action, unblocking
// the fleet's settlement attempt for it (ADR-0028 decision 3).
func (s *destructiveAuthzServer) ApproveDestructiveAction(
	ctx context.Context,
	req *destructiveauthzv1.ApproveDestructiveActionRequest,
) (*destructiveauthzv1.ApproveDestructiveActionResponse, error) {
	q, err := s.queue(ctx)
	if err != nil {
		return nil, err
	}
	actionID := req.GetActionId()
	if actionID == "" {
		return nil, status.Error(codes.InvalidArgument, "action_id is required")
	}
	userID, err := requireActingUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := q.Decide(actionID, userID, true); err != nil {
		s.logger.Warn("approve destructive action failed",
			slog.String("action_id", actionID), slog.Any("err", err))
		return nil, status.Errorf(codes.FailedPrecondition, "approve destructive action: %v", err)
	}
	return &destructiveauthzv1.ApproveDestructiveActionResponse{}, nil
}

// DenyDestructiveAction refuses the named pending action (ADR-0028 decision
// 3). Same refusal rules as ApproveDestructiveAction.
func (s *destructiveAuthzServer) DenyDestructiveAction(
	ctx context.Context,
	req *destructiveauthzv1.DenyDestructiveActionRequest,
) (*destructiveauthzv1.DenyDestructiveActionResponse, error) {
	q, err := s.queue(ctx)
	if err != nil {
		return nil, err
	}
	actionID := req.GetActionId()
	if actionID == "" {
		return nil, status.Error(codes.InvalidArgument, "action_id is required")
	}
	userID, err := requireActingUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := q.Decide(actionID, userID, false); err != nil {
		s.logger.Warn("deny destructive action failed",
			slog.String("action_id", actionID), slog.Any("err", err))
		return nil, status.Errorf(codes.FailedPrecondition, "deny destructive action: %v", err)
	}
	return &destructiveauthzv1.DenyDestructiveActionResponse{}, nil
}
