// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"errors"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/budget"
	connectionv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/connection/v1"
)

// connection_points.go serves ConnectionPointService: the neutral connection
// points of the platform (ADR-0060, D41, D54, gibson#713).
//
// The platform does not know which component calls these RPCs. Each RPC
// accepts one SPIFFE identity from config, read from the TLS peer of the
// call. A call through Envoy carries the SVID of Envoy and is refused. With
// no identity configured, no caller is accepted.

// Config of the two caller identities.
const (
	EnvSignupStepCompleterSVID = "GIBSON_SIGNUP_STEP_COMPLETER_SVID"
	EnvTenantActivationSVID    = "GIBSON_TENANT_ACTIVATION_SVID"
)

// ConnectionPointCallers holds the SPIFFE IDs that may call the connection
// points. An empty value accepts no caller.
type ConnectionPointCallers struct {
	SignupStepCompleter string
	TenantActivation    string
}

// WithConnectionPointCallers sets the SPIFFE IDs that may call the
// connection points.
func (s *DaemonServer) WithConnectionPointCallers(c ConnectionPointCallers) *DaemonServer {
	s.connectionCallers = ConnectionPointCallers{
		SignupStepCompleter: strings.TrimSpace(c.SignupStepCompleter),
		TenantActivation:    strings.TrimSpace(c.TenantActivation),
	}
	return s
}

// tlsPeerSVID returns the SPIFFE ID of the TLS peer of the call.
func tlsPeerSVID(ctx context.Context) (string, bool) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", false
	}
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(info.State.PeerCertificates) == 0 {
		return "", false
	}
	for _, u := range info.State.PeerCertificates[0].URIs {
		if u != nil && u.Scheme == "spiffe" {
			return u.String(), true
		}
	}
	return "", false
}

// callerRefusal returns why a call is refused when its TLS peer is not the
// configured SPIFFE ID, and ok when the peer is that ID.
func callerRefusal(ctx context.Context, want string) (reason string, ok bool) {
	if want == "" {
		return "this connection point has no configured caller", false
	}
	got, found := tlsPeerSVID(ctx)
	if !found || got != want {
		return "the caller is not the configured identity of this connection point", false
	}
	return "", true
}

// tenantUsageReader is the part of the budget enforcer that reads the usage
// of a named tenant.
type tenantUsageReader interface {
	TenantPeriodUsage(ctx context.Context, tenantID string) (tokens, costUSDCents int64, resetAt time.Time)
}

// CompleteSignupStep implements ConnectionPointServiceServer.
func (s *DaemonServer) CompleteSignupStep(ctx context.Context, req *connectionv1.CompleteSignupStepRequest) (*connectionv1.CompleteSignupStepResponse, error) {
	if reason, ok := callerRefusal(ctx, s.connectionCallers.SignupStepCompleter); !ok {
		return nil, status.Error(codes.PermissionDenied, reason)
	}
	if req.GetStepToken() == "" {
		return nil, status.Error(codes.InvalidArgument, "step_token is required")
	}
	var done bool
	switch req.GetOutcome() {
	case connectionv1.SignupStepOutcome_SIGNUP_STEP_OUTCOME_DONE:
		done = true
	case connectionv1.SignupStepOutcome_SIGNUP_STEP_OUTCOME_FAILED:
		done = false
	case connectionv1.SignupStepOutcome_SIGNUP_STEP_OUTCOME_UNSPECIFIED:
		return nil, status.Error(codes.InvalidArgument, "outcome must be DONE or FAILED")
	default:
		return nil, status.Error(codes.InvalidArgument, "outcome must be DONE or FAILED")
	}
	db := s.entitlementsDB()
	if db == nil {
		return nil, status.Error(codes.Unavailable, "platform Postgres not configured")
	}
	if err := ensurePendingTenantProvisioningTable(ctx, db); err != nil {
		return nil, status.Errorf(codes.Internal, "ensure table: %v", err)
	}
	switch err := completeSignupStep(ctx, db, req.GetStepToken(), done, s.signupNow()); {
	case errors.Is(err, errSignupStepNotFound):
		return nil, status.Error(codes.NotFound, "unknown or expired step token")
	case err != nil:
		s.logger.ErrorContext(ctx, "CompleteSignupStep failed", "error", err.Error())
		return nil, status.Error(codes.Unavailable, "the signup step could not be recorded; try again")
	}
	return &connectionv1.CompleteSignupStepResponse{}, nil
}

// DescribeSignupStep implements ConnectionPointServiceServer. It returns the
// tenant, the plan and the owner address of the signup that the step token
// names (gibson#943). The step completer reads them here and never from the
// browser, which carries the step link and could change a value in it.
func (s *DaemonServer) DescribeSignupStep(ctx context.Context, req *connectionv1.DescribeSignupStepRequest) (*connectionv1.DescribeSignupStepResponse, error) {
	if reason, ok := callerRefusal(ctx, s.connectionCallers.SignupStepCompleter); !ok {
		return nil, status.Error(codes.PermissionDenied, reason)
	}
	if req.GetStepToken() == "" {
		return nil, status.Error(codes.InvalidArgument, "step_token is required")
	}
	db := s.entitlementsDB()
	if db == nil {
		return nil, status.Error(codes.Unavailable, "platform Postgres not configured")
	}
	if err := ensurePendingTenantProvisioningTable(ctx, db); err != nil {
		return nil, status.Errorf(codes.Internal, "ensure table: %v", err)
	}
	d, err := describeSignupStep(ctx, db, req.GetStepToken(), s.signupNow())
	switch {
	case errors.Is(err, errSignupStepNotFound):
		return nil, status.Error(codes.NotFound, "unknown or expired step token")
	case err != nil:
		s.logger.ErrorContext(ctx, "DescribeSignupStep failed", "error", err.Error())
		return nil, status.Error(codes.Unavailable, "the signup step could not be read; try again")
	}
	return d, nil
}

// SetTenantActivation implements ConnectionPointServiceServer.
//
// gibsoncheck:allow tenant-from-request — the caller is the configured
// activation identity, checked from the TLS peer above. It names a tenant by
// design: it starts and stops tenants of the platform.
func (s *DaemonServer) SetTenantActivation(ctx context.Context, req *connectionv1.SetTenantActivationRequest) (*connectionv1.SetTenantActivationResponse, error) {
	if reason, ok := callerRefusal(ctx, s.connectionCallers.TenantActivation); !ok {
		return nil, status.Error(codes.PermissionDenied, reason)
	}
	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}
	var activation string
	switch req.GetState() {
	case connectionv1.TenantActivationState_TENANT_ACTIVATION_STATE_ACTIVE:
		activation = activationActive
	case connectionv1.TenantActivationState_TENANT_ACTIVATION_STATE_SUSPENDED:
		activation = activationSuspended
	case connectionv1.TenantActivationState_TENANT_ACTIVATION_STATE_UNSPECIFIED:
		return nil, status.Error(codes.InvalidArgument, "state must be ACTIVE or SUSPENDED")
	default:
		return nil, status.Error(codes.InvalidArgument, "state must be ACTIVE or SUSPENDED")
	}
	db := s.entitlementsDB()
	if db == nil {
		return nil, status.Error(codes.Unavailable, "platform Postgres not configured")
	}
	if err := ensureTenantStatusTable(ctx, db); err != nil {
		return nil, status.Errorf(codes.Internal, "ensure table: %v", err)
	}
	changed, found, err := setTenantActivation(ctx, db, req.GetTenantId(), activation)
	if err != nil {
		s.logger.ErrorContext(ctx, "SetTenantActivation failed", "error", err.Error())
		return nil, status.Error(codes.Unavailable, "the activation could not be recorded; try again")
	}
	if !found {
		return nil, status.Errorf(codes.NotFound, "tenant %q is not known", req.GetTenantId())
	}
	s.tenantActivation.forget(req.GetTenantId())
	return &connectionv1.SetTenantActivationResponse{Changed: changed}, nil
}

// ListTenantUsage implements ConnectionPointServiceServer.
func (s *DaemonServer) ListTenantUsage(ctx context.Context, _ *connectionv1.ListTenantUsageRequest) (*connectionv1.ListTenantUsageResponse, error) {
	if reason, ok := callerRefusal(ctx, s.connectionCallers.TenantActivation); !ok {
		return nil, status.Error(codes.PermissionDenied, reason)
	}
	usage, ok := s.budgetEnforcer.(tenantUsageReader)
	if !ok {
		return nil, status.Error(codes.Unavailable, "budget counters are not configured")
	}
	db := s.entitlementsDB()
	if db == nil {
		return nil, status.Error(codes.Unavailable, "platform Postgres not configured")
	}
	if err := ensureTenantStatusTable(ctx, db); err != nil {
		return nil, status.Errorf(codes.Internal, "ensure table: %v", err)
	}
	tenants, err := listTenantIDs(ctx, db)
	if err != nil {
		s.logger.ErrorContext(ctx, "ListTenantUsage: list tenants failed", "error", err.Error())
		return nil, status.Error(codes.Unavailable, "usage is not available; try again")
	}
	resp := &connectionv1.ListTenantUsageResponse{Tenants: make([]*connectionv1.TenantUsage, 0, len(tenants))}
	for _, t := range tenants {
		tokens, cost, _ := usage.TenantPeriodUsage(ctx, t)
		resp.Tenants = append(resp.Tenants, &connectionv1.TenantUsage{TenantId: t, Tokens: tokens, CostUsdCents: cost})
	}
	now := s.signupNow()
	end := budget.PeriodResetAt(now)
	start := time.Date(end.Year(), end.Month()-1, 1, 0, 0, 0, 0, time.UTC)
	resp.PeriodStartUnix, resp.PeriodEndUnix = start.Unix(), end.Unix()
	return resp, nil
}
