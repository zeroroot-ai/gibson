// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

// capability_gate.go enforces the session-capability bits gibson#1186 slice C
// introduced: capname.MissionDelegate (checked by DelegateToAgent in
// service_delegation.go) and capname.MissionOriginate (checked by every
// mission-origination RPC through missionCall in service_missions.go, wired in
// gibson#1358).
//
// Both bits are checked HERE, in the handler, not at ext-authz. The coarse
// grant validity — does this CG-JWT verify at all, is the component's FGA
// principal allowed to reach ComponentService — is ext-authz's job and
// happens before the request arrives. But "may THIS principal delegate" needs
// the resolved capability-grant row, which lives in the daemon's Postgres;
// ext-authz never talks to Postgres and a body-independent decision is the
// only kind it makes (the #1245 rule: body-dependent authorization decisions
// belong in the handler, not the gateway). Nothing about mission:delegate is
// decidable from the CG-JWT claims alone — the grant can be revoked after the
// JWT was minted — so the handler is the only place this check can be both
// correct and current.

import (
	"context"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/sdk/auth"
)

// requireCapability resolves the calling component's FGA principal from ctx
// and denies the request unless that principal holds an ACTIVE grant named
// capabilityName within tenant. On success it returns that grant's id, which
// mission origination records as the immutable lineage of the mission it
// creates (gibson#1358) — one lookup, so an authorization answer and the
// attribution written alongside it can never name different grants.
//
// Fails closed on every ambiguous path — no identity, no CapabilityChecker
// wired, or a checker error all deny rather than silently letting the call
// through:
//
//   - no identity on ctx                → Unauthenticated
//   - s.capabilityChecker == nil        → Unavailable (the gate cannot be
//     evaluated, which is never the same thing as "the gate is open")
//   - checker returns an error          → Internal
//   - checker returns false             → PermissionDenied
//
// PermissionDenied, not FailedPrecondition: the earlier interim stub this
// replaces (gibson#1201) used FailedPrecondition to mean "the seam does not
// exist yet, ask a human." That is no longer true — the seam exists and the
// answer is a real per-caller authorization decision, the same status every
// other insufficient-grant path in this service already returns.
func (s *ComponentServiceServer) requireCapability(ctx context.Context, tenant, capabilityName string) (grantID string, err error) {
	id, idErr := auth.IdentityFromContext(ctx)
	if idErr != nil || id.Subject == "" {
		return "", status.Error(codes.Unauthenticated, "caller identity unavailable")
	}

	if s.capabilityChecker == nil {
		s.logger.ErrorContext(ctx, "capability check: checker not wired; refusing capability-gated request",
			slog.String("tenant", tenant),
			slog.String("capability", capabilityName),
		)
		return "", status.Errorf(codes.Unavailable,
			"capability %q cannot be evaluated: capability-grant service is not configured", capabilityName)
	}

	grantID, checkErr := s.capabilityChecker.ActiveGrantID(ctx, tenant, id.Subject, capabilityName)
	if checkErr != nil {
		s.logger.ErrorContext(ctx, "capability check failed",
			slog.String("tenant", tenant),
			slog.String("capability", capabilityName),
			slog.String("error", checkErr.Error()),
		)
		return "", status.Errorf(codes.Internal, "capability check failed: %v", checkErr)
	}
	if grantID == "" {
		s.logger.WarnContext(ctx, "capability check denied",
			slog.String("tenant", tenant),
			slog.String("principal", id.Subject),
			slog.String("capability", capabilityName),
		)
		return "", status.Errorf(codes.PermissionDenied,
			"capability %q is not granted to this component", capabilityName)
	}
	return grantID, nil
}
