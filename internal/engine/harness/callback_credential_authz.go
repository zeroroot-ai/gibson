// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/sdk/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// relationCanResolve is the FGA relation that grants plaintext read-back of a
// secret. Per internal/platform/authz/model.fga the `secret` type declares
//
//	define can_resolve: [plugin_principal]
//
// and NOTHING else: agent_principal and tool_principal have no relation to
// secret at all, so their absence is a STRUCTURAL gate, not a policy default.
// A can_resolve tuple for a user-, agent- or tool-typed subject is rejected by
// OpenFGA at insert time (spec non-plugin-secret-isolation).
const relationCanResolve = "can_resolve"

// denyReasonNoCanResolve is the categorised audit/log reason for a secret read
// refused because FGA has no can_resolve tuple. It matches the DecisionReason
// value documented in internal/platform/secrets/audit.go and asserted by
// tests/e2e/secrets/non_plugin_deny_test.go.
const denyReasonNoCanResolve = "fga_no_can_resolve"

// typedFGAPrincipalPrefixes are the FGA subject types the daemon asserts
// verbatim in a component's identity Subject (ADR-0045). ext-authz uses the
// Subject unchanged as the FGA user for these (see the IdentityComponent branch
// in internal/server/extauthz/fga/check.go) because the model rejects the
// `user:` type for principal-typed subjects. callbackFGAUser mirrors that
// transformation exactly — a check that shapes its user differently from the
// gateway would never match the same tuples.
var typedFGAPrincipalPrefixes = []string{
	"agent_principal:",
	"tool_principal:",
	"plugin_principal:",
	"user:",
}

// callbackFGAUser maps an identity Subject to the FGA user string, mirroring
// internal/server/extauthz/fga/check.go. Subjects that already carry a typed
// principal prefix pass through verbatim; anything else is prefixed `user:`
// with any SPIFFE scheme stripped (OpenFGA's user-ID validator rejects "://").
func callbackFGAUser(subject string) string {
	for _, prefix := range typedFGAPrincipalPrefixes {
		if strings.HasPrefix(subject, prefix) {
			return subject
		}
	}
	return "user:" + strings.TrimPrefix(subject, "spiffe://")
}

// authorizeCredentialResolve is the per-SECRET authorization gate for
// HarnessCallbackService/GetCredential (gibson#1245).
//
// Before this, GetCredential had NO per-secret decision at EITHER layer:
//
//   - the gateway does not see it — the harness callback listener is a separate
//     :50001 mTLS listener that ext-authz never fronts, so the registry rule that
//     enforces can_resolve on the SecretsService/ComponentService paths never runs;
//   - the handler did a bare credentialStore read with no Check.
//
// Any caller that reached the RPC therefore got any secret in its header-asserted
// tenant. This restores the same decision the gateway makes for every other
// secret-resolving RPC: user = the caller's typed principal, relation =
// can_resolve, object = authz.SecretObject(tenant, name) — the identical triple
// the tenant-operator and the daemon's secret writers seed tuples against, so
// Check can actually match Write (gibson#1024/#1035).
//
// Fail-closed on every axis: no tenant, no identity, no authorizer wired, or an
// FGA error all deny. It returns gRPC status errors rather than the handler's
// in-band HarnessError so an authorization refusal is a PERMISSION_DENIED on the
// wire — what a caller (and tests/e2e/secrets/non_plugin_deny_test.go) must be
// able to distinguish from "credential not found".
func (s *HarnessCallbackService) authorizeCredentialResolve(ctx context.Context, name string) error {
	if name == "" {
		return status.Error(codes.InvalidArgument, "credential name is required")
	}

	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" || tenant == auth.SystemTenantString {
		s.logCredentialDeny(ctx, "", name, "no_tenant_in_context")
		return status.Error(codes.PermissionDenied,
			"credential resolution denied: no tenant in context")
	}

	identity, err := auth.IdentityFromContext(ctx)
	if err != nil || identity.Subject == "" {
		s.logCredentialDeny(ctx, tenant, name, "no_caller_identity")
		return status.Error(codes.Unauthenticated,
			"credential resolution denied: no caller identity")
	}

	if s.componentAuthorizer == nil {
		// No authorizer wired means no decision can be made. Deny rather than
		// serve the secret: an undecidable authorization question is a deny.
		// The daemon always wires one (daemon.go SetComponentAuthorizer,
		// one-code-path slice deploy#195); this branch catches a misconfigured
		// or partially-constructed service.
		s.logCredentialDeny(ctx, tenant, name, "no_authorizer_configured")
		return status.Error(codes.PermissionDenied,
			"credential resolution denied: authorization unavailable")
	}

	// A bank member is bounded a second time, by the job it is working on
	// (ADR-0019, gibson#1711). The daemon's grant minter already refuses to put
	// secret resolution on a non-plugin grant, so a member should never reach
	// here at all — this is the layer that holds if that one ever moves, and it
	// answers the question the grant cannot: not "may this component read a
	// secret" but "did the job this member is running declare this name".
	if err := s.refuseUndeclaredMemberCredential(ctx, tenant, name); err != nil {
		return err
	}

	fgaUser := callbackFGAUser(identity.Subject)
	fgaObject := authz.SecretObject(tenant, name)

	allowed, checkErr := s.componentAuthorizer.Check(ctx, fgaUser, relationCanResolve, fgaObject)
	if checkErr != nil {
		s.logger.ErrorContext(ctx, "credential resolution: FGA check failed",
			slog.String("fga_user", fgaUser),
			slog.String("fga_relation", relationCanResolve),
			slog.String("fga_object", fgaObject),
			slog.String("error", checkErr.Error()),
		)
		return status.Error(codes.Unavailable,
			"credential resolution: authorization service error")
	}
	if !allowed {
		s.logCredentialDeny(ctx, tenant, name, denyReasonNoCanResolve,
			slog.String("fga_user", fgaUser),
			slog.String("fga_object", fgaObject),
		)
		return status.Error(codes.PermissionDenied,
			"credential resolution denied: caller has no can_resolve on this secret")
	}
	return nil
}

// refuseUndeclaredMemberCredential refuses a credential name that none of the
// calling member's open jobs declared.
//
// It answers nothing at all for a caller that is not a member: a dispatched
// one-shot agent and a first-party plugin are bounded by the FGA check below,
// which is the boundary they were designed against. Only a member carries a
// job, and only a job declares credential names.
func (s *HarnessCallbackService) refuseUndeclaredMemberCredential(ctx context.Context, tenant, name string) error {
	info, ok := TaskGrantClaimsFromContext(ctx)
	if !ok {
		return nil
	}
	_, _, err := s.members.MemberByRun(ctx, tenant, info.MissionID)
	switch {
	case errors.Is(err, ErrNotAMember), errors.Is(err, ErrNoBankSurface):
		// Not a member. The FGA check below is this caller's boundary.
		return nil
	case err != nil:
		// An outage is not "not a member". Refuse, because the alternative
		// reads a member as unbounded while the bank store is down.
		s.logCredentialDeny(ctx, tenant, name, "member_lookup_unavailable")
		return status.Errorf(codes.Unavailable, "credential resolution denied: cannot resolve the calling member: %v", err)
	}
	j, err := s.jobs.Get(ctx, tenant, info.TaskID)
	if err != nil {
		s.logCredentialDeny(ctx, tenant, name, "member_grant_names_no_job")
		return status.Error(codes.PermissionDenied,
			"credential resolution denied: this turn is not running a job")
	}
	if !CredentialAllowedByJob(j.Spec.GetCredentialNames(), name) {
		s.logCredentialDeny(ctx, tenant, name, "credential_not_declared_by_job",
			slog.String("job_id", j.ID))
		return status.Error(codes.PermissionDenied,
			"credential resolution denied: the job did not declare this credential")
	}
	return nil
}

// logCredentialDeny emits the structured deny record for a refused secret read.
// The credential NAME is logged (it is an identifier, never a value); no secret
// material passes through here.
func (s *HarnessCallbackService) logCredentialDeny(ctx context.Context, tenant, name, reason string, extra ...slog.Attr) {
	// s.logger is never nil: both constructors (NewHarnessCallbackService,
	// NewHarnessCallbackServiceWithRegistry) default it to slog.Default()
	// before the service is ever reachable — the same invariant every other
	// s.logger call site in callback_service.go already relies on unguarded.
	attrs := []any{
		"event", "callback.credential.denied",
		"audit_event", "secret_read_deny",
		"decision", "deny",
		"decision_reason", reason,
		"tenant_id", tenant,
		"credential_name", name,
	}
	for _, a := range extra {
		attrs = append(attrs, a.Key, a.Value.String())
	}
	s.logger.WarnContext(ctx, "credential resolution denied", attrs...)
}
