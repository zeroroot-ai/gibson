// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"log/slog"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/sdk/auth"
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
// `user:` type for principal-typed subjects. componentFGAUser mirrors that
// transformation exactly — a check that shapes its user differently from the
// gateway would never match the same tuples.
var typedFGAPrincipalPrefixes = []string{
	"agent_principal:",
	"tool_principal:",
	"plugin_principal:",
	"user:",
}

// componentFGAUser maps an identity Subject to the FGA user string, mirroring
// internal/server/extauthz/fga/check.go. Subjects that already carry a typed
// principal prefix pass through verbatim; anything else is prefixed `user:`
// with any SPIFFE scheme stripped (OpenFGA's user-ID validator rejects "://").
//
// This is the sibling of callbackFGAUser in
// internal/engine/harness/callback_credential_authz.go (gibson#1245, PR #1278).
// The two GetCredential endpoints MUST ask FGA the same question; keep the two
// copies in step, and the table test TestComponentFGAUser_MirrorsGatewayShape
// pins the shared cases so a divergence shows up as a failing test rather than
// as a silent authorization gap.
func componentFGAUser(subject string) string {
	for _, prefix := range typedFGAPrincipalPrefixes {
		if strings.HasPrefix(subject, prefix) {
			return subject
		}
	}
	return "user:" + strings.TrimPrefix(subject, "spiffe://")
}

// authorizeCredentialResolve is the per-SECRET authorization gate for
// ComponentService/GetCredential (gibson#1245).
//
// Before this, GetCredential had NO per-secret decision the daemon could rely
// on: the handler did a bare credentialStore read after a tenant-presence check
// only, so any caller that reached the RPC got any secret in its
// header-asserted tenant. The gateway cannot supply the decision either — its
// field deriver has no request field to derive the secret object from, so the
// registry rule cannot form the per-secret question.
//
// This asks the same question the gateway builds for every other
// secret-resolving RPC: user = the caller's typed principal, relation =
// can_resolve, object = authz.SecretObject(tenant, name) — the identical triple
// the tenant-operator and the daemon's secret writers seed tuples against, so
// Check can actually match Write (gibson#1024/#1035).
//
// Fail-closed on every axis: no tenant, no identity, no authorizer wired, or an
// FGA error all deny. It returns gRPC status errors so an authorization refusal
// is a PERMISSION_DENIED on the wire — what a caller (and
// tests/e2e/secrets/non_plugin_deny_test.go) must be able to distinguish from
// "credential not found".
//
// The sibling implementation is HarnessCallbackService.authorizeCredentialResolve
// in internal/engine/harness/callback_credential_authz.go (PR #1278). Both
// endpoints resolve the same secrets against the same tuples; a change to one
// belongs in the other.
func (s *ComponentServiceServer) authorizeCredentialResolve(ctx context.Context, name string) error {
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

	if s.authorizer == nil {
		// No authorizer wired means no decision can be made. Deny rather than
		// serve the secret: an undecidable authorization question is a deny.
		// The daemon always wires one (grpc.go compSvc.WithAuthorizer, and
		// d.authorizer is always a real FGA client after initAuthorizer —
		// one-code-path slice deploy#195); this branch catches a misconfigured
		// or partially-constructed service.
		s.logCredentialDeny(ctx, tenant, name, "no_authorizer_configured")
		return status.Error(codes.PermissionDenied,
			"credential resolution denied: authorization unavailable")
	}

	fgaUser := componentFGAUser(identity.Subject)
	fgaObject := authz.SecretObject(tenant, name)

	allowed, checkErr := s.authorizer.Check(ctx, fgaUser, relationCanResolve, fgaObject)
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

// logCredentialDeny emits the structured deny record for a refused secret read.
// The credential NAME is logged (it is an identifier, never a value); no secret
// material passes through here.
//
// s.logger is guaranteed non-nil by NewComponentServiceServer (it defaults to
// slog.Default() when the caller passes nil), so a deny here is never silently
// dropped for want of a logger.
func (s *ComponentServiceServer) logCredentialDeny(ctx context.Context, tenant, name, reason string, extra ...slog.Attr) {
	attrs := []any{
		"event", "component.credential.denied",
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
