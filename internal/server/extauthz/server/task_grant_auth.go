// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc/codes"

	"github.com/zeroroot-ai/gibson/internal/server/extauthz/headers"
	"github.com/zeroroot-ai/sdk/capabilitygrant"
)

// componentTokenType is the `typ` header of a registered component's
// self-signed token (ADR-0045). tryComponentAuth owns those. Every other typ on
// x-capability-grant is a daemon-minted grant.
const componentTokenType = "agent+jwt"

// tryTaskGrantAuth authenticates a request whose ONLY credential is a
// daemon-minted task grant (gibson#1605).
//
// # Why this path exists
//
// A sandboxed platform agent holds nothing standing (ADR-0016 decision 2). The
// daemon injects one per-dispatch grant and no identity at all. Since
// gibson#1450 its callbacks go through Envoy, jwt_authn and ext-authz, so
// without this path the only credential that passes is the component's own
// self-signed agent+jwt — the standing identity ADR-0016 removes.
//
// # Why the grant is the authorization here, and not a constraint
//
// enforceCapabilityGrant treats a grant presented ALONGSIDE an identity as a
// constraint: it can only take a request away. That is right for a caller who
// authenticated on its own. It is the wrong reading of a grant that is the
// caller's only credential, for two reasons.
//
//  1. The decision is already made. The daemon mints a work grant only after
//     the dispatch gate passed: can_execute on component:<kind>/<name> for this
//     tenant (implementation.go authorizeComponentDispatch). That IS the FGA
//     decision, taken with the mission context ext-authz does not have.
//  2. ext-authz cannot re-ask it. The registry rule for every
//     HarnessCallbackService RPC derives the object component:_system — the
//     platform backplane, which a dispatched catalog agent holds no tuple on
//     precisely because it has no standing principal. Asking that question
//     would deny every callback, whatever the tenant enabled.
//
// So the grant's own claims are the authority, and they are narrow: the daemon's
// key signed them, they name one tenant, one mission and one task, they expire
// (capabilitygrant.MaxLifetime), they list the exact methods, and the minter
// refuses to put secret resolution on a non-plugin grant. The callback listener
// then binds the grant to the request body — a grant for mission A cannot
// present a ContextInfo naming mission B (callback_task_grant.go).
//
// It returns (resp, true) when it owns the decision, or (nil, false) when there
// is no grant at all or the token is a component's own agent+jwt, leaving the
// caller to fall through to tryComponentAuth.
func (s *EnvoyAuthzServer) tryTaskGrantAuth(ctx context.Context, method string, httpHeaders map[string]string) (*authv3.CheckResponse, bool) {
	token := extractCapabilityGrant(httpHeaders)
	if token == "" || tokenType(token) == componentTokenType {
		return nil, false
	}
	if s.cgjwt == nil {
		// A task grant is present and this ext-authz cannot verify one. That is
		// a refusal, not a fall-through: letting it reach the component path
		// would answer "unauthenticated" for a credential that was never read.
		extauthzCGJWTRejectedTotal.WithLabelValues("task_grant_no_verifier").Inc()
		s.log.ErrorContext(ctx, "ext-authz: task grant presented but no grant verifier is configured",
			"method", method)
		return denyResponse(codes.Unauthenticated, typev3.StatusCode_Unauthorized, bodyUnauthenticated), true
	}

	claims, err := s.cgjwt.Verify(ctx, token)
	if err != nil {
		switch {
		case errors.Is(err, capabilitygrant.ErrExpired):
			extauthzCGJWTRejectedTotal.WithLabelValues("task_grant_expired").Inc()
		case errors.Is(err, capabilitygrant.ErrSignature), errors.Is(err, capabilitygrant.ErrUnknownKey):
			extauthzCGJWTRejectedTotal.WithLabelValues("task_grant_signature").Inc()
		default:
			extauthzCGJWTRejectedTotal.WithLabelValues("task_grant_invalid").Inc()
		}
		s.log.WarnContext(ctx, "ext-authz: task grant invalid", "method", method, "err", err)
		return denyResponse(codes.Unauthenticated, typev3.StatusCode_Unauthorized, bodyUnauthenticated), true
	}

	if claims.Subject == "" || claims.Tenant.String() == "" {
		extauthzCGJWTRejectedTotal.WithLabelValues("task_grant_claims").Inc()
		s.log.WarnContext(ctx, "ext-authz: task grant carries no subject or tenant", "method", method)
		return denyResponse(codes.PermissionDenied, typev3.StatusCode_Forbidden, bodyPermissionDenied), true
	}

	if !claims.AllowsMethod(method) {
		extauthzCGJWTRejectedTotal.WithLabelValues("method_not_allowed").Inc()
		s.log.InfoContext(ctx, "ext-authz: task grant does not cover method",
			"method", method, "subject", claims.Subject, "task", claims.TaskID)
		extauthzDeniedTotal.WithLabelValues(method).Inc()
		return denyResponse(codes.PermissionDenied, typev3.StatusCode_Forbidden, bodyPermissionDenied), true
	}

	id := headers.Identity{
		Subject:        claims.Subject,
		Issuer:         headers.IssuerCapabilityGrant,
		CredentialType: headers.CredentialCapabilityGrant,
		// Daemon-asserted. The x-gibson-tenant header is never consulted:
		// the tenant is a signed claim, so a caller cannot name its own.
		Tenant: claims.Tenant.String(),
	}
	id.IssuedAt = nowUTC()
	extauthzTaskGrantAllowedTotal.WithLabelValues(method).Inc()
	extauthzAllowedTotal.WithLabelValues(method).Inc()
	s.log.DebugContext(ctx, "ext-authz: allowed (daemon task grant)",
		"method", method, "subject", claims.Subject, "tenant", id.Tenant,
		"mission", claims.MissionID, "task", claims.TaskID)
	return okResponse(headers.Emit(id)), true
}

// tokenType reads the `typ` of a compact JWT header WITHOUT trusting it. It
// only routes between the two credential kinds; each path verifies in full
// before reading a claim.
func tokenType(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return ""
	}
	var h struct {
		Typ string `json:"typ"`
	}
	if json.Unmarshal(raw, &h) != nil {
		return ""
	}
	return h.Typ
}
