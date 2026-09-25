// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package server implements the Envoy ext_authz Authorization gRPC
// service. Per the unified-identity-and-authorization spec, ext-authz
// is the single point that:
//
//  1. Accepts requests Envoy has already authenticated (an OIDC IdP JWT
//     via jwt_authn). The forwarded x-jwt-payload header carries the
//     verified claims.
//  2. Calls OpenFGA via a cached Checker for every request that carries an
//     identity. FGA is the only authority for a per-RPC decision there.
//     Item 4 is the one exception, and it names its reason.
//  3. Treats a capability-grant JWT (X-Capability-Grant header) presented
//     ALONGSIDE an identity as a constraint on the request, never as an
//     authority for it: such a grant must verify, be bound to the calling
//     subject and tenant, and cover the requested method, or the request is
//     denied. It can only narrow what FGA already permits.
//  4. Accepts a daemon-minted task grant presented as the SOLE credential of
//     a dispatched component, which holds nothing standing (ADR-0016
//     decision 2). The grant's own claims are the authority there, because the
//     daemon already made the FGA decision at dispatch and ext-authz cannot
//     re-ask it. See tryTaskGrantAuth for the full reasoning (gibson#1605).
//  5. On allow, emits the canonical x-gibson-identity-* header set
//     to the upstream daemon. Headers are NOT HMAC-signed — the
//     Envoy↔daemon channel is SPIFFE-pinned mTLS.
//  6. Derives a signed-in person's tenant from their token's verified
//     Zitadel org, via OrgTenants (ADR-0093 decision 4) — never from a
//     client-supplied x-gibson-tenant header, which is refused outright
//     for an OIDC-user identity. A service account acting cross-tenant
//     (credential_type=client-credentials) still names its tenant via the
//     header, gated on platform_operator (unchanged).
//
// Spec: unified-identity-and-authorization Phase 2.
package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"

	"github.com/zeroroot-ai/gibson/internal/server/extauthz/cgjwt"
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/fga"
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/headers"
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/orgtenant"
	"github.com/zeroroot-ai/sdk/capabilitygrant"
)

// Constant body strings for deny responses. NEVER leak internal
// error detail across the trust boundary.
const (
	bodyPermissionDenied = "permission denied"
	bodyUnavailable      = "authorization service unavailable"
	bodyUnauthenticated  = "unauthenticated"
)

// Header names ext-authz reads from the inbound request.
const (
	headerJWTPayload      = "x-jwt-payload"
	headerCapabilityGrant = "x-capability-grant"
	headerTenantHint      = "x-gibson-tenant"
)

// Config configures NewEnvoyAuthzServer at construction.
type Config struct {
	// Cache is the cached FGA checker (required).
	Cache *fga.CachedChecker

	// CGJWT is the capability-grant verifier. Every request goes through
	// FGA whether or not it is set; the verifier decides whether a
	// presented capability grant is accepted as a constraint on the
	// request. Optional — when nil, a presented daemon-minted grant is
	// not verifiable here and is ignored (FGA still decides).
	CGJWT *cgjwt.Verifier

	// Component verifies a component's self-signed per-RPC CG-JWT against the
	// daemon's per-kid key descriptor (ADR-0045). Optional — when nil, a
	// request bearing only an x-capability-grant component token and no Zitadel
	// JWT is unauthenticated. When set, such a request is authenticated as the
	// daemon-asserted principal and authorized by the normal per-method FGA
	// check.
	Component *cgjwt.ComponentVerifier

	// Logger for structured events. Required.
	Logger *slog.Logger

	// IssuerAllowlist is the set of acceptable values for the JWT `iss`
	// claim (security-hardening R13). Tokens whose iss does not match
	// any entry are rejected with PermissionDenied. Optional in tests
	// (an empty list disables the check); production main always sets it.
	IssuerAllowlist []string
	// HumanClientIDs is the set of OIDC client ids that human sign-in flows
	// use (the dashboard application). A token whose `client_id` (or
	// `azp`) is one of them was issued to a person and carries a session
	// the gate can revoke. A token issued to any other client is a machine
	// credential. Zitadel writes a machine user's client_credentials token
	// with client_id = the user's name and sub = its numeric id, so the two
	// never match; without this set every scripted caller (the SDK, the
	// CLI, CI, the hosted smokes) was classed as a human and denied by the
	// session gate. Optional: empty keeps the client_id == sub rule alone.
	HumanClientIDs []string

	// OrgTenants maps a signed-in person's verified Zitadel org (the
	// urn:zitadel:iam:user:resourceowner:id claim) to their tenant
	// (ADR-0093 decision 4). Required — NewEnvoyAuthzServer panics without
	// it, the same as a nil Cache. A person's tenant comes ONLY from this
	// resolver; a client-supplied x-gibson-tenant header is refused outright
	// for an OIDC-user identity.
	OrgTenants OrgTenantResolver
}

// OrgTenantResolver maps a verified Zitadel org id to a tenant id. See
// internal/server/extauthz/orgtenant.Resolver for the production
// implementation (a cached lookup against the daemon).
type OrgTenantResolver interface {
	TenantForOrg(ctx context.Context, orgID string) (string, error)
}

// EnvoyAuthzServer implements envoy.service.auth.v3.AuthorizationServer.
type EnvoyAuthzServer struct {
	authv3.UnimplementedAuthorizationServer
	cache      *fga.CachedChecker
	cgjwt      *cgjwt.Verifier
	component  *cgjwt.ComponentVerifier
	log        *slog.Logger
	issuers    map[string]struct{} // empty ⇒ issuer check disabled (tests only)
	humans     map[string]struct{} // OIDC client ids of human sign-in flows; empty ⇒ client_id == sub rule alone
	orgTenants OrgTenantResolver
}

// NewEnvoyAuthzServer constructs an EnvoyAuthzServer. cache, logger and
// orgTenants are required; cgjwt may be nil.
func NewEnvoyAuthzServer(cfg Config) *EnvoyAuthzServer {
	if cfg.Cache == nil {
		panic("server.NewEnvoyAuthzServer: Cache required")
	}
	if cfg.Logger == nil {
		panic("server.NewEnvoyAuthzServer: Logger required")
	}
	if cfg.OrgTenants == nil {
		panic("server.NewEnvoyAuthzServer: OrgTenants required")
	}
	issuers := make(map[string]struct{}, len(cfg.IssuerAllowlist))
	for _, iss := range cfg.IssuerAllowlist {
		iss = strings.TrimSpace(iss)
		if iss == "" {
			continue
		}
		issuers[iss] = struct{}{}
	}
	humans := make(map[string]struct{}, len(cfg.HumanClientIDs))
	for _, c := range cfg.HumanClientIDs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		humans[c] = struct{}{}
	}
	return &EnvoyAuthzServer{
		cache:      cfg.Cache,
		cgjwt:      cfg.CGJWT,
		component:  cfg.Component,
		log:        cfg.Logger,
		issuers:    issuers,
		humans:     humans,
		orgTenants: cfg.OrgTenants,
	}
}

// Check implements envoy.service.auth.v3.Authorization/Check.
func (s *EnvoyAuthzServer) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	method := extractMethod(req)
	httpHeaders := req.GetAttributes().GetRequest().GetHttp().GetHeaders()

	tok, err := identityFromJWTPayload(httpHeaders, s.humans)
	if err != nil {
		// No Zitadel JWT. A component (agent/tool/plugin) authenticates instead
		// with its self-signed Capability-Grant JWT in x-capability-grant, with
		// no Authorization at all (ADR-0045). Try that path; if it handles the
		// request (verified component → FGA decision, or a present-but-invalid
		// component token → hard fail) return its response. Otherwise fall
		// through to the unauthenticated deny.
		// A dispatched component holds ONLY its per-dispatch task grant
		// (ADR-0016 decision 2, gibson#1605). That path is tried first: the
		// two credentials share the header and are told apart by the token's
		// typ, so neither can be mistaken for the other.
		if resp, handled := s.tryTaskGrantAuth(ctx, method, httpHeaders); handled {
			return resp, nil
		}
		if resp, handled := s.tryComponentAuth(ctx, method, httpHeaders); handled {
			return resp, nil
		}
		s.log.WarnContext(ctx, "ext-authz: unauthenticated", "method", method, "reason", err.Error())
		extauthzUnauthenticatedTotal.WithLabelValues(method).Inc()
		return denyResponse(codes.Unauthenticated, typev3.StatusCode_Unauthorized, bodyUnauthenticated), nil
	}
	id := tok.id
	// Issuer allowlist check (security-hardening R13). The verified JWT iss
	// claim (a URL like https://auth.zeroroot.local:30443) must match a
	// configured acceptable issuer; mismatches are denied with
	// PermissionDenied and emit a structured `extauthz.issuer_mismatch`
	// log event. An empty allowlist disables the check (tests only).
	//
	// Note: id.Issuer is the canonical wire constant ("oidc") that gets
	// forwarded to the daemon — NOT the URL we check here. The verified
	// URL lives only inside this handler. See ext-authz#26 for why these
	// two values must remain separate.
	if len(s.issuers) > 0 {
		if _, ok := s.issuers[tok.verifiedIss]; !ok {
			extauthzIssuerMismatchTotal.WithLabelValues(method).Inc()
			s.log.WarnContext(ctx, "extauthz.issuer_mismatch",
				"method", method,
				"subject", id.Subject,
				"presented_iss", tok.verifiedIss,
			)
			return denyResponse(codes.PermissionDenied, typev3.StatusCode_Forbidden, bodyPermissionDenied), nil
		}
	}
	s.log.DebugContext(ctx, "ext-authz: identity decoded",
		"method", method, "subject", id.Subject, "credential_type", id.CredentialType)

	// A person's tenant is a fact of their identity (ADR-0093 decision 4):
	// it comes from the verified Zitadel org their token names, resolved
	// against the daemon's org->tenant mapping — never from a client-
	// supplied header. This runs BEFORE the registry dispatch below, so
	// both self-mode/unauthenticated entries (the sign-in bootstrap window)
	// and rule-mode entries see the same resolved id.Tenant.
	if id.CredentialType == headers.CredentialOIDCUser {
		if httpHeaders[headerTenantHint] != "" {
			extauthzUserTenantHeaderRefusedTotal.Inc()
			s.log.WarnContext(ctx, "ext-authz: tenant header refused for a user",
				"method", method, "subject", id.Subject)
			return denyResponse(codes.PermissionDenied, typev3.StatusCode_Forbidden, bodyPermissionDenied), nil
		}
		tenant, tErr := s.userTenant(ctx, tok.orgID)
		switch {
		case errors.Is(tErr, orgtenant.ErrNoTenant):
			// No tenant. Allowed only for self and unauthenticated entries
			// (the Platform owner, and the sign-in window before a
			// tenant finishes provisioning) — the rule-mode switch below
			// denies an OIDC user with an empty id.Tenant.
		case tErr != nil:
			extauthzOrgTenantUnavailableTotal.Inc()
			s.log.ErrorContext(ctx, "ext-authz: org->tenant resolver unavailable",
				"method", method, "subject", id.Subject, "err", tErr)
			return denyResponse(codes.Unavailable, typev3.StatusCode_ServiceUnavailable, bodyUnavailable), nil
		default:
			id.Tenant = tenant
		}
	}

	// Early registry dispatch: look up the per-RPC authz entry. Self-mode
	// and unauthenticated entries by design may have no tenant (sign-in
	// bootstrap, liveness probes, the Platform owner) — running the
	// rule-mode switch below would deny every such call with "no tenant
	// derivable" before the registry-aware short-circuit in cache.Check
	// ever runs. Skip it for those modes.
	//
	// Spec: self-mode-authz Req 3 (post-hotfix re-ordering).
	regEntry, regOK := s.cache.LookupEntry(method)
	skipTenantResolution := regOK && (regEntry.Self || regEntry.Unauthenticated)

	if skipTenantResolution {
		// Self-mode and unauthenticated RPCs reach the FGA path directly.
		// id.Tenant is left as-is (may be empty) — downstream consumers
		// for these modes (handler self-scope by Subject) do not require
		// it. Capability-grant enforcement is also skipped — grant scoping
		// is per-tenant by definition.
		s.log.DebugContext(ctx, "ext-authz: skipping tenant resolution",
			"method", method, "entry_mode", entryModeName(regEntry))
		meta := requestMeta(id.Tenant) // may be empty; handler doesn't use it for self/unauth
		allowed, fgaErr := s.cache.Check(ctx, method, id, meta)
		if fgaErr != nil {
			extauthzFGAUnavailableTotal.Inc()
			s.log.ErrorContext(ctx, "ext-authz: FGA unavailable", "method", method, "err", fgaErr)
			return denyResponse(codes.Unavailable, typev3.StatusCode_ServiceUnavailable, bodyUnavailable), nil
		}
		if !allowed {
			extauthzDeniedTotal.WithLabelValues(method).Inc()
			s.log.InfoContext(ctx, "ext-authz: denied",
				"method", method, "subject", id.Subject, "entry_mode", entryModeName(regEntry))
			return denyResponse(codes.PermissionDenied, typev3.StatusCode_Forbidden, bodyPermissionDenied), nil
		}
		// Session gate: run for OIDC-user requests even on self-mode paths.
		// Unauthenticated entries (e.g. liveness probes) carry no identity and
		// checkSessionGate is a no-op for non-oidc-user credential types.
		//
		// id.Tenant was resolved above from the token's verified Zitadel org
		// (ADR-0093 decision 4) and may be empty — a person with no tenant
		// yet (the Platform owner, or the sign-in window before provisioning
		// finishes) gates on the user-scoped active_session relation instead
		// of a per-tenant one. Either way the gate can only deny.
		if gateResp, _ := s.checkSessionGate(ctx, method, id, id.Tenant); gateResp != nil {
			extauthzDeniedTotal.WithLabelValues(method).Inc()
			return gateResp, nil
		}
		id.IssuedAt = time.Now().UTC()
		extauthzAllowedTotal.WithLabelValues(method).Inc()
		s.log.DebugContext(ctx, "ext-authz: allowed (self/unauthenticated mode)",
			"method", method, "subject", id.Subject, "entry_mode", entryModeName(regEntry))
		return okResponse(headers.Emit(id)), nil
	}

	switch {
	case id.CredentialType == headers.CredentialOIDCUser:
		// id.Tenant was already resolved above from the token's verified
		// Zitadel org (ADR-0093 decision 4). A user with no tenant cannot
		// be authorized for a rule-mode RPC — the tenant IS the FGA object
		// these rules derive from.
		if id.Tenant == "" {
			extauthzTenantMissingTotal.Inc()
			s.log.WarnContext(ctx, "ext-authz: user has no tenant",
				"method", method, "subject", id.Subject)
			return denyResponse(codes.PermissionDenied, typev3.StatusCode_Forbidden, bodyPermissionDenied), nil
		}
	case httpHeaders[headerTenantHint] != "" && id.CredentialType == headers.CredentialClientCredentials:
		// Case 2, unchanged: a service account acting cross-tenant (e.g.
		// tenant-operator pruning a deleted tenant) names the tenant via
		// the header and must hold platform_operator on
		// system_tenant:_system, verified by a direct FGA query.
		headerTenant := httpHeaders[headerTenantHint]
		allowed, fgaErr := s.cache.CheckPlatformOperator(ctx, id.Subject)
		if fgaErr != nil || !allowed {
			extauthzTenantCrossTenantDenied.Inc()
			s.log.WarnContext(ctx, "ext-authz: cross-tenant denied — no platform_operator relation",
				"method", method, "subject", id.Subject, "header_tenant", headerTenant)
			return denyResponse(codes.PermissionDenied, typev3.StatusCode_Forbidden, bodyPermissionDenied), nil //nolint:nilerr // an FGA error denies via CheckResponse, not a Go error; every deny path in this handler returns a nil Go error
		}
		id.Tenant = headerTenant
	default:
		// Neither an OIDC user's resolved tenant nor a service account's
		// header tenant is present.
		extauthzTenantMissingTotal.Inc()
		s.log.WarnContext(ctx, "ext-authz: no tenant derivable",
			"method", method, "subject", id.Subject)
		return denyResponse(codes.PermissionDenied, typev3.StatusCode_Forbidden, bodyPermissionDenied), nil
	}

	// id.Tenant is already resolved above and is what object resolvers
	// (tenant_from_identity deriver) scope on.
	meta := requestMeta(id.Tenant)

	// A capability grant constrains a request; it never authorizes one.
	// When the request carries one it must verify, be bound to the calling
	// subject and tenant, and cover this method — otherwise the request is
	// denied here. Whatever survives is still decided by FGA below.
	if cgToken := extractCapabilityGrant(httpHeaders); cgToken != "" && s.cgjwt != nil {
		if denied := s.enforceCapabilityGrant(ctx, method, id, cgToken); denied != nil {
			extauthzDeniedTotal.WithLabelValues(method).Inc()
			return denied, nil
		}
	}

	// FGA path — the single authority for every per-RPC decision.
	allowed, fgaErr := s.cache.Check(ctx, method, id, meta)
	if fgaErr != nil {
		extauthzFGAUnavailableTotal.Inc()
		s.log.ErrorContext(ctx, "ext-authz: FGA unavailable", "method", method, "err", fgaErr)
		return denyResponse(codes.Unavailable, typev3.StatusCode_ServiceUnavailable, bodyUnavailable), nil
	}
	if !allowed {
		extauthzDeniedTotal.WithLabelValues(method).Inc()
		s.log.InfoContext(ctx, "ext-authz: denied",
			"method", method, "subject", id.Subject, "tenant", id.Tenant)
		return denyResponse(codes.PermissionDenied, typev3.StatusCode_Forbidden, bodyPermissionDenied), nil
	}

	// Session gate: applies after the per-RPC FGA check for OIDC-user requests.
	// Machine principals (service accounts, capability-grant components) are exempt —
	// checkSessionGate is a no-op for non-oidc-user credential types.
	if gateResp, _ := s.checkSessionGate(ctx, method, id, id.Tenant); gateResp != nil {
		extauthzDeniedTotal.WithLabelValues(method).Inc()
		return gateResp, nil
	}

	id.IssuedAt = time.Now().UTC()
	extauthzAllowedTotal.WithLabelValues(method).Inc()
	s.log.DebugContext(ctx, "ext-authz: allowed via FGA",
		"method", method, "subject", id.Subject, "tenant", id.Tenant)
	return okResponse(headers.Emit(id)), nil
}

// nowUTC is the allow-time stamp emitted as HeaderIssuedAt.
func nowUTC() time.Time { return time.Now().UTC() }

// tryComponentAuth authenticates + authorizes a request that carries a
// component's self-signed Capability-Grant JWT in x-capability-grant and no
// Zitadel JWT (ADR-0045 / gibson#648). It returns (resp, true) when it owns the
// decision, or (nil, false) when there is no component verifier or no component
// token — leaving the caller to fall through to the unauthenticated deny.
//
// The component token proves only key-possession; identity (the typed FGA
// principal + tenant) comes from the daemon's per-kid descriptor, never the
// token's own claims. Authorization is the SAME per-method FGA check used for
// human and S2S callers — there is no allowed_rpcs short-circuit here; FGA is
// the boundary.
func (s *EnvoyAuthzServer) tryComponentAuth(ctx context.Context, method string, httpHeaders map[string]string) (*authv3.CheckResponse, bool) {
	if s.component == nil {
		return nil, false
	}
	token := extractCapabilityGrant(httpHeaders)
	if token == "" {
		return nil, false
	}

	// Bind the token to this exact request: Verify refuses a token whose
	// `method` claim does not match the request method (gibson#1246).
	cid, err := s.component.Verify(ctx, token, method)
	if err != nil {
		// A present-but-invalid component token is a hard authentication
		// failure — never fall through to other auth paths.
		extauthzCGJWTRejectedTotal.WithLabelValues("component_invalid").Inc()
		s.log.WarnContext(ctx, "ext-authz: component cg-jwt invalid", "method", method, "err", err)
		return denyResponse(codes.Unauthenticated, typev3.StatusCode_Unauthorized, bodyUnauthenticated), true
	}

	id := headers.Identity{
		Subject:        cid.Principal, // typed FGA principal ref, used verbatim as the FGA user
		Issuer:         headers.IssuerCapabilityGrant,
		CredentialType: headers.CredentialCapabilityGrant,
		Tenant:         cid.Tenant, // daemon-asserted; the x-gibson-tenant header is NOT trusted here
		// The component's own scope, from the signature-verified
		// component_scope claim — httpHeaders is deliberately not consulted.
		// A component that could name its own scope could name any
		// component's, and the component_from_identity object deriver
		// authorizes against exactly this value.
		ComponentScope: cid.ComponentScope,
	}
	allowed, fgaErr := s.cache.Check(ctx, method, id, requestMeta(id.Tenant))
	if fgaErr != nil {
		extauthzFGAUnavailableTotal.Inc()
		s.log.ErrorContext(ctx, "ext-authz: FGA unavailable (component)", "method", method, "err", fgaErr)
		return denyResponse(codes.Unavailable, typev3.StatusCode_ServiceUnavailable, bodyUnavailable), true
	}
	if !allowed {
		extauthzDeniedTotal.WithLabelValues(method).Inc()
		s.log.InfoContext(ctx, "ext-authz: denied (component)",
			"method", method, "principal", id.Subject, "tenant", id.Tenant)
		return denyResponse(codes.PermissionDenied, typev3.StatusCode_Forbidden, bodyPermissionDenied), true
	}

	id.IssuedAt = time.Now().UTC()
	extauthzAllowedTotal.WithLabelValues(method).Inc()
	s.log.DebugContext(ctx, "ext-authz: allowed (component CG-JWT)",
		"method", method, "principal", id.Subject, "tenant", id.Tenant, "sub", cid.Subject)
	return okResponse(headers.Emit(id)), true
}

// enforceCapabilityGrant validates a capability grant presented alongside a
// primary identity. It returns nil when the grant is acceptable (the request
// then proceeds to the FGA decision) and a deny response when it is not.
//
// A grant is NEVER an authorization authority: it cannot make FGA's answer
// more permissive, and it is not consulted for an allow. It is only able to
// take a request away, which is why every failure below is a deny:
//
//   - it does not verify (bad signature, unknown key, expired, malformed) —
//     a presented credential that cannot be validated is never ignored;
//   - it names a different tenant than the request resolved to;
//   - it is not bound to the calling subject. A grant is minted for one
//     principal; presenting somebody else's grant is not a use of it;
//   - it does not cover the requested method.
//
// The subject binding is what stops a leaked grant (task payload, log line,
// low-privilege component) from being replayed by any other member of the
// same tenant.
func (s *EnvoyAuthzServer) enforceCapabilityGrant(
	ctx context.Context,
	method string,
	id headers.Identity,
	token string,
) *authv3.CheckResponse {
	claims, err := s.cgjwt.Verify(ctx, token)
	if err != nil {
		switch {
		case errors.Is(err, capabilitygrant.ErrExpired):
			extauthzCGJWTRejectedTotal.WithLabelValues("expired").Inc()
		case errors.Is(err, capabilitygrant.ErrSignature):
			extauthzCGJWTRejectedTotal.WithLabelValues("signature").Inc()
		case errors.Is(err, capabilitygrant.ErrUnknownKey):
			extauthzCGJWTRejectedTotal.WithLabelValues("unknown_key").Inc()
		case errors.Is(err, capabilitygrant.ErrClaimsInvalid):
			extauthzCGJWTRejectedTotal.WithLabelValues("claims_invalid").Inc()
		default:
			extauthzCGJWTRejectedTotal.WithLabelValues("other").Inc()
		}
		s.log.WarnContext(ctx, "ext-authz: capability grant invalid",
			"method", method, "subject", id.Subject, "err", err)
		return denyResponse(codes.PermissionDenied, typev3.StatusCode_Forbidden, bodyPermissionDenied)
	}

	switch {
	case claims.Tenant.String() != id.Tenant:
		extauthzCGJWTRejectedTotal.WithLabelValues("tenant_mismatch").Inc()
		s.log.WarnContext(ctx, "ext-authz: capability grant tenant mismatch",
			"method", method, "grant_tenant", claims.Tenant.String(), "req_tenant", id.Tenant)
		return denyResponse(codes.PermissionDenied, typev3.StatusCode_Forbidden, bodyPermissionDenied)

	case claims.Subject == "" || claims.Subject != id.Subject:
		extauthzCGJWTRejectedTotal.WithLabelValues("subject_mismatch").Inc()
		s.log.WarnContext(ctx, "ext-authz: capability grant not bound to caller",
			"method", method, "grant_subject", claims.Subject, "req_subject", id.Subject,
			"mission", claims.MissionID, "task", claims.TaskID)
		return denyResponse(codes.PermissionDenied, typev3.StatusCode_Forbidden, bodyPermissionDenied)

	case !claims.AllowsMethod(method):
		extauthzCGJWTRejectedTotal.WithLabelValues("method_not_allowed").Inc()
		s.log.WarnContext(ctx, "ext-authz: capability grant does not cover method",
			"method", method, "subject", id.Subject, "task", claims.TaskID)
		return denyResponse(codes.PermissionDenied, typev3.StatusCode_Forbidden, bodyPermissionDenied)
	}

	extauthzCGJWTBoundTotal.WithLabelValues(method).Inc()
	s.log.DebugContext(ctx, "ext-authz: capability grant bound to caller; FGA decides",
		"method", method, "subject", id.Subject, "task", claims.TaskID)
	return nil
}

// verifiedToken is what identityFromJWTPayload extracts from the verified
// JWT payload Envoy forwards: the Identity ext-authz emits downstream, the
// raw verified `iss` URL, and the verified Zitadel org id (ADR-0093
// decision 4). id.Tenant is always empty here — a person's tenant is
// resolved separately, from orgID, never read directly off the token.
type verifiedToken struct {
	id headers.Identity
	// verifiedIss is the real `iss` URL, used by the caller for the
	// issuer-allowlist check (security-hardening R13) and audit logging —
	// never forwarded. Distinct from id.Issuer, which carries the
	// canonical wire constant ("oidc") the daemon SDK expects. See
	// ext-authz#26 for the regression that motivated this split.
	verifiedIss string
	// orgID is the urn:zitadel:iam:user:resourceowner:id claim: the
	// Zitadel org the signed-in person belongs to. Empty for a token that
	// carries no such claim (a pre-ADR-0093 session, or a non-OIDC-user
	// credential). It is meaningless for anything but an OIDC-user
	// identity — the tenant derivation in Check reads it only then.
	orgID string
}

// identityFromJWTPayload parses the verified-claims payload Envoy's
// jwt_authn filter forwards. We accept ONLY the configured OIDC IdP per
// Requirement 1: every primary identity in the system is an OIDC IdP
// JWT. SPIFFE/apikey paths are gone.
func identityFromJWTPayload(httpHeaders map[string]string, humanClients map[string]struct{}) (verifiedToken, error) {
	encoded := httpHeaders[headerJWTPayload]
	if encoded == "" {
		return verifiedToken{}, errors.New("missing x-jwt-payload (Envoy jwt_authn must populate)")
	}
	data, decErr := base64.RawURLEncoding.DecodeString(encoded)
	if decErr != nil {
		// Some encoders include padding.
		if data2, err2 := base64.URLEncoding.DecodeString(encoded); err2 == nil {
			data = data2
		} else {
			return verifiedToken{}, fmt.Errorf("x-jwt-payload base64 decode: %w", decErr)
		}
	}
	var claims struct {
		Iss      string `json:"iss"`
		Sub      string `json:"sub"`
		Aud      any    `json:"aud"`
		ClientID string `json:"client_id"`
		// Azp is the authorized party: the client the token was issued to.
		// Zitadel sets it on every token; client_id is read first and azp
		// stands in when client_id is absent.
		Azp string `json:"azp"`
		// ResourceOwnerID is the urn:zitadel:iam:user:resourceowner:id
		// claim: the Zitadel org the signed-in person belongs to (ADR-0093
		// decision 4). Present on the access token when the client
		// requested the urn:zitadel:iam:user:resourceowner scope. This is
		// the ONLY source of a person's tenant — ext-authz resolves it
		// against the daemon's org->tenant mapping. There is no
		// client-asserted tenant claim (the former gibson:tenant / tenant
		// claims and their Zitadel Action are gone; nothing ever produced
		// them).
		ResourceOwnerID string `json:"urn:zitadel:iam:user:resourceowner:id"`
		// Iat is the standard JWT issued-at claim (Unix seconds). Carried
		// for the ext-authz-local instant-revocation condition
		// (token_iat > revoked_at; gibson#627), NOT for the downstream
		// freshness header. OIDC and client-credentials tokens from the
		// configured IdP always include it; absence ⇒ zero ⇒ treated as
		// the oldest possible token (fail-closed once a revocation lands).
		Iat int64 `json:"iat"`
	}
	if jerr := json.Unmarshal(data, &claims); jerr != nil {
		return verifiedToken{}, fmt.Errorf("x-jwt-payload JSON: %w", jerr)
	}
	if claims.Sub == "" {
		return verifiedToken{}, errors.New("x-jwt-payload: missing sub")
	}

	credType := credentialTypeFor(claims.Sub, claims.ClientID, claims.Azp, humanClients)

	// Subject derivation: always use the JWT sub claim (numeric Zitadel
	// subject ID). This is the canonical-numeric-sub requirement
	// (zero-trust-hardening Req 3.1). The previous behaviour of swapping
	// preferred_username for service-account tokens has been removed; the
	// numeric sub is the single authoritative identifier for all token types.
	//
	// Downstream FGA tuples are seeded with numeric subs by fga-init.
	// The dashboard's verifyZitadelBearer already compares on numeric sub
	// (populated from gibson-sa-identity-map by the resolve-sa-identity-map
	// init container). No downstream change is required.
	subject := claims.Sub

	// Per security-hardening R13, the issuer allowlist check belongs in
	// ext-authz (the caller verifies claims.Iss against the configured
	// EXT_AUTHZ_ZITADEL_ISSUER allowlist before any allow path runs).
	// But the forwarded x-gibson-identity-issuer header MUST be the
	// canonical wire constant `auth.IssuerOIDC` ("oidc"), because the SDK's
	// `auth/headers.go` accepts only that closed enum and rejects raw
	// issuer URLs with `unknown issuer`. A previous version of this code
	// forwarded claims.Iss verbatim, which broke every dashboard request
	// for 10 days (ext-authz#26). The verified iss URL is returned
	// separately for the allowlist check + audit logging.
	id := headers.Identity{
		Subject:        subject,
		Issuer:         headers.IssuerOIDC,
		CredentialType: credType,
		// Tenant is deliberately left empty here. It is resolved in Check
		// from orgID, against the daemon's org->tenant mapping — never
		// read directly off the token (ADR-0093 decision 4).
	}
	// Carry the token's iat for the instant-revocation condition
	// (gibson#627). Left as the zero time when the token has no iat, which
	// the condition treats as the oldest possible token (fail-closed).
	if claims.Iat > 0 {
		id.TokenIssuedAt = time.Unix(claims.Iat, 0).UTC()
	}
	return verifiedToken{id: id, verifiedIss: claims.Iss, orgID: claims.ResourceOwnerID}, nil
}

// credentialTypeFor decides whether a token was issued to a person or to a
// machine. Two rules, either one makes it a machine credential:
//
//  1. client_id == sub. The shape of a token minted to a client that is its
//     own subject.
//  2. The client the token was issued to (client_id, or azp when client_id
//     is absent) is not one of the human sign-in clients the operator
//     configured. Zitadel writes a machine user's client_credentials token
//     with client_id = the user's name and sub = its numeric id, so rule 1
//     never fires for it; rule 2 does, because the only clients that mint
//     tokens for people are the ones the chart names.
//
// With no human clients configured only rule 1 applies, which is the
// behaviour before gibson#133: every scripted caller read as a person.
func credentialTypeFor(sub, clientID, azp string, humanClients map[string]struct{}) string {
	if clientID != "" && clientID == sub {
		return "client-credentials"
	}
	client := clientID
	if client == "" {
		client = azp
	}
	if client != "" && len(humanClients) > 0 {
		if _, human := humanClients[client]; !human {
			return "client-credentials"
		}
	}
	return "oidc-user"
}

func extractCapabilityGrant(httpHeaders map[string]string) string {
	v := httpHeaders[headerCapabilityGrant]
	if v == "" {
		return ""
	}
	// Strip optional "Bearer " prefix (the spec recommends bare token
	// in this header but tolerate Bearer for caller convenience).
	if strings.HasPrefix(strings.ToLower(v), "bearer ") {
		return strings.TrimSpace(v[7:])
	}
	return v
}

func extractMethod(req *authv3.CheckRequest) string {
	if req == nil {
		return ""
	}
	return req.GetAttributes().GetRequest().GetHttp().GetPath()
}

// checkSessionGate evaluates the active_session FGA gate for a human
// JWT-bearing request (gibson#627 slice 3). It is called on every code path
// that would otherwise emit an allow response for an OIDC-user identity.
//
// Gate applicability:
//   - Only oidc-user credentials carry a session that can be revoked via
//     RevokeUserSessions. Machine principals (client-credentials,
//     capability-grant, platform-operator) are exempt — they are revoked at the
//     key/credential level, not the session level.
//   - When the request names a tenant, the gate checks the per-tenant
//     active_session relation (`type tenant`). id.Tenant is the tenant Check
//     already resolved from the token's verified Zitadel org (ADR-0093
//     decision 4) — the same value on both the self-mode and rule-mode
//     paths now, never a client-supplied header. A missing or absent tuple
//     fails closed.
//   - When the request names NO tenant at all (the sign-in bootstrap window),
//     the gate checks the USER-SCOPED active_session relation (`type user`,
//     gibson#1244) via CheckUserSession. That path is allow-on-absent (a
//     genuinely-first sign-in that has no user-scoped tuple yet must still pass,
//     or sign-in would be unrecoverable) and deny-on-revoked (a caller whose
//     user-scoped tuple carries revoked_at at or after the token's iat is
//     denied — the exposure gibson#1244 closes). Tenant-less requests are no
//     longer passed through un-gated.
//   - Requires a non-zero TokenIssuedAt (the token's iat) on BOTH paths. Zitadel
//     always includes iat; a zero value means the JWT is malformed or pre-dates
//     the condition. Treat as the oldest possible token (fail-closed: deny).
//
// Returns (nil, nil) when the gate is not applicable (machine principal) or
// allows (transparent — the caller proceeds). Returns (denyResponse, nil) when
// the gate fires (missing iat, revoked, or — on the tenant-scoped path — absent
// tuple), or on infrastructure error with Unavailable status.
func (s *EnvoyAuthzServer) checkSessionGate(
	ctx context.Context,
	method string,
	id headers.Identity,
	tenant string,
) (*authv3.CheckResponse, error) {
	// Only apply to OIDC users (human JWT sessions).
	if id.CredentialType != headers.CredentialOIDCUser {
		return nil, nil
	}
	// A zero TokenIssuedAt means the JWT carried no iat claim. Treat as the
	// oldest possible token (fail-closed: deny) on BOTH the tenant-scoped and
	// the tenant-less path. This case should be rare in practice because Zitadel
	// always includes iat in its JWTs.
	if id.TokenIssuedAt.IsZero() {
		s.log.WarnContext(ctx, "extauthz.session_gate: missing iat — denying (fail-closed)",
			"method", method, "subject", id.Subject, "tenant", tenant)
		return denyResponse(codes.PermissionDenied, typev3.StatusCode_Forbidden, bodyPermissionDenied), nil
	}
	// Tenant-less request (the sign-in bootstrap window). The per-tenant
	// active_session relation has no `type tenant` object to check here, so gate
	// on the USER-SCOPED active_session object instead of passing through
	// (gibson#1244). CheckUserSession allows a genuinely-first sign-in that has
	// no user-scoped tuple yet, and denies a revoked session.
	if tenant == "" {
		allowed, err := s.cache.CheckUserSession(ctx, id.Subject, id.TokenIssuedAt)
		if err != nil {
			extauthzFGAUnavailableTotal.Inc()
			s.log.ErrorContext(ctx, "ext-authz: FGA unavailable (user-scoped session gate)",
				"method", method, "subject", id.Subject, "err", err)
			return denyResponse(codes.Unavailable, typev3.StatusCode_ServiceUnavailable, bodyUnavailable), nil
		}
		if !allowed {
			s.log.InfoContext(ctx, "ext-authz: denied by user-scoped session gate",
				"method", method, "subject", id.Subject,
				"token_issued_at", id.TokenIssuedAt.UTC().Format(time.RFC3339))
			return denyResponse(codes.PermissionDenied, typev3.StatusCode_Forbidden, bodyPermissionDenied), nil
		}
		return nil, nil
	}
	allowed, err := s.cache.CheckActiveSession(ctx, id.Subject, tenant, id.TokenIssuedAt)
	if err != nil {
		extauthzFGAUnavailableTotal.Inc()
		s.log.ErrorContext(ctx, "ext-authz: FGA unavailable (session gate)",
			"method", method, "subject", id.Subject, "tenant", tenant, "err", err)
		return denyResponse(codes.Unavailable, typev3.StatusCode_ServiceUnavailable, bodyUnavailable), nil
	}
	if !allowed {
		s.log.InfoContext(ctx, "ext-authz: denied by session gate",
			"method", method, "subject", id.Subject, "tenant", tenant,
			"token_issued_at", id.TokenIssuedAt.UTC().Format(time.RFC3339))
		return denyResponse(codes.PermissionDenied, typev3.StatusCode_Forbidden, bodyPermissionDenied), nil
	}
	return nil, nil
}

// entryModeName returns a string tag identifying the authorization mode for
// a registry entry. Used in this server's structured-log `entry_mode` fields.
// Mirrors the unexported `entryMode` helper in the fga package; duplicated
// here to avoid widening the fga package's public surface.
func entryModeName(e fga.Entry) string {
	switch {
	case e.Self:
		return "self"
	case e.Unauthenticated:
		return "unauthenticated"
	default:
		return "rule"
	}
}

// requestMeta constructs the request-metadata map passed to FGA object
// resolvers, from the values ext-authz can actually establish: the resolved
// tenant.
//
// It carries no request-BODY fields, and cannot: Envoy's ext_authz check
// gives this service the request line and headers, not the decoded protobuf
// body. Rules whose object is derived from a body field (from_field /
// tenant_and_field) therefore have no object at this layer — resolveObject
// denies them rather than widening them to a tenant-wide object. Adding a
// header as a stand-in for a body field would be worse than either: the
// header the gateway authorized and the body the handler acts on could
// disagree.
func requestMeta(tenant string) map[string]string {
	return map[string]string{"tenant": tenant}
}

// userTenant resolves a signed-in person's tenant from their token's
// verified Zitadel org (ADR-0093 decision 4), through s.orgTenants. It
// returns orgtenant.ErrNoTenant when orgID is empty (a token with no org
// claim, e.g. a pre-ADR-0093 session) or when the org maps to no tenant —
// callers treat that as "no tenant," never as an error. Any other error
// means the resolver could not be asked and the caller must deny.
func (s *EnvoyAuthzServer) userTenant(ctx context.Context, orgID string) (string, error) {
	if orgID == "" {
		return "", orgtenant.ErrNoTenant
	}
	tenant, err := s.orgTenants.TenantForOrg(ctx, orgID)
	if err != nil {
		// %w keeps errors.Is(err, orgtenant.ErrNoTenant) working for the
		// caller's switch above.
		return "", fmt.Errorf("orgtenant: %w", err)
	}
	return tenant, nil
}

func okResponse(emitted httpHeader) *authv3.CheckResponse {
	var hdrOpts []*corev3.HeaderValueOption
	for k, vals := range emitted {
		if len(vals) == 0 {
			continue
		}
		hdrOpts = append(hdrOpts, &corev3.HeaderValueOption{
			Header: &corev3.HeaderValue{Key: strings.ToLower(k), Value: vals[0]},
		})
	}
	return &authv3.CheckResponse{
		Status:       &rpcstatus.Status{Code: int32(codes.OK)},
		HttpResponse: &authv3.CheckResponse_OkResponse{OkResponse: &authv3.OkHttpResponse{Headers: hdrOpts}},
	}
}

func denyResponse(grpcCode codes.Code, httpCode typev3.StatusCode, body string) *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{Code: int32(grpcCode), Message: body},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status: &typev3.HttpStatus{Code: httpCode},
				Body:   body,
			},
		},
	}
}

// httpHeader aliases net/http.Header so the okResponse helper does
// not need a direct import — keeps the package's third-party imports
// minimal.
type httpHeader = map[string][]string

// Prometheus metrics.
var (
	extauthzAllowedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "extauthz_allowed_total",
		Help: "ext-authz Check requests allowed.",
	}, []string{"method"})

	extauthzDeniedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "extauthz_denied_total",
		Help: "ext-authz Check requests denied.",
	}, []string{"method"})

	extauthzUnauthenticatedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "extauthz_unauthenticated_total",
		Help: "ext-authz Check requests rejected for missing/invalid identity.",
	}, []string{"method"})

	extauthzFGAUnavailableTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "extauthz_fga_unavailable_total",
		Help: "ext-authz Check requests denied because FGA was unreachable.",
	})

	extauthzTaskGrantAllowedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "extauthz_task_grant_allowed_total",
		Help: "ext-authz Check requests authorized by a daemon-minted task grant presented as the sole credential (gibson#1605).",
	}, []string{"method"})

	extauthzCGJWTBoundTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "extauthz_cgjwt_bound_total",
		Help: "ext-authz Check requests whose capability grant verified and bound to the caller. " +
			"The FGA decision still applies — a grant never authorizes on its own.",
	}, []string{"method"})

	extauthzCGJWTRejectedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "extauthz_cgjwt_rejected_total",
		Help: "ext-authz Check requests denied because the presented capability grant did not " +
			"verify, was not bound to the caller, or did not cover the method.",
	}, []string{"reason"})

	// Tenant-from-identity counters (ADR-0093 decision 4).
	extauthzUserTenantHeaderRefusedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "extauthz_user_tenant_header_refused_total",
		Help: "Requests denied because an OIDC-user identity presented an x-gibson-tenant header; " +
			"a person's tenant comes only from their token's verified Zitadel org.",
	})

	extauthzOrgTenantUnavailableTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "extauthz_org_tenant_unavailable_total",
		Help: "Requests denied because the org->tenant resolver was unreachable.",
	})

	extauthzTenantCrossTenantDenied = promauto.NewCounter(prometheus.CounterOpts{
		Name: "extauthz_tenant_cross_tenant_denied_total",
		Help: "Cross-tenant requests denied because caller lacks platform_operator relation.",
	})

	extauthzTenantMissingTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "extauthz_tenant_missing_total",
		Help: "Requests denied because no tenant could be derived from the identity or header.",
	})

	// Issuer allowlist counter (security-hardening R13).
	extauthzIssuerMismatchTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "extauthz_issuer_mismatch_total",
		Help: "Requests denied because the JWT iss claim is not in the configured allowlist.",
	}, []string{"method"})
)
