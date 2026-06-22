// Package server implements the Envoy ext_authz Authorization gRPC
// service. Per the unified-identity-and-authorization spec, ext-authz
// is the single point that:
//
//  1. Accepts requests Envoy has already authenticated (an OIDC IdP JWT
//     via jwt_authn). The forwarded x-jwt-payload header carries the
//     verified claims.
//  2. Optionally short-circuits FGA when the request carries a
//     capability-grant JWT (X-Capability-Grant header) whose
//     allowed_rpcs covers the requested method and whose tenant
//     matches.
//  3. Calls OpenFGA via a cached Checker for everything else.
//  4. On allow, emits the canonical x-gibson-identity-* header set
//     to the upstream daemon. Headers are NOT HMAC-signed — the
//     Envoy↔daemon channel is SPIFFE-pinned mTLS.
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

	// CGJWT is the capability-grant verifier. Optional — when nil,
	// CG-JWT short-circuit is disabled and every request goes through
	// FGA.
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
}

// EnvoyAuthzServer implements envoy.service.auth.v3.AuthorizationServer.
type EnvoyAuthzServer struct {
	authv3.UnimplementedAuthorizationServer
	cache     *fga.CachedChecker
	cgjwt     *cgjwt.Verifier
	component *cgjwt.ComponentVerifier
	log       *slog.Logger
	issuers   map[string]struct{} // empty ⇒ issuer check disabled (tests only)
}

// NewEnvoyAuthzServer constructs an EnvoyAuthzServer. cache and
// logger are required; cgjwt may be nil.
func NewEnvoyAuthzServer(cfg Config) *EnvoyAuthzServer {
	if cfg.Cache == nil {
		panic("server.NewEnvoyAuthzServer: Cache required")
	}
	if cfg.Logger == nil {
		panic("server.NewEnvoyAuthzServer: Logger required")
	}
	issuers := make(map[string]struct{}, len(cfg.IssuerAllowlist))
	for _, iss := range cfg.IssuerAllowlist {
		iss = strings.TrimSpace(iss)
		if iss == "" {
			continue
		}
		issuers[iss] = struct{}{}
	}
	return &EnvoyAuthzServer{
		cache:     cfg.Cache,
		cgjwt:     cfg.CGJWT,
		component: cfg.Component,
		log:       cfg.Logger,
		issuers:   issuers,
	}
}

// Check implements envoy.service.auth.v3.Authorization/Check.
func (s *EnvoyAuthzServer) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	method := extractMethod(req)
	httpHeaders := req.GetAttributes().GetRequest().GetHttp().GetHeaders()

	id, subjectSource, verifiedIss, err := identityFromJWTPayload(httpHeaders)
	if err != nil {
		// No Zitadel JWT. A component (agent/tool/plugin) authenticates instead
		// with its self-signed Capability-Grant JWT in x-capability-grant, with
		// no Authorization at all (ADR-0045). Try that path; if it handles the
		// request (verified component → FGA decision, or a present-but-invalid
		// component token → hard fail) return its response. Otherwise fall
		// through to the unauthenticated deny.
		if resp, handled := s.tryComponentAuth(ctx, method, httpHeaders); handled {
			return resp, nil
		}
		s.log.WarnContext(ctx, "ext-authz: unauthenticated", "method", method, "reason", err.Error())
		extauthzUnauthenticatedTotal.WithLabelValues(method).Inc()
		return denyResponse(codes.Unauthenticated, typev3.StatusCode_Unauthorized, bodyUnauthenticated), nil
	}
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
		if _, ok := s.issuers[verifiedIss]; !ok {
			extauthzIssuerMismatchTotal.WithLabelValues(method).Inc()
			s.log.WarnContext(ctx, "extauthz.issuer_mismatch",
				"method", method,
				"subject", id.Subject,
				"presented_iss", verifiedIss,
			)
			return denyResponse(codes.PermissionDenied, typev3.StatusCode_Forbidden, bodyPermissionDenied), nil
		}
	}
	// subjectSource is always "sub" (preferred_username swap removed per
	// zero-trust-hardening Req 3.1). Logged at debug for operator tracing.
	s.log.DebugContext(ctx, "ext-authz: identity decoded",
		"method", method, "subject", id.Subject, "subject_source", subjectSource, "credential_type", id.CredentialType)

	// Early registry dispatch: look up the per-RPC authz entry BEFORE the
	// tenant cross-check. Rule-mode entries derive their FGA object from a
	// tenant — so the cross-check is required for them. Self-mode and
	// unauthenticated entries by design have no tenant context (sign-in
	// bootstrap, liveness probes) — running the cross-check would deny
	// every such call with "no tenant derivable" before the registry-aware
	// short-circuit in cache.Check ever runs. Skip it for those modes.
	//
	// Spec: self-mode-authz Req 3 (post-hotfix re-ordering).
	regEntry, regOK := s.cache.LookupEntry(method)
	skipTenantResolution := regOK && (regEntry.Self || regEntry.Unauthenticated)

	// Tenant resolution: cross-check the x-gibson-tenant header against the
	// JWT-asserted tenant claim (zero-trust-hardening Req 4). Only runs for
	// rule-mode entries.
	//
	//   • JWT tenant + header match or header absent → use JWT tenant.
	//   • JWT tenant + header mismatch → PermissionDenied (log both values).
	//   • No JWT tenant + header present → require platform_operator on
	//     system_tenant:_system; allow if FGA confirms, deny otherwise.
	//   • Neither → deny (no derived tenant).
	jwtTenant := id.Tenant // populated by identityFromJWTPayload from gibson:tenant / tenant claim
	headerTenant := httpHeaders[headerTenantHint]

	if skipTenantResolution {
		// Self-mode and unauthenticated RPCs reach the FGA path directly.
		// id.Tenant is left as-is (may be empty) — downstream consumers
		// for these modes (handler self-scope by Subject) do not require
		// it. CG-JWT short-circuit also skipped — CG-JWT scoping is
		// per-tenant by definition.
		s.log.DebugContext(ctx, "ext-authz: skipping tenant resolution",
			"method", method, "entry_mode", entryModeName(regEntry))
		meta := buildRequestMeta(httpHeaders, id)
		meta["tenant"] = id.Tenant // may be empty; handler doesn't use it for self/unauth
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
		id.IssuedAt = time.Now().UTC()
		extauthzAllowedTotal.WithLabelValues(method).Inc()
		s.log.DebugContext(ctx, "ext-authz: allowed (self/unauthenticated mode)",
			"method", method, "subject", id.Subject, "entry_mode", entryModeName(regEntry))
		return okResponse(headers.Emit(id)), nil
	}

	switch {
	case jwtTenant != "" && headerTenant == "":
		// Normal case: JWT-only tenant — nothing to cross-check.
		id.Tenant = jwtTenant
	case jwtTenant != "" && headerTenant != "":
		if jwtTenant != headerTenant {
			extauthzTenantMismatchTotal.Inc()
			s.log.WarnContext(ctx, "ext-authz: tenant cross-check failed",
				"method", method, "subject", id.Subject,
				"jwt_tenant", jwtTenant, "header_tenant", headerTenant)
			return denyResponse(codes.PermissionDenied, typev3.StatusCode_Forbidden, bodyPermissionDenied), nil
		}
		id.Tenant = jwtTenant
	case jwtTenant == "" && headerTenant != "":
		// No JWT-asserted tenant + header tenant present. Two distinct paths:
		//
		//   1. OIDC user (credential_type=oidc-user). Standard sign-in flow.
		//      Zitadel's user JWTs deliberately do NOT carry a tenant claim —
		//      users may be members of multiple tenants and the active-tenant
		//      choice is a UI selection (gibson_active_tenant cookie →
		//      x-gibson-tenant header). Trust the header and let the
		//      rule-mode FGA Check on `tenant_from_identity` enforce
		//      membership: `(user:<sub>, member, tenant:<header>)`. Non-
		//      members deny at the FGA layer; tenant probing is closed by
		//      that membership check, not by the absence of a JWT claim.
		//
		//   2. Service account acting cross-tenant (credential_type=
		//      client-credentials). Genuinely cross-tenant SA path —
		//      tenant-operator pruning a deleted tenant, etc. Require the
		//      caller to hold `platform_operator` on
		//      `system_tenant:_system` via a direct FGA query.
		//
		// Spec: zero-trust-hardening Req 4 (post-fix); the original
		// platform_operator-only gate broke OIDC user sign-in for any
		// rule-mode RPC because it conflated the two cases.
		if id.CredentialType == headers.CredentialClientCredentials {
			allowed, fgaErr := s.cache.CheckPlatformOperator(ctx, id.Subject)
			if fgaErr != nil || !allowed {
				extauthzTenantCrossTenantDenied.Inc()
				s.log.WarnContext(ctx, "ext-authz: cross-tenant denied — no platform_operator relation",
					"method", method, "subject", id.Subject, "header_tenant", headerTenant)
				return denyResponse(codes.PermissionDenied, typev3.StatusCode_Forbidden, bodyPermissionDenied), nil
			}
		}
		// USER (no platform_operator gate) and SERVICE (passed gate) both
		// adopt the header tenant; the rule-mode FGA Check downstream
		// enforces membership for USER and the rule's relation for SERVICE.
		id.Tenant = headerTenant
	default:
		// Neither JWT tenant nor header present.
		extauthzTenantMissingTotal.Inc()
		s.log.WarnContext(ctx, "ext-authz: no tenant derivable",
			"method", method, "subject", id.Subject)
		return denyResponse(codes.PermissionDenied, typev3.StatusCode_Forbidden, bodyPermissionDenied), nil
	}

	meta := buildRequestMeta(httpHeaders, id)
	// id.Tenant is already resolved above; meta["tenant"] is set from
	// the header for use by object resolvers (tenant_from_identity deriver).
	meta["tenant"] = id.Tenant

	// Short-circuit FGA when a CG-JWT covers the method.
	if s.cgjwt != nil {
		if cgToken := extractCapabilityGrant(httpHeaders); cgToken != "" {
			claims, err := s.cgjwt.Verify(ctx, cgToken)
			if err == nil {
				if claims.Tenant.String() != id.Tenant {
					s.log.WarnContext(ctx, "ext-authz: cg-jwt tenant mismatch",
						"method", method, "cg_tenant", claims.Tenant.String(), "req_tenant", id.Tenant)
					extauthzCGJWTRejectedTotal.WithLabelValues("tenant_mismatch").Inc()
				} else if claims.AllowsMethod(method) {
					id.IssuedAt = time.Now().UTC()
					extauthzCGJWTAllowsTotal.WithLabelValues(method).Inc()
					s.log.DebugContext(ctx, "ext-authz: allowed via CG-JWT short-circuit",
						"method", method, "subject", id.Subject, "task", claims.TaskID)
					return okResponse(headers.Emit(id)), nil
				}
				// CG-JWT valid but does not cover this method —
				// fall through to FGA.
			} else {
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
				s.log.WarnContext(ctx, "ext-authz: cg-jwt invalid", "method", method, "err", err)
			}
		}
	}

	// FGA path.
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

	id.IssuedAt = time.Now().UTC()
	extauthzAllowedTotal.WithLabelValues(method).Inc()
	s.log.DebugContext(ctx, "ext-authz: allowed via FGA",
		"method", method, "subject", id.Subject, "tenant", id.Tenant)
	return okResponse(headers.Emit(id)), nil
}

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

	cid, err := s.component.Verify(ctx, token)
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
	}
	meta := buildRequestMeta(httpHeaders, id)
	meta["tenant"] = id.Tenant

	allowed, fgaErr := s.cache.Check(ctx, method, id, meta)
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

// identityFromJWTPayload parses the verified-claims payload Envoy's
// jwt_authn filter forwards. We accept ONLY the configured OIDC IdP per
// Requirement 1: every primary identity in the system is an OIDC IdP
// JWT. SPIFFE/apikey paths are gone.
//
// Returns the decoded Identity and a debug-only `subjectSource` string
// (always "sub" now that preferred_username swapping is removed per
// zero-trust-hardening Req 3.1). The source field is kept for log
// compatibility without affecting the deny/allow path.
// identityFromJWTPayload extracts the Identity that ext-authz forwards
// downstream PLUS the raw verified JWT iss URL. The two are intentionally
// distinct return values: the Identity.Issuer carries the canonical wire
// constant ("oidc") for the daemon's SDK contract; the verifiedIss is the
// real iss URL, used by the caller for the issuer-allowlist check
// (security-hardening R13) and for audit logging — never forwarded.
//
// See ext-authz#26 for the regression that motivated this split.
func identityFromJWTPayload(httpHeaders map[string]string) (id headers.Identity, subjectSource string, verifiedIss string, err error) {
	encoded := httpHeaders[headerJWTPayload]
	if encoded == "" {
		return headers.Identity{}, "", "", errors.New("missing x-jwt-payload (Envoy jwt_authn must populate)")
	}
	data, decErr := base64.RawURLEncoding.DecodeString(encoded)
	if decErr != nil {
		// Some encoders include padding.
		if data2, err2 := base64.URLEncoding.DecodeString(encoded); err2 == nil {
			data = data2
		} else {
			return headers.Identity{}, "", "", fmt.Errorf("x-jwt-payload base64 decode: %w", decErr)
		}
	}
	var claims struct {
		Iss      string `json:"iss"`
		Sub      string `json:"sub"`
		Aud      any    `json:"aud"`
		ClientID string `json:"client_id"`
		// The configured IdP may inject role claims such as
		// "urn:zitadel:iam:org:project:roles" or our custom tenant claim.
		// (The previous wire value was "zitadel"; the field name is IdP-specific.)
		GibsonTenant string `json:"gibson:tenant"`
		Tenant       string `json:"tenant"`
	}
	if jerr := json.Unmarshal(data, &claims); jerr != nil {
		return headers.Identity{}, "", "", fmt.Errorf("x-jwt-payload JSON: %w", jerr)
	}
	if claims.Sub == "" {
		return headers.Identity{}, "", "", errors.New("x-jwt-payload: missing sub")
	}

	credType := "oidc-user"
	if claims.ClientID != "" && claims.ClientID == claims.Sub {
		// Service-account JWT (client_credentials grant): sub == client_id.
		credType = "client-credentials"
	}

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
	subjectSource = "sub"

	tenant := claims.GibsonTenant
	if tenant == "" {
		tenant = claims.Tenant
	}

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
	id = headers.Identity{
		Subject:        subject,
		Issuer:         headers.IssuerOIDC,
		CredentialType: credType,
		Tenant:         tenant,
	}
	verifiedIss = claims.Iss
	return id, subjectSource, verifiedIss, nil
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

// buildRequestMeta constructs the request-metadata map passed to FGA object
// resolvers. The "tenant" key is intentionally left empty here — it is set
// by the caller (Check) after tenant cross-check resolution (Req 4).
func buildRequestMeta(httpHeaders map[string]string, id headers.Identity) map[string]string {
	_ = httpHeaders // retained in signature for future per-request fields
	_ = id
	return make(map[string]string, 2)
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

	extauthzCGJWTAllowsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "extauthz_cgjwt_allows_total",
		Help: "ext-authz Check requests allowed via capability-grant short-circuit.",
	}, []string{"method"})

	extauthzCGJWTRejectedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "extauthz_cgjwt_rejected_total",
		Help: "ext-authz Check requests with an invalid capability-grant JWT.",
	}, []string{"reason"})

	// Tenant cross-check counters (zero-trust-hardening Req 4).
	extauthzTenantMismatchTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "extauthz_tenant_mismatch_total",
		Help: "Requests denied because x-gibson-tenant header mismatches JWT-asserted tenant.",
	})

	extauthzTenantCrossTenantDenied = promauto.NewCounter(prometheus.CounterOpts{
		Name: "extauthz_tenant_cross_tenant_denied_total",
		Help: "Cross-tenant requests denied because caller lacks platform_operator relation.",
	})

	extauthzTenantMissingTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "extauthz_tenant_missing_total",
		Help: "Requests denied because no tenant could be derived from JWT or header.",
	})

	// Issuer allowlist counter (security-hardening R13).
	extauthzIssuerMismatchTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "extauthz_issuer_mismatch_total",
		Help: "Requests denied because the JWT iss claim is not in the configured allowlist.",
	}, []string{"method"})
)
