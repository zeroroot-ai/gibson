// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package server

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/golang-jwt/jwt/v5"
	openfga "github.com/openfga/go-sdk"
	fgaclient "github.com/openfga/go-sdk/client"
	"google.golang.org/grpc/codes"

	"github.com/zeroroot-ai/gibson/internal/server/extauthz/cgjwt"
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/fga"
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/headers"
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/orgtenant"
)

// encodePayload base64-encodes a JSON payload as Envoy's jwt_authn
// filter forwards via the x-jwt-payload header (raw URL encoding, no
// padding).
func encodePayload(t *testing.T, claims map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// fakeOrgTenantResolver is a test double for OrgTenantResolver (ADR-0093
// decision 4). By default it treats an org id of the form "org-<tenant>" as
// mapping to <tenant>, so a test can mint a token carrying
// "urn:zitadel:iam:user:resourceowner:id": "org-acme" and get "acme" back
// without a table per test, and any org id without that prefix is
// unmapped (orgtenant.ErrNoTenant). Set tenantFor for a custom mapping, or
// err for every call to fail the same way (orgtenant.ErrNoTenant for
// "unmapped", any other error for "resolver unavailable").
type fakeOrgTenantResolver struct {
	tenantFor func(orgID string) (string, error)
	err       error
}

func (f *fakeOrgTenantResolver) TenantForOrg(_ context.Context, orgID string) (string, error) {
	if f.tenantFor != nil {
		return f.tenantFor(orgID)
	}
	if f.err != nil {
		return "", f.err
	}
	if tenant, ok := strings.CutPrefix(orgID, "org-"); ok {
		return tenant, nil
	}
	return "", orgtenant.ErrNoTenant
}

// ---------------------------------------------------------------------------
// identityFromJWTPayload tests
// ---------------------------------------------------------------------------

// TestIdentityFromJWTPayload_SAToken_NumericSub verifies that service-account
// tokens always use the numeric sub as Subject, even when preferred_username
// is present (zero-trust-hardening Req 3.1: preferred_username swap removed).
func TestIdentityFromJWTPayload_SAToken_NumericSub(t *testing.T) {
	t.Parallel()
	const numericClientID = "267843291982000001"
	const username = "gibson-tenant-operator"

	hdrs := map[string]string{
		headerJWTPayload: encodePayload(t, map[string]any{
			"iss":                "https://zitadel.example",
			"sub":                numericClientID,
			"client_id":          numericClientID,
			"preferred_username": username,
		}),
	}

	tok, err := identityFromJWTPayload(hdrs, nil)
	if err != nil {
		t.Fatalf("identityFromJWTPayload: %v", err)
	}
	// sub is always used — preferred_username swap is removed.
	if tok.id.Subject != numericClientID {
		t.Errorf("Subject = %q, want numeric sub %q (preferred_username swap removed per Req 3.1)", tok.id.Subject, numericClientID)
	}
	if tok.id.CredentialType != "client-credentials" {
		t.Errorf("CredentialType = %q, want %q", tok.id.CredentialType, "client-credentials")
	}
}

// TestIdentityFromJWTPayload_SAToken_NoPreferredUsername — SA token without
// preferred_username still uses sub.
func TestIdentityFromJWTPayload_SAToken_NoPreferredUsername(t *testing.T) {
	t.Parallel()
	const sub = "12345"

	hdrs := map[string]string{
		headerJWTPayload: encodePayload(t, map[string]any{
			"iss":       "https://zitadel.example",
			"sub":       sub,
			"client_id": sub,
		}),
	}

	tok, err := identityFromJWTPayload(hdrs, nil)
	if err != nil {
		t.Fatalf("identityFromJWTPayload: %v", err)
	}
	if tok.id.Subject != sub {
		t.Errorf("Subject = %q, want %q", tok.id.Subject, sub)
	}
	if tok.id.CredentialType != "client-credentials" {
		t.Errorf("CredentialType = %q, want %q", tok.id.CredentialType, "client-credentials")
	}
}

// TestIdentityFromJWTPayload_UserTokenUsesSub — user OIDC tokens always use sub.
func TestIdentityFromJWTPayload_UserTokenUsesSub(t *testing.T) {
	t.Parallel()
	const userSub = "user-uuid-abc"

	hdrs := map[string]string{
		headerJWTPayload: encodePayload(t, map[string]any{
			"iss":                "https://zitadel.example",
			"sub":                userSub,
			"client_id":          "different-web-client-id",
			"preferred_username": "alice@example.com",
		}),
	}

	tok, err := identityFromJWTPayload(hdrs, nil)
	if err != nil {
		t.Fatalf("identityFromJWTPayload: %v", err)
	}
	if tok.id.Subject != userSub {
		t.Errorf("Subject = %q, want %q", tok.id.Subject, userSub)
	}
	if tok.id.CredentialType != "oidc-user" {
		t.Errorf("CredentialType = %q, want %q", tok.id.CredentialType, "oidc-user")
	}
}

// TestIdentityFromJWTPayload_ParsesIat — the token's iat claim is parsed into
// TokenIssuedAt (consumed ext-authz-locally for the instant-revocation
// condition, gibson#627), and is kept distinct from the freshness IssuedAt
// stamp (which is set later, at allow time, and emitted as HeaderIssuedAt).
func TestIdentityFromJWTPayload_ParsesIat(t *testing.T) {
	t.Parallel()
	const iat int64 = 1_700_000_000

	hdrs := map[string]string{
		headerJWTPayload: encodePayload(t, map[string]any{
			"iss": "https://zitadel.example",
			"sub": "user-uuid-abc",
			"iat": iat,
		}),
	}

	tok, err := identityFromJWTPayload(hdrs, nil)
	if err != nil {
		t.Fatalf("identityFromJWTPayload: %v", err)
	}
	if got := tok.id.TokenIssuedAt.Unix(); got != iat {
		t.Errorf("TokenIssuedAt = %d, want token iat %d", got, iat)
	}
	if tok.id.TokenIssuedAt.Location() != time.UTC {
		t.Errorf("TokenIssuedAt location = %v, want UTC", tok.id.TokenIssuedAt.Location())
	}
	// The freshness IssuedAt must NOT be populated from the token iat — it is
	// stamped to allow-time later in the request path, not here.
	if !tok.id.IssuedAt.IsZero() {
		t.Errorf("IssuedAt = %v, want zero (freshness stamp is set at allow time, not from iat)", tok.id.IssuedAt)
	}
}

// TestIdentityFromJWTPayload_NoIat — a token without an iat claim leaves
// TokenIssuedAt at the zero time (the revocation condition treats the zero
// time as the oldest possible token, i.e. fail-closed once a revocation lands).
func TestIdentityFromJWTPayload_NoIat(t *testing.T) {
	t.Parallel()
	hdrs := map[string]string{
		headerJWTPayload: encodePayload(t, map[string]any{
			"iss": "https://zitadel.example",
			"sub": "user-uuid-abc",
		}),
	}

	tok, err := identityFromJWTPayload(hdrs, nil)
	if err != nil {
		t.Fatalf("identityFromJWTPayload: %v", err)
	}
	if !tok.id.TokenIssuedAt.IsZero() {
		t.Errorf("TokenIssuedAt = %v, want zero time when iat absent", tok.id.TokenIssuedAt)
	}
}

// TestIdentityFromJWTPayload_MissingHeader — error on missing x-jwt-payload.
func TestIdentityFromJWTPayload_MissingHeader(t *testing.T) {
	t.Parallel()
	if _, err := identityFromJWTPayload(map[string]string{}, nil); err == nil {
		t.Fatal("identityFromJWTPayload: expected error on missing x-jwt-payload, got nil")
	}
}

// TestIdentityFromJWTPayload_MissingSub — error on payload present but no sub.
func TestIdentityFromJWTPayload_MissingSub(t *testing.T) {
	t.Parallel()
	hdrs := map[string]string{
		headerJWTPayload: encodePayload(t, map[string]any{
			"iss": "https://zitadel.example",
		}),
	}
	if _, err := identityFromJWTPayload(hdrs, nil); err == nil {
		t.Fatal("identityFromJWTPayload: expected error on missing sub, got nil")
	}
}

// TestUser_TenantClaimIgnored — legacy gibson:tenant / tenant claims (the
// dead path nothing in production ever produced — the former Zitadel Action
// never existed) are simply unknown JSON fields now: the identity carries no
// tenant and no org from them. A person's tenant comes ONLY from the
// urn:zitadel:iam:user:resourceowner:id claim, resolved by the org->tenant
// resolver (ADR-0093 decision 4).
func TestUser_TenantClaimIgnored(t *testing.T) {
	t.Parallel()
	hdrs := map[string]string{
		headerJWTPayload: encodePayload(t, map[string]any{
			"iss":           "https://zitadel.example",
			"sub":           "user-1",
			"gibson:tenant": "acme",
			"tenant":        "acme",
		}),
	}
	tok, err := identityFromJWTPayload(hdrs, nil)
	if err != nil {
		t.Fatalf("identityFromJWTPayload: %v", err)
	}
	if tok.id.Tenant != "" {
		t.Errorf("Identity.Tenant = %q, want empty (legacy tenant claims are ignored)", tok.id.Tenant)
	}
	if tok.orgID != "" {
		t.Errorf("orgID = %q, want empty (legacy tenant claims never populate the org)", tok.orgID)
	}
}

// ---------------------------------------------------------------------------
// Tenant cross-check tests (case 2: a service account acting cross-tenant,
// unchanged by ADR-0093 decision 4 — a service account still names its
// tenant via x-gibson-tenant, gated on platform_operator)
// ---------------------------------------------------------------------------

// tenantTestYAML is the shared registry fixture for the tenant-derivation
// tests below: one platform-operator sentinel method (case 2's gate), one
// SERVICE-only rule-mode method, one USER-only rule-mode method, and one
// USER-only self-mode method.
const tenantTestYAML = `entries:
  "/gibson.daemon.v1.PlatformOperatorService/Ping":
    relation: "platform_operator"
    object_type: "system_tenant"
    object_deriver: "system_tenant"
    allowed_identities:
      - PLATFORM_OPERATOR
  "/test.v1.S/Op":
    relation: "member"
    object_type: "tenant"
    object_deriver: "tenant_from_identity"
    allowed_identities:
      - SERVICE
  "/test.v1.S/UserOp":
    relation: "member"
    object_type: "tenant"
    object_deriver: "tenant_from_identity"
    allowed_identities:
      - USER
  "/test.v1.S/SelfOp":
    self: true
    allowed_identities:
      - USER
`

// buildServerForTenantTests builds a server with the shared tenantTestYAML
// registry and a fakeOrgTenantResolver that maps no org (an OIDC-user test
// that never presents an org claim keeps id.Tenant empty). Case 2 (service
// accounts) doesn't consult the org resolver at all, so this default is
// inert for those tests.
func buildServerForTenantTests(t *testing.T, fgaAllowed bool) *EnvoyAuthzServer {
	t.Helper()

	reg, err := fga.LoadRegistry([]byte(tenantTestYAML))
	if err != nil {
		t.Fatal(err)
	}

	mock := &tenantMockFGA{allowed: fgaAllowed}
	checker := fga.NewChecker(mock, reg)
	cachedChecker := fga.NewCachedChecker(checker, 0, 0)

	return NewEnvoyAuthzServer(Config{
		Cache:      cachedChecker,
		Logger:     newTestLogger(),
		OrgTenants: &fakeOrgTenantResolver{},
	})
}

// buildServerForOrgTenantTests is buildServerForTenantTests with an
// injectable OrgTenantResolver, for the ADR-0093 decision 4 tenant-derivation
// tests below.
func buildServerForOrgTenantTests(t *testing.T, fgaAllowed bool, resolver OrgTenantResolver) *EnvoyAuthzServer {
	t.Helper()
	reg, err := fga.LoadRegistry([]byte(tenantTestYAML))
	if err != nil {
		t.Fatal(err)
	}
	mock := &tenantMockFGA{allowed: fgaAllowed}
	checker := fga.NewChecker(mock, reg)
	cachedChecker := fga.NewCachedChecker(checker, 0, 0)
	return NewEnvoyAuthzServer(Config{
		Cache:      cachedChecker,
		Logger:     newTestLogger(),
		OrgTenants: resolver,
	})
}

func makeCheckRequest(t *testing.T, method string, jwtClaims map[string]any, tenantHeader string) *authv3.CheckRequest {
	t.Helper()
	hdrs := map[string]string{
		headerJWTPayload: encodePayload(t, jwtClaims),
	}
	if tenantHeader != "" {
		hdrs[headerTenantHint] = tenantHeader
	}
	return &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Path:    method,
					Headers: hdrs,
				},
			},
		},
	}
}

// TestTenantCrossCheck_PlatformOperatorAllowed — no org-derived tenant
// (SERVICE credential; the org resolver is never consulted for it) + header
// present + FGA confirms platform_operator → allowed.
func TestTenantCrossCheck_PlatformOperatorAllowed(t *testing.T) {
	t.Parallel()
	srv := buildServerForTenantTests(t, true) // FGA allows
	req := makeCheckRequest(t, "/test.v1.S/Op", map[string]any{
		"iss":       "https://zitadel.example",
		"sub":       "platform-op-id",
		"client_id": "platform-op-id",
	}, "some-tenant")

	// The cross-tenant branch first checks platform_operator on system_tenant:_system.
	// Our stub FGA returns allowed=true for that, so the overall request proceeds.
	// However the actual /test.v1.S/Op check also hits FGA and allows (stub=true).
	resp, err := srv.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	// With FGA always-allow stub, platform_operator check passes, then the method
	// check also passes (if the identity class matches). The SA is "client-credentials"
	// → SERVICE class, and /test.v1.S/Op allows SERVICE. Expect OK.
	if codes.Code(resp.GetStatus().GetCode()) != codes.OK {
		t.Errorf("expected OK for platform-operator cross-tenant, got %v: %s",
			resp.GetStatus().GetCode(), resp.GetStatus().GetMessage())
	}
}

// TestTenantCrossCheck_PlatformOperatorDenied — no org-derived tenant +
// header present + FGA denies platform_operator → PermissionDenied.
func TestTenantCrossCheck_PlatformOperatorDenied(t *testing.T) {
	t.Parallel()
	srv := buildServerForTenantTests(t, false) // FGA denies
	req := makeCheckRequest(t, "/test.v1.S/Op", map[string]any{
		"iss":       "https://zitadel.example",
		"sub":       "not-an-operator",
		"client_id": "not-an-operator",
	}, "some-tenant")

	resp, err := srv.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if codes.Code(resp.GetStatus().GetCode()) != codes.PermissionDenied {
		t.Errorf("expected PermissionDenied for cross-tenant non-operator, got %v", resp.GetStatus().GetCode())
	}
}

// TestSelfMode_NoTenant_Allows — the sign-in scenario. A USER token with no
// org claim at all (so the org resolver is never even asked — userTenant
// short-circuits on an empty orgID) calls a self-mode RPC. The early
// registry lookup detects entry.Self and skips the rule-mode tenant-missing
// deny; the request reaches cache.Check which short-circuits on Self and
// returns OK, and the session gate runs against the user-scoped object.
//
// Spec: self-mode-authz Req 4.6.
func TestSelfMode_NoTenant_Allows(t *testing.T) {
	t.Parallel()
	// fgaAllowed=true is required for the session gate (CheckUserSession) to
	// pass — the mock answers every relation the same way, including
	// active_session.
	srv := buildServerForTenantTests(t, true)
	req := makeCheckRequest(t, "/test.v1.S/SelfOp", map[string]any{
		"iss": "https://zitadel.example",
		"sub": "user-123",
		"iat": int64(1_700_000_100), // session gate requires iat; real Zitadel JWTs always include it
		// no client_id (USER token, not SA)
		// no org claim, no header
	}, "")

	resp, err := srv.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if codes.Code(resp.GetStatus().GetCode()) != codes.OK {
		t.Errorf("expected OK for self-mode RPC with no tenant context, got %v: %s",
			resp.GetStatus().GetCode(), resp.GetStatus().GetMessage())
	}
}

// ---------------------------------------------------------------------------
// Tenant derivation from the token's verified Zitadel org (ADR-0093
// decision 4): a person's tenant comes ONLY from their token's org, resolved
// against the daemon's org->tenant mapping via OrgTenantResolver — never
// from a client-supplied x-gibson-tenant header, and never from a JWT
// "tenant" / "gibson:tenant" claim (see TestUser_TenantClaimIgnored above).
// ---------------------------------------------------------------------------

// TestUser_TenantHeaderRefused — an OIDC user presenting x-gibson-tenant is
// refused outright on a rule-mode entry, even where the header would (if
// trusted) name the caller's own real, org-resolved tenant.
func TestUser_TenantHeaderRefused(t *testing.T) {
	t.Parallel()
	srv := buildServerForOrgTenantTests(t, true, &fakeOrgTenantResolver{})
	req := makeCheckRequest(t, "/test.v1.S/UserOp", map[string]any{
		"iss":                                   "https://zitadel.example",
		"sub":                                   "user-1",
		"iat":                                   time.Now().Unix(),
		"urn:zitadel:iam:user:resourceowner:id": "org-acme",
	}, "acme") // header names the caller's own real tenant — still refused

	resp, err := srv.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if codes.Code(resp.GetStatus().GetCode()) != codes.PermissionDenied { //nolint:gosec // controlled small value
		t.Errorf("expected PermissionDenied (tenant header refused for a user), got %v: %s",
			resp.GetStatus().GetCode(), resp.GetStatus().GetMessage())
	}
}

// TestUser_TenantHeaderRefused_SelfMode — the same refusal fires on a
// self-mode entry: the header is refused before the registry dispatch runs.
func TestUser_TenantHeaderRefused_SelfMode(t *testing.T) {
	t.Parallel()
	srv := buildServerForOrgTenantTests(t, true, &fakeOrgTenantResolver{})
	req := makeCheckRequest(t, "/test.v1.S/SelfOp", map[string]any{
		"iss":                                   "https://zitadel.example",
		"sub":                                   "user-1",
		"iat":                                   time.Now().Unix(),
		"urn:zitadel:iam:user:resourceowner:id": "org-acme",
	}, "acme")

	resp, err := srv.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if codes.Code(resp.GetStatus().GetCode()) != codes.PermissionDenied {
		t.Errorf("expected PermissionDenied (tenant header refused for a user, self-mode), got %v",
			resp.GetStatus().GetCode())
	}
}

// TestUser_TenantFromOrg — the normal sign-in shape: no header, the token's
// org resolves to the caller's tenant, FGA is asked about that tenant, and
// the emitted x-gibson-identity-tenant header carries it.
func TestUser_TenantFromOrg(t *testing.T) {
	t.Parallel()
	srv := buildServerForOrgTenantTests(t, true, &fakeOrgTenantResolver{})
	req := makeCheckRequest(t, "/test.v1.S/UserOp", map[string]any{
		"iss":                                   "https://zitadel.example",
		"sub":                                   "user-1",
		"iat":                                   time.Now().Unix(),
		"urn:zitadel:iam:user:resourceowner:id": "org-acme",
	}, "") // no header

	resp, err := srv.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if codes.Code(resp.GetStatus().GetCode()) != codes.OK { //nolint:gosec // controlled small value
		t.Fatalf("expected OK, got %v: %s", resp.GetStatus().GetCode(), resp.GetStatus().GetMessage())
	}
	var tenantHdr string
	for _, h := range resp.GetOkResponse().GetHeaders() {
		if h.GetHeader().GetKey() == headers.HeaderTenant {
			tenantHdr = h.GetHeader().GetValue()
		}
	}
	if tenantHdr != "acme" {
		t.Errorf("emitted tenant header = %q, want acme (resolved from org-acme)", tenantHdr)
	}
}

// TestUser_UnmappedOrg_RuleModeDenied — the token's org resolves to no
// tenant (an org that is not a tenant, or a tenant not yet provisioned) on a
// rule-mode entry: denied, the same as no tenant at all.
func TestUser_UnmappedOrg_RuleModeDenied(t *testing.T) {
	t.Parallel()
	srv := buildServerForOrgTenantTests(t, true, &fakeOrgTenantResolver{err: orgtenant.ErrNoTenant})
	req := makeCheckRequest(t, "/test.v1.S/UserOp", map[string]any{
		"iss":                                   "https://zitadel.example",
		"sub":                                   "user-1",
		"iat":                                   time.Now().Unix(),
		"urn:zitadel:iam:user:resourceowner:id": "org-platform",
	}, "")

	resp, err := srv.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if codes.Code(resp.GetStatus().GetCode()) != codes.PermissionDenied {
		t.Errorf("expected PermissionDenied (org maps to no tenant), got %v", resp.GetStatus().GetCode())
	}
}

// TestUser_UnmappedOrg_SelfModeAllowed — the same unmapped org on a
// self-mode entry (the Platform owner's shape): allowed, with an empty
// emitted tenant header.
func TestUser_UnmappedOrg_SelfModeAllowed(t *testing.T) {
	t.Parallel()
	srv := buildServerForOrgTenantTests(t, true, &fakeOrgTenantResolver{err: orgtenant.ErrNoTenant})
	req := makeCheckRequest(t, "/test.v1.S/SelfOp", map[string]any{
		"iss":                                   "https://zitadel.example",
		"sub":                                   "platform-owner",
		"iat":                                   time.Now().Unix(),
		"urn:zitadel:iam:user:resourceowner:id": "org-platform",
	}, "")

	resp, err := srv.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if codes.Code(resp.GetStatus().GetCode()) != codes.OK {
		t.Fatalf("expected OK (self-mode allows a person with no tenant), got %v: %s",
			resp.GetStatus().GetCode(), resp.GetStatus().GetMessage())
	}
	for _, h := range resp.GetOkResponse().GetHeaders() {
		if h.GetHeader().GetKey() == headers.HeaderTenant && h.GetHeader().GetValue() != "" {
			t.Errorf("emitted tenant header = %q, want empty (no tenant)", h.GetHeader().GetValue())
		}
	}
}

// TestUser_NoOrgClaim_RuleModeDenied — a token with no org claim at all
// (e.g. a pre-ADR-0093 session) on a rule-mode entry: denied. userTenant
// treats an empty orgID as ErrNoTenant, the same as an org that maps to
// nothing.
func TestUser_NoOrgClaim_RuleModeDenied(t *testing.T) {
	t.Parallel()
	srv := buildServerForOrgTenantTests(t, true, &fakeOrgTenantResolver{})
	req := makeCheckRequest(t, "/test.v1.S/UserOp", map[string]any{
		"iss": "https://zitadel.example",
		"sub": "user-1",
		"iat": time.Now().Unix(),
		// no resourceowner claim
	}, "")

	resp, err := srv.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if codes.Code(resp.GetStatus().GetCode()) != codes.PermissionDenied {
		t.Errorf("expected PermissionDenied (no org claim), got %v", resp.GetStatus().GetCode())
	}
}

// TestUser_ResolverError_Unavailable — a transport/daemon failure while
// resolving the org must deny with Unavailable, never fall through to "no
// tenant" or an allow.
func TestUser_ResolverError_Unavailable(t *testing.T) {
	t.Parallel()
	srv := buildServerForOrgTenantTests(t, true, &fakeOrgTenantResolver{err: errors.New("daemon unreachable")})
	req := makeCheckRequest(t, "/test.v1.S/UserOp", map[string]any{
		"iss":                                   "https://zitadel.example",
		"sub":                                   "user-1",
		"iat":                                   time.Now().Unix(),
		"urn:zitadel:iam:user:resourceowner:id": "org-acme",
	}, "")

	resp, err := srv.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if codes.Code(resp.GetStatus().GetCode()) != codes.Unavailable { //nolint:gosec // controlled small value
		t.Errorf("expected Unavailable (org resolver error), got %v: %s",
			resp.GetStatus().GetCode(), resp.GetStatus().GetMessage())
	}
}

// TestNewEnvoyAuthzServer_PanicsWithoutOrgTenants — OrgTenants is required,
// the same as Cache and Logger: a person's tenant comes ONLY from this
// resolver (ADR-0093 decision 4), so a server built without one must fail
// loud at construction, not silently deny (or worse, allow) every user.
func TestNewEnvoyAuthzServer_PanicsWithoutOrgTenants(t *testing.T) {
	t.Parallel()
	reg, err := fga.LoadRegistry([]byte(tenantTestYAML))
	if err != nil {
		t.Fatal(err)
	}
	cc := fga.NewCachedChecker(fga.NewChecker(&tenantMockFGA{allowed: true}, reg), 0, 0)
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected NewEnvoyAuthzServer to panic with a nil OrgTenants")
		}
	}()
	NewEnvoyAuthzServer(Config{Cache: cc, Logger: newTestLogger()})
}

// ---------------------------------------------------------------------------
// Issuer allowlist tests (security-hardening R13)
// ---------------------------------------------------------------------------

// buildServerWithIssuerAllowlist mirrors buildServerForTenantTests but injects
// a non-empty IssuerAllowlist so that the per-request iss check runs.
func buildServerWithIssuerAllowlist(t *testing.T, fgaAllowed bool, allowlist []string) *EnvoyAuthzServer {
	t.Helper()

	const issuerTestYAML = `entries:
  "/gibson.daemon.v1.PlatformOperatorService/Ping":
    relation: "platform_operator"
    object_type: "system_tenant"
    object_deriver: "system_tenant"
    allowed_identities:
      - PLATFORM_OPERATOR
  "/test.v1.S/Op":
    relation: "member"
    object_type: "tenant"
    object_deriver: "tenant_from_identity"
    allowed_identities:
      - SERVICE
`
	reg, err := fga.LoadRegistry([]byte(issuerTestYAML))
	if err != nil {
		t.Fatal(err)
	}
	mock := &tenantMockFGA{allowed: fgaAllowed}
	checker := fga.NewChecker(mock, reg)
	cachedChecker := fga.NewCachedChecker(checker, 0, 0)

	return NewEnvoyAuthzServer(Config{
		Cache:           cachedChecker,
		Logger:          newTestLogger(),
		IssuerAllowlist: allowlist,
		OrgTenants:      &fakeOrgTenantResolver{},
	})
}

// TestIssuerAllowlist_UnknownIssuerDenied — a JWT with an `iss` not in the
// configured allowlist must be rejected with PermissionDenied. Spec R13.
func TestIssuerAllowlist_UnknownIssuerDenied(t *testing.T) {
	t.Parallel()
	srv := buildServerWithIssuerAllowlist(t, true, []string{"https://auth.zeroroot.ai"})
	req := makeCheckRequest(t, "/test.v1.S/Op", map[string]any{
		"iss":       "https://attacker.example.com",
		"sub":       "sa-x",
		"client_id": "sa-x",
	}, "acme")

	resp, err := srv.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if codes.Code(resp.GetStatus().GetCode()) != codes.PermissionDenied {
		t.Errorf("expected PermissionDenied for unknown iss, got %v: %s",
			resp.GetStatus().GetCode(), resp.GetStatus().GetMessage())
	}
}

// TestIssuerAllowlist_AllowedIssuerAccepted — a JWT whose `iss` matches an
// allowlist entry passes the iss check and continues into FGA. The verified
// iss flows into the resulting Identity (and onward to header emission).
// Spec R13.
func TestIssuerAllowlist_AllowedIssuerAccepted(t *testing.T) {
	t.Parallel()
	const goodIss = "https://auth.zeroroot.ai"
	srv := buildServerWithIssuerAllowlist(t, true, []string{goodIss, "https://auth.staging.zeroroot.ai"})
	req := makeCheckRequest(t, "/test.v1.S/Op", map[string]any{
		"iss":       goodIss,
		"sub":       "sa-y",
		"client_id": "sa-y",
	}, "acme")

	resp, err := srv.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if codes.Code(resp.GetStatus().GetCode()) != codes.OK {
		t.Fatalf("expected OK for allowlisted iss, got %v: %s",
			resp.GetStatus().GetCode(), resp.GetStatus().GetMessage())
	}

	// The emitted x-gibson-identity-issuer header carries the canonical
	// wire constant "oidc" — NOT the raw claims.iss URL. The SDK's
	// auth/headers.go accepts only the closed enum (IssuerOIDC,
	// IssuerCapabilityGrant); forwarding the URL produced "unknown issuer"
	// rejections at the daemon. See ext-authz#26.
	//
	// The security-hardening R13 issuer-allowlist check still runs in
	// ext-authz BEFORE this header is emitted — verified above by
	// reaching codes.OK with goodIss on the allowlist.
	hdrs := resp.GetOkResponse().GetHeaders()
	var issuerHdr string
	for _, h := range hdrs {
		if h.GetHeader().GetKey() == "x-gibson-identity-issuer" {
			issuerHdr = h.GetHeader().GetValue()
			break
		}
	}
	if issuerHdr != headers.IssuerOIDC {
		t.Errorf("emitted issuer header = %q, want %q (canonical wire constant)", issuerHdr, headers.IssuerOIDC)
	}
}

// TestIssuerAllowlist_CanonicalIssuerOnIdentity — drills into
// identityFromJWTPayload directly to confirm the returned Identity.Issuer
// field carries the canonical wire constant `IssuerOIDC`, not the raw
// claims.iss URL. The SDK's auth/headers.go enforces a closed enum on
// this header value; emitting anything else (including a verified iss URL
// that's on the allowlist) produces `unknown issuer` rejections at the
// daemon. See ext-authz#26.
func TestIssuerAllowlist_CanonicalIssuerOnIdentity(t *testing.T) {
	t.Parallel()
	const iss = "https://auth.example.com"
	hdrs := map[string]string{
		headerJWTPayload: encodePayload(t, map[string]any{
			"iss":       iss,
			"sub":       "user-1",
			"client_id": "user-1",
		}),
	}
	tok, err := identityFromJWTPayload(hdrs, nil)
	if err != nil {
		t.Fatalf("identityFromJWTPayload: %v", err)
	}
	if tok.id.Issuer != headers.IssuerOIDC {
		t.Errorf("Identity.Issuer = %q, want canonical wire constant %q", tok.id.Issuer, headers.IssuerOIDC)
	}
}

// TestSelfMode_ServiceTokenDenied — self-mode RPCs declare allowed_identities
// (USER-only in this fixture). A SERVICE-class token must be rejected by the
// AllowedIdentities bitfield even though the FGA Check is skipped. This is
// what `unauthenticated: true` would have lost (the original audit's concern
// for self-bootstrap RPCs).
//
// Spec: self-mode-authz Req 3.6.
func TestSelfMode_ServiceTokenDenied(t *testing.T) {
	t.Parallel()
	srv := buildServerForTenantTests(t, true)
	req := makeCheckRequest(t, "/test.v1.S/SelfOp", map[string]any{
		"iss":       "https://zitadel.example",
		"sub":       "sa-456",
		"client_id": "sa-456", // sub == client_id ⇒ SERVICE class
	}, "")

	resp, err := srv.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if codes.Code(resp.GetStatus().GetCode()) != codes.PermissionDenied {
		t.Errorf("expected PermissionDenied for SERVICE caller on USER-only self-mode RPC, got %v",
			resp.GetStatus().GetCode())
	}
}

// ---------------------------------------------------------------------------
// Capability-grant enforcement
//
// A capability grant constrains a request; it never authorizes one. These
// tests pin both halves of that: FGA decides every request, and a grant that
// is not bound to the caller takes the request away.
//
// The primary identity's tenant here comes from an
// "urn:zitadel:iam:user:resourceowner:id": "org-<tenant>" claim, resolved by
// fakeOrgTenantResolver's default convention (ADR-0093 decision 4) — never
// from a "tenant" claim. The capability GRANT's own tenant assertion
// (mintGrant's "tenant" field, verified separately by cgjwt against the
// grant's signature) is a distinct concept and is untouched by that change.
// ---------------------------------------------------------------------------

// grantTestFGA answers `allowed` to every question and records the objects it
// was asked about, so a test can tell "FGA said yes" from "FGA was never
// asked".
type grantTestFGA struct {
	allowed  bool
	mu       sync.Mutex
	requests []fgaclient.ClientCheckRequest
}

func (m *grantTestFGA) Check(_ context.Context) fgaclient.SdkClientCheckRequestInterface {
	return &grantTestReq{m: m}
}

func (m *grantTestFGA) captured() []fgaclient.ClientCheckRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]fgaclient.ClientCheckRequest(nil), m.requests...)
}

type grantTestReq struct {
	m    *grantTestFGA
	body fgaclient.ClientCheckRequest
}

func (r *grantTestReq) Body(b fgaclient.ClientCheckRequest) fgaclient.SdkClientCheckRequestInterface {
	r.body = b
	return r
}

func (r *grantTestReq) Options(_ fgaclient.ClientCheckOptions) fgaclient.SdkClientCheckRequestInterface {
	return r
}

func (r *grantTestReq) Execute() (*fgaclient.ClientCheckResponse, error) {
	r.m.mu.Lock()
	r.m.requests = append(r.m.requests, r.body)
	r.m.mu.Unlock()
	v := r.m.allowed
	return &fgaclient.ClientCheckResponse{CheckResponse: openfga.CheckResponse{Allowed: &v}}, nil
}

func (r *grantTestReq) GetAuthorizationModelIdOverride() *string  { return nil } //nolint:revive,staticcheck // method name set by openfga SDK request interface
func (r *grantTestReq) GetStoreIdOverride() *string               { return nil } //nolint:revive,staticcheck // method name set by openfga SDK request interface
func (r *grantTestReq) GetContext() context.Context               { return context.Background() }
func (r *grantTestReq) GetBody() *fgaclient.ClientCheckRequest    { b := r.body; return &b }
func (r *grantTestReq) GetOptions() *fgaclient.ClientCheckOptions { return nil }

const grantTestYAML = `entries:
  "/test.v1.S/Guarded":
    relation: "member"
    object_type: "tenant"
    object_deriver: "tenant_from_identity"
    allowed_identities:
      - USER
`

const (
	grantIssuer   = "https://daemon.example/cg"
	grantAudience = "gibson-daemon"
	grantKID      = "cg-test-1"
	grantMethod   = "/test.v1.S/Guarded"
)

// startCGKeyServer stands in for the daemon's per-kid key endpoint, serving the
// daemon's own dispatch key as a bare key document (ADR-0045; no JWKS-wide
// document exists).
func startCGKeyServer(t *testing.T, pub ed25519.PublicKey) *httptest.Server {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"keys": []map[string]string{{
			"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig",
			"kid": grantKID,
			"x":   base64.RawURLEncoding.EncodeToString(pub),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/capabilitygrant/v1/keys/"+grantKID {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// mintGrant signs a daemon-shaped capability grant for (subject, tenant) that
// covers the given methods.
func mintGrant(t *testing.T, priv ed25519.PrivateKey, subject, tenant string, methods []string) string {
	t.Helper()
	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"iss":          grantIssuer,
		"aud":          grantAudience,
		"sub":          subject,
		"tenant":       tenant,
		"mission_id":   "mission-1",
		"task_id":      "task-1",
		"jti":          "jti-" + subject,
		"iat":          now.Add(-time.Second).Unix(),
		"exp":          now.Add(10 * time.Minute).Unix(),
		"allowed_rpcs": methods,
	})
	tok.Header["kid"] = grantKID
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// buildGrantServer wires an ext-authz server whose FGA answers `fgaAllowed`
// and whose capability-grant verifier trusts the returned signing key.
func buildGrantServer(t *testing.T, fgaAllowed bool) (*EnvoyAuthzServer, ed25519.PrivateKey, *grantTestFGA) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keys := startCGKeyServer(t, pub)
	verifier, err := cgjwt.NewVerifier(cgjwt.Config{
		KeysBaseURL:      keys.URL + "/capabilitygrant/v1/keys",
		ExpectedIssuer:   grantIssuer,
		ExpectedAudience: grantAudience,
		// The constructor has no default client: the key document is the
		// trust anchor, so its transport is always the caller's choice.
		HTTPClient: keys.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	reg, err := fga.LoadRegistry([]byte(grantTestYAML))
	if err != nil {
		t.Fatal(err)
	}
	mock := &grantTestFGA{allowed: fgaAllowed}
	cc := fga.NewCachedChecker(fga.NewChecker(mock, reg), 0, 0)
	srv := NewEnvoyAuthzServer(Config{Cache: cc, CGJWT: verifier, Logger: newTestLogger(), OrgTenants: &fakeOrgTenantResolver{}})
	return srv, priv, mock
}

// grantRequest builds a Check request from `subject` in `tenant` carrying the
// supplied capability grant. The primary identity's tenant is derived from
// an org claim ("org-<tenant>", per fakeOrgTenantResolver's default), never
// from a JWT "tenant" claim (ADR-0093 decision 4).
func grantRequest(t *testing.T, subject, tenant, grant string) *authv3.CheckRequest {
	t.Helper()
	hdrs := map[string]string{
		headerJWTPayload: encodePayload(t, map[string]any{
			"iss":                                   "https://zitadel.example",
			"sub":                                   subject,
			"urn:zitadel:iam:user:resourceowner:id": "org-" + tenant,
			"iat":                                   time.Now().Unix(),
		}),
	}
	if grant != "" {
		hdrs[headerCapabilityGrant] = grant
	}
	return &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{Path: grantMethod, Headers: hdrs},
			},
		},
	}
}

// TestCapabilityGrant_DoesNotSubstituteForFGA — a grant that verifies, names
// the request's tenant, is bound to the caller and covers the method still
// does not authorize the request on its own: FGA denies, so the request is
// denied.
func TestCapabilityGrant_DoesNotSubstituteForFGA(t *testing.T) {
	t.Parallel()
	srv, priv, mock := buildGrantServer(t, false /* FGA denies */)
	grant := mintGrant(t, priv, "u-1", "acme", []string{grantMethod})

	resp, err := srv.Check(context.Background(), grantRequest(t, "u-1", "acme", grant))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if codes.Code(resp.GetStatus().GetCode()) != codes.PermissionDenied { //nolint:gosec // gRPC status code is a controlled small value
		t.Errorf("expected PermissionDenied (FGA denies; a grant cannot substitute for it), got %v",
			resp.GetStatus().GetCode())
	}
	// The per-RPC question specifically — the session gate asks its own
	// question on the same stub, so merely counting calls would not show that
	// the per-RPC decision happened.
	var askedPerRPC bool
	for _, q := range mock.captured() {
		if q.Relation == "member" && q.Object == "tenant:acme" {
			askedPerRPC = true
		}
	}
	if !askedPerRPC {
		t.Errorf("FGA was never asked the per-RPC question; questions = %+v. The per-RPC "+
			"decision must not be skipped for grant-bearing requests", mock.captured())
	}
}

// TestCapabilityGrant_NotBoundToCaller_Denied — a grant minted for another
// principal is not usable by this caller, even where FGA would allow the call.
// This is what stops a leaked grant from being replayed by anyone else in the
// same tenant.
func TestCapabilityGrant_NotBoundToCaller_Denied(t *testing.T) {
	t.Parallel()
	srv, priv, _ := buildGrantServer(t, true /* FGA allows */)
	grant := mintGrant(t, priv, "component:tool:scanner", "acme", []string{grantMethod})

	resp, err := srv.Check(context.Background(), grantRequest(t, "u-1", "acme", grant))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if codes.Code(resp.GetStatus().GetCode()) != codes.PermissionDenied { //nolint:gosec // gRPC status code is a controlled small value
		t.Errorf("expected PermissionDenied (grant is bound to another principal), got %v",
			resp.GetStatus().GetCode())
	}
}

// TestCapabilityGrant_BoundAndAllowedByFGA_Allowed — the normal case: the
// grant is bound to the caller and FGA allows, so the request proceeds.
func TestCapabilityGrant_BoundAndAllowedByFGA_Allowed(t *testing.T) {
	t.Parallel()
	srv, priv, mock := buildGrantServer(t, true /* FGA allows */)
	grant := mintGrant(t, priv, "u-1", "acme", []string{grantMethod})

	resp, err := srv.Check(context.Background(), grantRequest(t, "u-1", "acme", grant))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if codes.Code(resp.GetStatus().GetCode()) != codes.OK { //nolint:gosec // gRPC status code is a controlled small value
		t.Errorf("expected OK, got %v: %s", resp.GetStatus().GetCode(), resp.GetStatus().GetMessage())
	}
	got := mock.captured()
	if len(got) == 0 || got[0].Relation != "member" || got[0].Object != "tenant:acme" {
		t.Errorf("first FGA question = %+v, want the per-RPC check (member on tenant:acme)", got)
	}
}

// TestCapabilityGrant_ForAnotherTenant_Denied — a grant naming a different
// tenant than the request resolved to is refused.
func TestCapabilityGrant_ForAnotherTenant_Denied(t *testing.T) {
	t.Parallel()
	srv, priv, _ := buildGrantServer(t, true /* FGA allows */)
	grant := mintGrant(t, priv, "u-1", "other-tenant", []string{grantMethod})

	resp, err := srv.Check(context.Background(), grantRequest(t, "u-1", "acme", grant))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if codes.Code(resp.GetStatus().GetCode()) != codes.PermissionDenied { //nolint:gosec // gRPC status code is a controlled small value
		t.Errorf("expected PermissionDenied (grant names another tenant), got %v",
			resp.GetStatus().GetCode())
	}
}

// TestCapabilityGrant_MethodNotCovered_Denied — a grant that does not cover
// the requested method is not silently ignored: the request is denied rather
// than proceeding on a credential that does not support it.
func TestCapabilityGrant_MethodNotCovered_Denied(t *testing.T) {
	t.Parallel()
	srv, priv, _ := buildGrantServer(t, true /* FGA allows */)
	grant := mintGrant(t, priv, "u-1", "acme", []string{"/test.v1.S/SomethingElse"})

	resp, err := srv.Check(context.Background(), grantRequest(t, "u-1", "acme", grant))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if codes.Code(resp.GetStatus().GetCode()) != codes.PermissionDenied { //nolint:gosec // gRPC status code is a controlled small value
		t.Errorf("expected PermissionDenied (grant does not cover this method), got %v",
			resp.GetStatus().GetCode())
	}
}

// TestCapabilityGrant_Unverifiable_Denied — a presented grant that does not
// verify is a failed credential, not an absent one. The request is denied
// rather than proceeding on the primary identity alone.
func TestCapabilityGrant_Unverifiable_Denied(t *testing.T) {
	t.Parallel()
	srv, _, _ := buildGrantServer(t, true /* FGA allows */)
	_, otherPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	forged := mintGrant(t, otherPriv, "u-1", "acme", []string{grantMethod})

	resp, err := srv.Check(context.Background(), grantRequest(t, "u-1", "acme", forged))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if codes.Code(resp.GetStatus().GetCode()) != codes.PermissionDenied { //nolint:gosec // gRPC status code is a controlled small value
		t.Errorf("expected PermissionDenied (grant does not verify), got %v",
			resp.GetStatus().GetCode())
	}
}

// gibson#133: a Zitadel machine user's client_credentials token carries
// client_id = the user's name and sub = its numeric id. With the human
// sign-in clients configured, that token is a machine credential; the
// dashboard's own token is a person.
func TestCredentialTypeFor_ZitadelMachineUserToken(t *testing.T) {
	t.Parallel()
	humans := map[string]struct{}{"334268812578094081@gibson": {}}
	cases := []struct {
		name               string
		sub, clientID, azp string
		humans             map[string]struct{}
		want               string
	}{
		// THE FIXTURE THIS EXISTS FOR.
		{"machine user, name as client_id", "212345678901234567", "gibson-sdk", "gibson-sdk", humans, "client-credentials"},
		{"machine user, azp only", "212345678901234567", "", "tenant-acme-ci", humans, "client-credentials"},
		{"client that is its own subject", "svc-1", "svc-1", "", nil, "client-credentials"},
		{"dashboard sign-in token", "999888777", "334268812578094081@gibson", "334268812578094081@gibson", humans, "oidc-user"},
		{"dashboard sign-in token, azp only", "999888777", "", "334268812578094081@gibson", humans, "oidc-user"},
		{"no human clients configured keeps the old rule", "212345678901234567", "gibson-sdk", "", nil, "oidc-user"},
		{"no client at all", "999888777", "", "", humans, "oidc-user"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := credentialTypeFor(tc.sub, tc.clientID, tc.azp, tc.humans); got != tc.want {
				t.Fatalf("credentialTypeFor(%q,%q,%q) = %q, want %q", tc.sub, tc.clientID, tc.azp, got, tc.want)
			}
		})
	}
	// And through the payload decoder, as the server sees it.
	hdrs := map[string]string{headerJWTPayload: encodePayload(t, map[string]any{
		"iss": "https://zitadel.example", "sub": "212345678901234567", "client_id": "gibson-sdk", "azp": "gibson-sdk",
	})}
	tok, err := identityFromJWTPayload(hdrs, humans)
	if err != nil {
		t.Fatalf("identityFromJWTPayload: %v", err)
	}
	if tok.id.CredentialType != "client-credentials" || tok.id.Subject != "212345678901234567" {
		t.Fatalf("machine user token: got %+v", tok.id)
	}
}

// The constructor trims and drops blank entries, so a chart value with
// stray whitespace still names the client.
func TestNewEnvoyAuthzServer_HumanClientIDs(t *testing.T) {
	t.Parallel()
	reg, err := fga.LoadRegistry([]byte(sessionGateTestYAML))
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	cc := fga.NewCachedChecker(fga.NewChecker(&sessionAwareFGA{rpcAllowed: true, sessionAllowed: false}, reg), 0, 0)
	srv := NewEnvoyAuthzServer(Config{
		Cache:          cc,
		Logger:         newTestLogger(),
		HumanClientIDs: []string{" 334268812578094081@gibson ", "", "  "},
		OrgTenants:     &fakeOrgTenantResolver{},
	})
	if len(srv.humans) != 1 {
		t.Fatalf("humans = %v, want the one trimmed client id", srv.humans)
	}
	if _, ok := srv.humans["334268812578094081@gibson"]; !ok {
		t.Fatalf("humans = %v, want the trimmed client id as key", srv.humans)
	}
}
