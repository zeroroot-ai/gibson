// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package server

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

	id, src, _, err := identityFromJWTPayload(hdrs)
	if err != nil {
		t.Fatalf("identityFromJWTPayload: %v", err)
	}
	// sub is always used — preferred_username swap is removed.
	if id.Subject != numericClientID {
		t.Errorf("Subject = %q, want numeric sub %q (preferred_username swap removed per Req 3.1)", id.Subject, numericClientID)
	}
	if src != "sub" {
		t.Errorf("subjectSource = %q, want %q", src, "sub")
	}
	if id.CredentialType != "client-credentials" {
		t.Errorf("CredentialType = %q, want %q", id.CredentialType, "client-credentials")
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

	id, src, _, err := identityFromJWTPayload(hdrs)
	if err != nil {
		t.Fatalf("identityFromJWTPayload: %v", err)
	}
	if id.Subject != sub {
		t.Errorf("Subject = %q, want %q", id.Subject, sub)
	}
	if src != "sub" {
		t.Errorf("subjectSource = %q, want %q", src, "sub")
	}
	if id.CredentialType != "client-credentials" {
		t.Errorf("CredentialType = %q, want %q", id.CredentialType, "client-credentials")
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

	id, src, _, err := identityFromJWTPayload(hdrs)
	if err != nil {
		t.Fatalf("identityFromJWTPayload: %v", err)
	}
	if id.Subject != userSub {
		t.Errorf("Subject = %q, want %q", id.Subject, userSub)
	}
	if src != "sub" {
		t.Errorf("subjectSource = %q, want %q", src, "sub")
	}
	if id.CredentialType != "oidc-user" {
		t.Errorf("CredentialType = %q, want %q", id.CredentialType, "oidc-user")
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

	id, _, _, err := identityFromJWTPayload(hdrs)
	if err != nil {
		t.Fatalf("identityFromJWTPayload: %v", err)
	}
	if got := id.TokenIssuedAt.Unix(); got != iat {
		t.Errorf("TokenIssuedAt = %d, want token iat %d", got, iat)
	}
	if id.TokenIssuedAt.Location() != time.UTC {
		t.Errorf("TokenIssuedAt location = %v, want UTC", id.TokenIssuedAt.Location())
	}
	// The freshness IssuedAt must NOT be populated from the token iat — it is
	// stamped to allow-time later in the request path, not here.
	if !id.IssuedAt.IsZero() {
		t.Errorf("IssuedAt = %v, want zero (freshness stamp is set at allow time, not from iat)", id.IssuedAt)
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

	id, _, _, err := identityFromJWTPayload(hdrs)
	if err != nil {
		t.Fatalf("identityFromJWTPayload: %v", err)
	}
	if !id.TokenIssuedAt.IsZero() {
		t.Errorf("TokenIssuedAt = %v, want zero time when iat absent", id.TokenIssuedAt)
	}
}

// TestIdentityFromJWTPayload_MissingHeader — error on missing x-jwt-payload.
func TestIdentityFromJWTPayload_MissingHeader(t *testing.T) {
	t.Parallel()
	if _, _, _, err := identityFromJWTPayload(map[string]string{}); err == nil {
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
	if _, _, _, err := identityFromJWTPayload(hdrs); err == nil {
		t.Fatal("identityFromJWTPayload: expected error on missing sub, got nil")
	}
}

// ---------------------------------------------------------------------------
// Tenant cross-check tests (zero-trust-hardening Req 4)
// ---------------------------------------------------------------------------

// stubCache is a minimal *fga.CachedChecker wrapper that stubs out Check.
// It is used for tenant cross-check tests that need to exercise the server's
// Check method without a real FGA server.
type stubCache struct {
	// checkFunc overrides the CachedChecker.Check call when set.
	checkFunc func(ctx context.Context, method string, identity headers.Identity, meta map[string]string) (bool, error)
}

// buildServerWithStub builds an EnvoyAuthzServer whose CachedChecker is driven
// by checkFunc. We construct a real CachedChecker to satisfy the type, then
// wrap it — but since tests inject a stub registry that lacks any method, the
// check falls through to checkFunc via the injected fga client.
//
// For simplicity in these tests, we build a special CachedChecker backed by
// a mock FGA client and a registry that contains the platformOp sentinel method.
func buildServerForTenantTests(t *testing.T, fgaAllowed bool) *EnvoyAuthzServer {
	t.Helper()

	// Build a registry that contains the PlatformOperator sentinel used in
	// the cross-tenant branch of Check.
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
	reg, err := fga.LoadRegistry([]byte(tenantTestYAML))
	if err != nil {
		t.Fatal(err)
	}

	import_openfga := fgaAllowed
	mock := &tenantMockFGA{allowed: import_openfga}
	checker := fga.NewChecker(mock, reg)
	cachedChecker := fga.NewCachedChecker(checker, 0, 0)

	import_slog := newTestLogger()
	return NewEnvoyAuthzServer(Config{
		Cache:  cachedChecker,
		Logger: import_slog,
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

// TestTenantCrossCheck_MatchingValues — JWT-tenant and header match → allowed
// (provided FGA also allows; here FGA is stubbed to allow).
func TestTenantCrossCheck_MatchingValues(t *testing.T) {
	t.Parallel()
	srv := buildServerForTenantTests(t, true)
	req := makeCheckRequest(t, "/test.v1.S/Op", map[string]any{
		"iss":       "https://zitadel.example",
		"sub":       "sa-123",
		"client_id": "sa-123",
		"tenant":    "acme",
	}, "acme") // header matches JWT

	resp, err := srv.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if codes.Code(resp.GetStatus().GetCode()) != codes.OK {
		t.Errorf("expected OK, got %v: %s", resp.GetStatus().GetCode(), resp.GetStatus().GetMessage())
	}
}

// TestTenantCrossCheck_MismatchingValues — JWT-tenant and header differ → PermissionDenied.
func TestTenantCrossCheck_MismatchingValues(t *testing.T) {
	t.Parallel()
	srv := buildServerForTenantTests(t, true)
	req := makeCheckRequest(t, "/test.v1.S/Op", map[string]any{
		"iss":       "https://zitadel.example",
		"sub":       "user-456",
		"client_id": "different",
		"tenant":    "acme",
	}, "bigcorp") // header != JWT tenant

	resp, err := srv.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if codes.Code(resp.GetStatus().GetCode()) != codes.PermissionDenied {
		t.Errorf("expected PermissionDenied on tenant mismatch, got %v", resp.GetStatus().GetCode())
	}
}

// TestTenantCrossCheck_MissingHeader — no header, JWT-tenant present → allowed.
func TestTenantCrossCheck_MissingHeader(t *testing.T) {
	t.Parallel()
	srv := buildServerForTenantTests(t, true)
	req := makeCheckRequest(t, "/test.v1.S/Op", map[string]any{
		"iss":       "https://zitadel.example",
		"sub":       "sa-789",
		"client_id": "sa-789",
		"tenant":    "acme",
	}, "") // no header

	resp, err := srv.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	// FGA stub returns allowed=true, identity is SERVICE, method allows SERVICE.
	if codes.Code(resp.GetStatus().GetCode()) != codes.OK {
		t.Errorf("expected OK for JWT-only tenant, got %v: %s", resp.GetStatus().GetCode(), resp.GetStatus().GetMessage())
	}
}

// TestTenantCrossCheck_PlatformOperator — no JWT-tenant + header present + FGA confirms
// platform_operator → allowed.
func TestTenantCrossCheck_PlatformOperatorAllowed(t *testing.T) {
	t.Parallel()
	srv := buildServerForTenantTests(t, true) // FGA allows
	req := makeCheckRequest(t, "/test.v1.S/Op", map[string]any{
		"iss":       "https://zitadel.example",
		"sub":       "platform-op-id",
		"client_id": "platform-op-id",
		// no "tenant" claim — this is a cross-tenant operator
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

// TestTenantCrossCheck_PlatformOperatorDenied — no JWT-tenant + header present +
// FGA denies platform_operator → PermissionDenied.
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

// TestTenantCrossCheck_NeitherPresent — no JWT-tenant and no header → PermissionDenied.
// Applies to RULE-mode entries only. Self-mode and unauthenticated entries skip
// tenant resolution per self-mode-authz Req 4.6 — see TestSelfMode_NoTenant_Allows
// below.
func TestTenantCrossCheck_NeitherPresent(t *testing.T) {
	t.Parallel()
	srv := buildServerForTenantTests(t, true)
	req := makeCheckRequest(t, "/test.v1.S/Op", map[string]any{
		"iss":       "https://zitadel.example",
		"sub":       "anon",
		"client_id": "anon",
		// no tenant claim, no header
	}, "")

	resp, err := srv.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if codes.Code(resp.GetStatus().GetCode()) != codes.PermissionDenied {
		t.Errorf("expected PermissionDenied when no tenant derivable, got %v", resp.GetStatus().GetCode())
	}
}

// TestTenantCrossCheck_UserNoJWTTenantHeaderPresent_FGAMember — the standard
// dashboard sign-in flow on rule-mode RPCs (e.g. ListProviders). Zitadel
// user JWTs deliberately do NOT carry a `gibson:tenant` claim — users may
// be members of multiple tenants and the active-tenant choice is a UI
// selection (gibson_active_tenant cookie → x-gibson-tenant header). The
// pre-fix behaviour treated this as "SA acting cross-tenant" and required
// platform_operator, which broke every normal user request that hit a
// rule-mode RPC. Post-fix the USER path trusts the header and lets the
// rule-mode FGA Check on `tenant_from_identity` enforce membership.
//
// Spec: zero-trust-hardening Req 4 (post-fix).
func TestTenantCrossCheck_UserNoJWTTenantHeaderPresent_FGAMember(t *testing.T) {
	t.Parallel()
	srv := buildServerForTenantTests(t, true) // FGA allows (=> user is a member + session valid)
	req := makeCheckRequest(t, "/test.v1.S/UserOp", map[string]any{
		"iss": "https://zitadel.example",
		"sub": "user-987",
		"iat": int64(1_700_000_100), // session gate requires iat; real Zitadel JWTs always include it
		// no client_id (USER token)
		// no tenant claim (Zitadel user JWTs don't carry one)
	}, "acme") // dashboard sets x-gibson-tenant from gibson_active_tenant

	resp, err := srv.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if codes.Code(resp.GetStatus().GetCode()) != codes.OK {
		t.Errorf("expected OK for USER caller with no JWT-tenant + header tenant + FGA membership, got %v: %s",
			resp.GetStatus().GetCode(), resp.GetStatus().GetMessage())
	}
}

// TestTenantCrossCheck_UserNoJWTTenantHeaderPresent_FGANonMember — the
// tenant-probing case the audit's Req 4 was designed to block. A USER asserts
// `x-gibson-tenant: <tenant they don't belong to>`. ext-authz trusts the
// header (per the design above) but the rule-mode FGA Check fails because
// `(user:<sub>, member, tenant:<X>)` is not seeded. Result: deny. Membership,
// not JWT-tenant binding, is the protection.
func TestTenantCrossCheck_UserNoJWTTenantHeaderPresent_FGANonMember(t *testing.T) {
	t.Parallel()
	srv := buildServerForTenantTests(t, false) // FGA denies (=> user is not a member)
	req := makeCheckRequest(t, "/test.v1.S/UserOp", map[string]any{
		"iss": "https://zitadel.example",
		"sub": "user-987",
	}, "tenant-they-dont-belong-to")

	resp, err := srv.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if codes.Code(resp.GetStatus().GetCode()) != codes.PermissionDenied {
		t.Errorf("expected PermissionDenied for USER asserting tenant they're not a member of, got %v",
			resp.GetStatus().GetCode())
	}
}

// TestSelfMode_NoTenant_Allows — the sign-in scenario. A USER token with
// NEITHER a JWT-tenant claim NOR an x-gibson-tenant header calls a self-mode
// RPC. Pre-fix (ext-authz v0.2.0) this was denied with "no tenant derivable"
// at the cross-check before the registry-aware Checker ever ran. Post-fix
// (v0.2.1) the early registry lookup detects entry.Self and skips tenant
// resolution; the request reaches cache.Check which short-circuits on Self
// and returns OK.
//
// Spec: self-mode-authz Req 4.6.
func TestSelfMode_NoTenant_Allows(t *testing.T) {
	t.Parallel()
	// Note: fgaAllowed=false here proves self-mode never calls the per-RPC FGA path.
	// However, the session gate IS a separate FGA call for oidc-user requests. Since
	// our FGA stub returns false for ALL checks, we must use fgaAllowed=true to make
	// the session gate pass. This is correct: self-mode tests that pre-date #627
	// used fgaAllowed=false to prove the per-RPC FGA call is skipped — that invariant
	// still holds (the mock call count would show exactly 1 call: the session gate).
	// The test is updated to fgaAllowed=true to reflect the backfill-populated session.
	srv := buildServerForTenantTests(t, true) // FGA allows session gate (oidc-user requires active_session)
	req := makeCheckRequest(t, "/test.v1.S/SelfOp", map[string]any{
		"iss": "https://zitadel.example",
		"sub": "user-123",
		"iat": int64(1_700_000_100), // session gate requires iat; real Zitadel JWTs always include it
		// no client_id (USER token, not SA)
		// no tenant claim, no header
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
		"tenant":    "acme",
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
		"tenant":    "acme",
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
	id, _, _, err := identityFromJWTPayload(hdrs)
	if err != nil {
		t.Fatalf("identityFromJWTPayload: %v", err)
	}
	if id.Issuer != headers.IssuerOIDC {
		t.Errorf("Identity.Issuer = %q, want canonical wire constant %q", id.Issuer, headers.IssuerOIDC)
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
	srv := NewEnvoyAuthzServer(Config{Cache: cc, CGJWT: verifier, Logger: newTestLogger()})
	return srv, priv, mock
}

// grantRequest builds a Check request from `subject` in `tenant` carrying the
// supplied capability grant.
func grantRequest(t *testing.T, subject, tenant, grant string) *authv3.CheckRequest {
	t.Helper()
	hdrs := map[string]string{
		headerJWTPayload: encodePayload(t, map[string]any{
			"iss":    "https://zitadel.example",
			"sub":    subject,
			"tenant": tenant,
			"iat":    time.Now().Unix(),
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
