package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc/codes"

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
	srv := buildServerForTenantTests(t, true) // FGA allows (=> user is a member)
	req := makeCheckRequest(t, "/test.v1.S/UserOp", map[string]any{
		"iss": "https://zitadel.example",
		"sub": "user-987",
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
	srv := buildServerForTenantTests(t, false) // FGA stub denies — proves we never call FGA
	req := makeCheckRequest(t, "/test.v1.S/SelfOp", map[string]any{
		"iss": "https://zitadel.example",
		"sub": "user-123",
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
