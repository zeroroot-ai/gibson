// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package server

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"testing"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc/codes"

	"github.com/zeroroot-ai/gibson/internal/server/extauthz/headers"
)

// taskGrantSubject is the subject the daemon mints for a dispatched agent
// (harness mintCGForWork: "component:<kind>:<name>").
const taskGrantSubject = "component:agent:claude"

// mintTaskGrant signs a daemon-shaped grant with an explicit lifetime, so the
// expiry case is reachable. Header typ is left to the library ("JWT"), which is
// what tells it apart from a component's own agent+jwt.
func mintTaskGrant(t *testing.T, priv ed25519.PrivateKey, tenant string, methods []string, exp time.Time) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"iss": grantIssuer, "aud": grantAudience,
		"sub": taskGrantSubject, "tenant": tenant,
		"mission_id": "mission-1", "task_id": "task-1", "jti": "jti-task",
		"iat":          time.Now().Add(-time.Minute).Unix(),
		"exp":          exp.Unix(),
		"allowed_rpcs": methods,
	})
	tok.Header["kid"] = grantKID
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// soleGrantRequest builds a Check request carrying ONLY the grant: no
// Authorization, no x-jwt-payload, exactly what a sandboxed agent sends.
func soleGrantRequest(grant string) *authv3.CheckRequest {
	return &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Path:    grantMethod,
					Headers: map[string]string{headerCapabilityGrant: grant},
				},
			},
		},
	}
}

func emittedHeader(resp *authv3.CheckResponse, name string) string {
	for _, h := range resp.GetOkResponse().GetHeaders() {
		if h.GetHeader().GetKey() == name {
			return h.GetHeader().GetValue()
		}
	}
	return ""
}

// TestCheck_TaskGrantAsSoleCredential_Allowed — a sandboxed agent presenting
// only its work grant is authenticated as the grant's subject in the grant's
// tenant, and the covered method is allowed.
func TestCheck_TaskGrantAsSoleCredential_Allowed(t *testing.T) {
	t.Parallel()
	// FGA denies: the point is that a sole task grant does not depend on a
	// backplane tuple a dispatched agent never holds.
	srv, priv, mock := buildGrantServer(t, false)
	grant := mintTaskGrant(t, priv, "acme", []string{grantMethod}, time.Now().Add(10*time.Minute))

	resp, err := srv.Check(context.Background(), soleGrantRequest(grant))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if codes.Code(resp.GetStatus().GetCode()) != codes.OK { //nolint:gosec // controlled small value
		t.Fatalf("expected OK, got %v: %s", resp.GetStatus().GetCode(), resp.GetStatus().GetMessage())
	}
	if got := emittedHeader(resp, headers.HeaderSubject); got != taskGrantSubject {
		t.Errorf("subject = %q, want %q", got, taskGrantSubject)
	}
	if got := emittedHeader(resp, headers.HeaderTenant); got != "acme" {
		t.Errorf("tenant = %q, want acme (the signed claim)", got)
	}
	if got := emittedHeader(resp, headers.HeaderCredentialType); got != headers.CredentialCapabilityGrant {
		t.Errorf("credential type = %q, want %q", got, headers.CredentialCapabilityGrant)
	}
	if len(mock.captured()) != 0 {
		t.Errorf("a sole task grant must not ask FGA the backplane question; asked %+v", mock.captured())
	}
}

// TestCheck_TaskGrantMethodNotCovered_Denied — allowed_rpcs is the method
// boundary. A method the grant does not list is refused.
func TestCheck_TaskGrantMethodNotCovered_Denied(t *testing.T) {
	t.Parallel()
	srv, priv, _ := buildGrantServer(t, true)
	grant := mintTaskGrant(t, priv, "acme", []string{"/other.v1.S/Elsewhere"}, time.Now().Add(10*time.Minute))

	resp, err := srv.Check(context.Background(), soleGrantRequest(grant))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if codes.Code(resp.GetStatus().GetCode()) != codes.PermissionDenied { //nolint:gosec // controlled small value
		t.Fatalf("expected PermissionDenied, got %v", resp.GetStatus().GetCode())
	}
}

// TestCheck_TaskGrantExpired_Denied — an expired grant is refused, never
// treated as an absent credential.
func TestCheck_TaskGrantExpired_Denied(t *testing.T) {
	t.Parallel()
	srv, priv, _ := buildGrantServer(t, true)
	grant := mintTaskGrant(t, priv, "acme", []string{grantMethod}, time.Now().Add(-time.Minute))

	resp, err := srv.Check(context.Background(), soleGrantRequest(grant))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if codes.Code(resp.GetStatus().GetCode()) != codes.Unauthenticated { //nolint:gosec // controlled small value
		t.Fatalf("expected Unauthenticated, got %v", resp.GetStatus().GetCode())
	}
}

// TestCheck_TaskGrantBadSignature_Denied — a grant this daemon did not sign is
// refused, and is never ignored into the unauthenticated deny.
func TestCheck_TaskGrantBadSignature_Denied(t *testing.T) {
	t.Parallel()
	srv, _, _ := buildGrantServer(t, true)
	_, otherPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	grant := mintTaskGrant(t, otherPriv, "acme", []string{grantMethod}, time.Now().Add(10*time.Minute))

	resp, cerr := srv.Check(context.Background(), soleGrantRequest(grant))
	if cerr != nil {
		t.Fatalf("Check: %v", cerr)
	}
	if codes.Code(resp.GetStatus().GetCode()) != codes.Unauthenticated { //nolint:gosec // controlled small value
		t.Fatalf("expected Unauthenticated, got %v", resp.GetStatus().GetCode())
	}
}

// TestTryTaskGrantAuth_LeavesAComponentTokenAlone — an agent+jwt in the same
// header is the component's own identity. The task-grant path must not claim
// it, or tryComponentAuth would never run.
func TestTryTaskGrantAuth_LeavesAComponentTokenAlone(t *testing.T) {
	t.Parallel()
	srv, _, _ := buildGrantServer(t, true)
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"agent+jwt","kid":"k"}`))
	body := base64.RawURLEncoding.EncodeToString([]byte(`{}`))
	_, handled := srv.tryTaskGrantAuth(context.Background(), grantMethod,
		map[string]string{headerCapabilityGrant: hdr + "." + body + ".sig"})
	if handled {
		t.Fatal("an agent+jwt must fall through to the component path")
	}
}

// TestTryTaskGrantAuth_NoTokenIsNotHandled — a request with no grant is left to
// the unauthenticated deny.
func TestTryTaskGrantAuth_NoTokenIsNotHandled(t *testing.T) {
	t.Parallel()
	srv, _, _ := buildGrantServer(t, true)
	if _, handled := srv.tryTaskGrantAuth(context.Background(), grantMethod, map[string]string{}); handled {
		t.Fatal("no grant must not be handled here")
	}
}

// TestTryTaskGrantAuth_NoVerifierRefuses — a grant this ext-authz cannot verify
// is refused, not handed to the component path, which would report
// "unauthenticated" for a credential nobody read.
func TestTryTaskGrantAuth_NoVerifierRefuses(t *testing.T) {
	t.Parallel()
	srv, priv, _ := buildGrantServer(t, true)
	srv.cgjwt = nil
	grant := mintTaskGrant(t, priv, "acme", []string{grantMethod}, time.Now().Add(10*time.Minute))
	resp, handled := srv.tryTaskGrantAuth(context.Background(), grantMethod,
		map[string]string{headerCapabilityGrant: grant})
	if !handled {
		t.Fatal("a presented grant must be owned by this path even with no verifier")
	}
	if codes.Code(resp.GetStatus().GetCode()) != codes.Unauthenticated { //nolint:gosec // controlled small value
		t.Fatalf("expected Unauthenticated, got %v", resp.GetStatus().GetCode())
	}
}

// TestCheck_TaskGrantWithNoSubjectOrTenant_Denied — a grant that verifies but
// names no subject or no tenant cannot become an identity, so it is refused
// rather than emitted as an empty one.
func TestCheck_TaskGrantWithNoSubjectOrTenant_Denied(t *testing.T) {
	t.Parallel()
	srv, priv, _ := buildGrantServer(t, true)
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"iss": grantIssuer, "aud": grantAudience,
		"sub": "", "tenant": "acme",
		"mission_id": "m", "task_id": "t", "jti": "j-empty",
		"iat":          time.Now().Add(-time.Minute).Unix(),
		"exp":          time.Now().Add(10 * time.Minute).Unix(),
		"allowed_rpcs": []string{grantMethod},
	})
	tok.Header["kid"] = grantKID
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}

	resp, cerr := srv.Check(context.Background(), soleGrantRequest(signed))
	if cerr != nil {
		t.Fatalf("Check: %v", cerr)
	}
	code := codes.Code(resp.GetStatus().GetCode()) //nolint:gosec // controlled small value
	if code != codes.PermissionDenied && code != codes.Unauthenticated {
		t.Fatalf("expected a refusal, got %v", code)
	}
}

func TestTokenType(t *testing.T) {
	t.Parallel()
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"agent+jwt"}`))
	if got := tokenType(hdr + ".x.y"); got != "agent+jwt" {
		t.Errorf("typ = %q", got)
	}
	for _, bad := range []string{"", "a.b", "!!!.b.c", "notjson.b.c"} {
		if got := tokenType(bad); got != "" {
			t.Errorf("tokenType(%q) = %q, want empty", bad, got)
		}
	}
}
