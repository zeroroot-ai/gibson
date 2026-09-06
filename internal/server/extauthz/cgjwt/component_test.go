// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package cgjwt

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// startDescriptorServer serves the per-kid descriptor (a JWKS superset) the
// daemon returns, mirroring buildKeyDescriptor in the gibson daemon.
func startDescriptorServer(t *testing.T, pub ed25519.PublicKey, kid, principal, tenant, status string) *httptest.Server {
	t.Helper()
	doc := map[string]any{
		"keys": []map[string]string{{
			"kty": "OKP", "crv": "Ed25519",
			"x":   base64.RawURLEncoding.EncodeToString(pub),
			"kid": kid, "alg": "EdDSA", "use": "sig",
		}},
		"principal": principal,
		"tenant":    tenant,
		"status":    status,
	}
	body, _ := json.Marshal(doc)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Expect GET {base}/{kid}.
		if !strings.HasSuffix(r.URL.Path, "/"+kid) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// testAudience is what newComponentVerifier pins and what mintAgentJWT
// addresses. ExpectedAudiences is required, so every verifier in this file
// has to name one.
const testAudience = "https://daemon/x"

// testMethod is the gRPC method every helper-minted token is bound to and that
// tests pass to Verify. Request binding (gibson#1246) requires the token's
// `method` claim to match the request method, so the two must agree.
const testMethod = "/gibson.test.v1.TestService/Ping"

// freshJTI returns a distinct jti per call. Component tokens are single-use
// (the replay cache), so tests that mint more than one token against the
// same verifier must not reuse a jti by accident.
var jtiSeq atomic.Int64

func freshJTI() string {
	return fmt.Sprintf("jti-%d", jtiSeq.Add(1))
}

func mintAgentJWT(t *testing.T, priv ed25519.PrivateKey, kid string, typ string, exp time.Time) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"iss":             "host-abc",
		"sub":             kid, // agent row id
		"aud":             testAudience,
		"iat":             time.Now().Add(-time.Second).Unix(),
		"exp":             exp.Unix(),
		"jti":             freshJTI(),
		"method":          testMethod,
		"component_scope": "component:hello",
	})
	tok.Header["kid"] = kid
	tok.Header["typ"] = typ
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func newComponentVerifier(t *testing.T, base string) *ComponentVerifier {
	t.Helper()
	v, err := NewComponentVerifier(ComponentConfig{
		KeysBaseURL:       base,
		TTL:               time.Minute,
		ExpectedAudiences: []string{testAudience},
		HTTPClient:        &http.Client{Timeout: 5 * time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestComponentVerify_HappyPath(t *testing.T) {
	pub, priv := mustGenKey(t)
	srv := startDescriptorServer(t, pub, "agent-1", "agent_principal:9", "acme", "active")
	v := newComponentVerifier(t, srv.URL+"/capabilitygrant/v1/keys")

	tok := mintAgentJWT(t, priv, "agent-1", "agent+jwt", time.Now().Add(55*time.Second))
	id, err := v.Verify(context.Background(), tok, testMethod)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if id.Principal != "agent_principal:9" || id.Tenant != "acme" {
		t.Fatalf("identity = %+v, want principal=agent_principal:9 tenant=acme", id)
	}
	if id.Subject != "agent-1" {
		t.Errorf("subject = %q, want agent-1", id.Subject)
	}
}

func TestComponentVerify_RejectsBadSignature(t *testing.T) {
	pub, _ := mustGenKey(t)
	_, otherPriv := mustGenKey(t) // sign with a key the descriptor does NOT publish
	srv := startDescriptorServer(t, pub, "agent-1", "agent_principal:9", "acme", "active")
	v := newComponentVerifier(t, srv.URL+"/capabilitygrant/v1/keys")

	tok := mintAgentJWT(t, otherPriv, "agent-1", "agent+jwt", time.Now().Add(55*time.Second))
	_, err := v.Verify(context.Background(), tok, testMethod)
	if !errors.Is(err, ErrSignature) {
		t.Fatalf("err = %v, want ErrSignature", err)
	}
}

func TestComponentVerify_RejectsExpired(t *testing.T) {
	pub, priv := mustGenKey(t)
	srv := startDescriptorServer(t, pub, "agent-1", "agent_principal:9", "acme", "active")
	v := newComponentVerifier(t, srv.URL+"/capabilitygrant/v1/keys")

	tok := mintAgentJWT(t, priv, "agent-1", "agent+jwt", time.Now().Add(-time.Minute))
	_, err := v.Verify(context.Background(), tok, testMethod)
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired", err)
	}
}

func TestComponentVerify_RejectsWrongTyp(t *testing.T) {
	pub, priv := mustGenKey(t)
	srv := startDescriptorServer(t, pub, "agent-1", "agent_principal:9", "acme", "active")
	v := newComponentVerifier(t, srv.URL+"/capabilitygrant/v1/keys")

	tok := mintAgentJWT(t, priv, "agent-1", "host+jwt", time.Now().Add(55*time.Second))
	_, err := v.Verify(context.Background(), tok, testMethod)
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
}

func TestComponentVerify_RejectsInactiveAgent(t *testing.T) {
	pub, priv := mustGenKey(t)
	srv := startDescriptorServer(t, pub, "agent-1", "agent_principal:9", "acme", "revoked")
	v := newComponentVerifier(t, srv.URL+"/capabilitygrant/v1/keys")

	tok := mintAgentJWT(t, priv, "agent-1", "agent+jwt", time.Now().Add(55*time.Second))
	_, err := v.Verify(context.Background(), tok, testMethod)
	if !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("err = %v, want ErrUnknownKey (inactive withheld)", err)
	}
}

func TestComponentVerify_RejectsNonComponentKid(t *testing.T) {
	// A bare key document (the daemon's own dispatch kid) has no principal/
	// tenant — it must not authenticate as a component.
	pub, priv := mustGenKey(t)
	srv := startDescriptorServer(t, pub, "cg-v1", "", "", "")
	v := newComponentVerifier(t, srv.URL+"/capabilitygrant/v1/keys")

	tok := mintAgentJWT(t, priv, "cg-v1", "agent+jwt", time.Now().Add(55*time.Second))
	_, err := v.Verify(context.Background(), tok, testMethod)
	if !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("err = %v, want ErrUnknownKey (no principal binding)", err)
	}
}

// mintAgentJWTClaims signs an agent+jwt from an explicit claim set, so tests
// can leave a claim out entirely (which mintAgentJWT cannot).
func mintAgentJWTClaims(t *testing.T, priv ed25519.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["kid"] = kid
	tok.Header["typ"] = "agent+jwt"
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// TestComponentVerify_RejectsTokenWithoutExpiry — a component token that
// carries no exp claim never stops being valid. Signature and descriptor are
// both good; the missing expiry alone must sink it.
func TestComponentVerify_RejectsTokenWithoutExpiry(t *testing.T) {
	pub, priv := mustGenKey(t)
	srv := startDescriptorServer(t, pub, "agent-1", "agent_principal:9", "acme", "active")
	v := newComponentVerifier(t, srv.URL+"/capabilitygrant/v1/keys")

	tok := mintAgentJWTClaims(t, priv, "agent-1", jwt.MapClaims{
		"iss":             "host-abc",
		"sub":             "agent-1",
		"aud":             testAudience,
		"iat":             time.Now().Add(-time.Second).Unix(),
		"jti":             "jti-no-exp",
		"component_scope": "component:hello",
		// deliberately no "exp"
	})
	if _, err := v.Verify(context.Background(), tok, testMethod); !errors.Is(err, ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired (token with no exp must be rejected)", err)
	}
}

// TestComponentVerify_RejectsOverlongLifetime — a component token is signed
// per RPC and lives ~55s. One minted with a day-long lifetime is a durable
// bearer credential and must be rejected however well it is signed.
func TestComponentVerify_RejectsOverlongLifetime(t *testing.T) {
	pub, priv := mustGenKey(t)
	srv := startDescriptorServer(t, pub, "agent-1", "agent_principal:9", "acme", "active")
	v := newComponentVerifier(t, srv.URL+"/capabilitygrant/v1/keys")

	now := time.Now()
	tok := mintAgentJWTClaims(t, priv, "agent-1", jwt.MapClaims{
		"iss":             "host-abc",
		"sub":             "agent-1",
		"aud":             testAudience,
		"iat":             now.Unix(),
		"exp":             now.Add(24 * time.Hour).Unix(),
		"jti":             "jti-long",
		"component_scope": "component:hello",
	})
	if _, err := v.Verify(context.Background(), tok, testMethod); !errors.Is(err, ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired (24h lifetime exceeds the per-RPC bound)", err)
	}
}

// TestComponentVerify_RejectsMissingIssuedAt — without iat the token's claimed
// lifetime is unknowable, so the lifetime bound cannot be enforced. Both SDKs
// that mint agent+jwt always set it.
func TestComponentVerify_RejectsMissingIssuedAt(t *testing.T) {
	pub, priv := mustGenKey(t)
	srv := startDescriptorServer(t, pub, "agent-1", "agent_principal:9", "acme", "active")
	v := newComponentVerifier(t, srv.URL+"/capabilitygrant/v1/keys")

	tok := mintAgentJWTClaims(t, priv, "agent-1", jwt.MapClaims{
		"iss":             "host-abc",
		"sub":             "agent-1",
		"aud":             testAudience,
		"exp":             time.Now().Add(30 * time.Second).Unix(),
		"jti":             "jti-no-iat",
		"component_scope": "component:hello",
		// deliberately no "iat"
	})
	if _, err := v.Verify(context.Background(), tok, testMethod); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed (token with no iat must be rejected)", err)
	}
}

// TestComponentVerify_AudiencePinned — when the deployment pins expected
// audiences, a token addressed elsewhere is rejected, and one addressed to a
// pinned audience still verifies.
func TestComponentVerify_AudiencePinned(t *testing.T) {
	pub, priv := mustGenKey(t)
	srv := startDescriptorServer(t, pub, "agent-1", "agent_principal:9", "acme", "active")
	v, err := NewComponentVerifier(ComponentConfig{
		KeysBaseURL:       srv.URL + "/capabilitygrant/v1/keys",
		TTL:               time.Minute,
		ExpectedAudiences: []string{"https://daemon/expected"},
		HTTPClient:        &http.Client{Timeout: 5 * time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}

	wrong := mintAgentJWTClaims(t, priv, "agent-1", jwt.MapClaims{
		"iss": "host-abc", "sub": "agent-1", "aud": "https://elsewhere/x",
		"iat": time.Now().Add(-time.Second).Unix(),
		"exp": time.Now().Add(30 * time.Second).Unix(),
		"jti": "jti-aud-wrong", "component_scope": "component:hello",
	})
	if _, err := v.Verify(context.Background(), wrong, testMethod); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed (audience outside the pinned set)", err)
	}

	right := mintAgentJWTClaims(t, priv, "agent-1", jwt.MapClaims{
		"iss": "host-abc", "sub": "agent-1", "aud": "https://daemon/expected",
		"iat": time.Now().Add(-time.Second).Unix(),
		"exp": time.Now().Add(30 * time.Second).Unix(),
		"jti": "jti-aud-right", "method": testMethod, "component_scope": "component:hello",
	})
	if _, err := v.Verify(context.Background(), right, testMethod); err != nil {
		t.Fatalf("Verify with pinned audience: %v", err)
	}
}

func TestComponentVerify_UnknownKid404(t *testing.T) {
	pub, priv := mustGenKey(t)
	srv := startDescriptorServer(t, pub, "agent-1", "agent_principal:9", "acme", "active")
	v := newComponentVerifier(t, srv.URL+"/capabilitygrant/v1/keys")

	// Token kid the server 404s.
	tok := mintAgentJWT(t, priv, "missing", "agent+jwt", time.Now().Add(55*time.Second))
	_, err := v.Verify(context.Background(), tok, testMethod)
	if !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("err = %v, want ErrUnknownKey", err)
	}
}

// TestNewComponentVerifier_RequiresAudiences — the audience pin must not be
// constructible in its permissive form. Before this, ExpectedAudiences was
// simply never set by the ext-authz binary, so the aud check was configured
// and dead (GHSA-4pv5-gx9c-x526); an empty list has to be a construction
// error, not "accept anything".
func TestNewComponentVerifier_RequiresAudiences(t *testing.T) {
	for name, auds := range map[string][]string{
		"nil":             nil,
		"empty slice":     {},
		"whitespace only": {"   "},
		"empty strings":   {"", ""},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewComponentVerifier(ComponentConfig{
				KeysBaseURL:       "https://daemon/capabilitygrant/v1/keys",
				ExpectedAudiences: auds,
				HTTPClient:        &http.Client{Timeout: 5 * time.Second},
			})
			if err == nil {
				t.Fatal("NewComponentVerifier accepted an empty audience pin; it must fail closed")
			}
			if !strings.Contains(err.Error(), "ExpectedAudiences") {
				t.Fatalf("err = %v, want it to name ExpectedAudiences", err)
			}
		})
	}
}

// TestComponentVerify_AudienceListIsOredNotOverwritten — jwt.WithAudience
// ASSIGNS the expected set rather than appending, so configuring several
// audiences via one option call per entry would pin only the last and reject
// every other. Every configured audience must verify.
func TestComponentVerify_AudienceListIsOredNotOverwritten(t *testing.T) {
	pub, priv := mustGenKey(t)
	srv := startDescriptorServer(t, pub, "agent-1", "agent_principal:9", "acme", "active")
	auds := []string{"https://daemon/first", "https://daemon/second"}
	v, err := NewComponentVerifier(ComponentConfig{
		KeysBaseURL:       srv.URL + "/capabilitygrant/v1/keys",
		TTL:               time.Minute,
		ExpectedAudiences: auds,
		HTTPClient:        &http.Client{Timeout: 5 * time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, aud := range auds {
		tok := mintAgentJWTClaims(t, priv, "agent-1", jwt.MapClaims{
			"iss": "host-abc", "sub": "agent-1", "aud": aud,
			"iat": time.Now().Add(-time.Second).Unix(),
			"exp": time.Now().Add(30 * time.Second).Unix(),
			"jti": freshJTI(), "method": testMethod, "component_scope": "component:hello",
		})
		if _, err := v.Verify(context.Background(), tok, testMethod); err != nil {
			t.Errorf("Verify with configured audience %q: %v", aud, err)
		}
	}

	off := mintAgentJWTClaims(t, priv, "agent-1", jwt.MapClaims{
		"iss": "host-abc", "sub": "agent-1", "aud": "https://daemon/third",
		"iat": time.Now().Add(-time.Second).Unix(),
		"exp": time.Now().Add(30 * time.Second).Unix(),
		"jti": freshJTI(), "method": testMethod, "component_scope": "component:hello",
	})
	if _, err := v.Verify(context.Background(), off, testMethod); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed (audience outside the configured set)", err)
	}
}

// TestComponentVerify_RejectsMissingAudience — a token that carries no aud at
// all must not slide past the pin. golang-jwt only requires the claim when an
// audience is expected, which the constructor now guarantees.
func TestComponentVerify_RejectsMissingAudience(t *testing.T) {
	pub, priv := mustGenKey(t)
	srv := startDescriptorServer(t, pub, "agent-1", "agent_principal:9", "acme", "active")
	v := newComponentVerifier(t, srv.URL+"/capabilitygrant/v1/keys")

	tok := mintAgentJWTClaims(t, priv, "agent-1", jwt.MapClaims{
		"iss": "host-abc", "sub": "agent-1",
		"iat": time.Now().Add(-time.Second).Unix(),
		"exp": time.Now().Add(30 * time.Second).Unix(),
		"jti": freshJTI(), "method": testMethod, "component_scope": "component:hello",
		// deliberately no "aud"
	})
	if _, err := v.Verify(context.Background(), tok, testMethod); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed (token with no aud must be rejected)", err)
	}
}

// TestComponentVerify_RejectsReplay — gibson#1246. A component token carries
// no binding to the request it travels with, so a captured one is replayable
// for its whole lifetime. The second presentation of the same (kid, jti) must
// be refused even though signature, descriptor, audience and lifetime are all
// still good.
func TestComponentVerify_RejectsReplay(t *testing.T) {
	pub, priv := mustGenKey(t)
	srv := startDescriptorServer(t, pub, "agent-1", "agent_principal:9", "acme", "active")
	v := newComponentVerifier(t, srv.URL+"/capabilitygrant/v1/keys")

	tok := mintAgentJWT(t, priv, "agent-1", "agent+jwt", time.Now().Add(55*time.Second))

	if _, err := v.Verify(context.Background(), tok, testMethod); err != nil {
		t.Fatalf("first presentation: %v", err)
	}
	_, err := v.Verify(context.Background(), tok, testMethod)
	if !errors.Is(err, ErrReplayed) {
		t.Fatalf("second presentation err = %v, want ErrReplayed", err)
	}
}

// TestComponentVerify_DistinctJTIStillPasses — the replay cache must not turn
// into a general denial. Every RPC mints a fresh token with a fresh jti, so
// back-to-back calls from the same component all have to verify.
func TestComponentVerify_DistinctJTIStillPasses(t *testing.T) {
	pub, priv := mustGenKey(t)
	srv := startDescriptorServer(t, pub, "agent-1", "agent_principal:9", "acme", "active")
	v := newComponentVerifier(t, srv.URL+"/capabilitygrant/v1/keys")

	for i := 0; i < 5; i++ {
		tok := mintAgentJWT(t, priv, "agent-1", "agent+jwt", time.Now().Add(55*time.Second))
		if _, err := v.Verify(context.Background(), tok, testMethod); err != nil {
			t.Fatalf("call %d with a distinct jti: %v", i, err)
		}
	}
}

// TestComponentVerify_RejectsMissingJTI — without a jti there is nothing to
// deduplicate on, so accepting such a token would be an opt-out of the replay
// check that any captured token could take. Both SDKs always mint one.
func TestComponentVerify_RejectsMissingJTI(t *testing.T) {
	pub, priv := mustGenKey(t)
	srv := startDescriptorServer(t, pub, "agent-1", "agent_principal:9", "acme", "active")
	v := newComponentVerifier(t, srv.URL+"/capabilitygrant/v1/keys")

	tok := mintAgentJWTClaims(t, priv, "agent-1", jwt.MapClaims{
		"iss": "host-abc", "sub": "agent-1", "aud": testAudience,
		"iat":             time.Now().Add(-time.Second).Unix(),
		"exp":             time.Now().Add(30 * time.Second).Unix(),
		"method":          testMethod,
		"component_scope": "component:hello",
		// deliberately no "jti"
	})
	if _, err := v.Verify(context.Background(), tok, testMethod); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed (token with no jti must be rejected)", err)
	}
}

// TestComponentVerify_ReplayIsScopedToKid — the jti is namespaced by the
// signing kid, so one component cannot burn another's jti. That matters
// because a shared namespace would hand any component a denial-of-service
// primitive against every other.
func TestComponentVerify_ReplayIsScopedToKid(t *testing.T) {
	pubA, privA := mustGenKey(t)
	pubB, privB := mustGenKey(t)

	mux := http.NewServeMux()
	for kid, pub := range map[string]ed25519.PublicKey{"agent-a": pubA, "agent-b": pubB} {
		doc := map[string]any{
			"keys": []map[string]string{{
				"kty": "OKP", "crv": "Ed25519",
				"x":   base64.RawURLEncoding.EncodeToString(pub),
				"kid": kid, "alg": "EdDSA", "use": "sig",
			}},
			"principal": "agent_principal:" + kid,
			"tenant":    "acme",
			"status":    "active",
		}
		body, _ := json.Marshal(doc)
		mux.HandleFunc("/capabilitygrant/v1/keys/"+kid, func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(body)
		})
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	v := newComponentVerifier(t, srv.URL+"/capabilitygrant/v1/keys")

	shared := "collision-jti"
	claims := func(kid string) jwt.MapClaims {
		return jwt.MapClaims{
			"iss": "host-abc", "sub": kid, "aud": testAudience,
			"iat": time.Now().Add(-time.Second).Unix(),
			"exp": time.Now().Add(30 * time.Second).Unix(),
			"jti": shared, "method": testMethod, "component_scope": "component:hello",
		}
	}

	if _, err := v.Verify(context.Background(), mintAgentJWTClaims(t, privA, "agent-a", claims("agent-a")), testMethod); err != nil {
		t.Fatalf("agent-a first use: %v", err)
	}
	// Same jti string, different signing key: a different token entirely.
	if _, err := v.Verify(context.Background(), mintAgentJWTClaims(t, privB, "agent-b", claims("agent-b")), testMethod); err != nil {
		t.Fatalf("agent-b must not be denied by agent-a's jti: %v", err)
	}
	// But agent-a replaying its own is still caught.
	if _, err := v.Verify(context.Background(), mintAgentJWTClaims(t, privA, "agent-a", claims("agent-a")), testMethod); !errors.Is(err, ErrReplayed) {
		t.Fatalf("agent-a replay err = %v, want ErrReplayed", err)
	}
}

// TestComponentVerify_MethodMatchAccepts — the request-binding happy path
// (gibson#1246): a token minted for the exact method the request carries
// verifies, and the request method Verify receives is the one it must match.
func TestComponentVerify_MethodMatchAccepts(t *testing.T) {
	pub, priv := mustGenKey(t)
	srv := startDescriptorServer(t, pub, "agent-1", "agent_principal:9", "acme", "active")
	v := newComponentVerifier(t, srv.URL+"/capabilitygrant/v1/keys")

	const method = "/gibson.daemon.v1.DaemonService/GetMission"
	tok := mintAgentJWTClaims(t, priv, "agent-1", jwt.MapClaims{
		"iss": "host-abc", "sub": "agent-1", "aud": testAudience,
		"iat":             time.Now().Add(-time.Second).Unix(),
		"exp":             time.Now().Add(30 * time.Second).Unix(),
		"jti":             freshJTI(),
		"method":          method,
		"component_scope": "component:hello",
	})
	if _, err := v.Verify(context.Background(), tok, method); err != nil {
		t.Fatalf("Verify with matching method: %v", err)
	}
}

// TestComponentVerify_RejectsMethodMismatch — gibson#1246 cross-RPC replay. A
// token minted for one method, presented at another, is refused even though
// signature, descriptor, audience, lifetime and jti are all good.
func TestComponentVerify_RejectsMethodMismatch(t *testing.T) {
	pub, priv := mustGenKey(t)
	srv := startDescriptorServer(t, pub, "agent-1", "agent_principal:9", "acme", "active")
	v := newComponentVerifier(t, srv.URL+"/capabilitygrant/v1/keys")

	tok := mintAgentJWTClaims(t, priv, "agent-1", jwt.MapClaims{
		"iss": "host-abc", "sub": "agent-1", "aud": testAudience,
		"iat":             time.Now().Add(-time.Second).Unix(),
		"exp":             time.Now().Add(30 * time.Second).Unix(),
		"jti":             freshJTI(),
		"method":          "/gibson.daemon.v1.DaemonService/GetMission",
		"component_scope": "component:hello",
	})
	// Presented at a DIFFERENT method than it was minted for.
	_, err := v.Verify(context.Background(), tok, "/gibson.daemon.v1.DaemonService/DeleteMission")
	if !errors.Is(err, ErrMethodMismatch) {
		t.Fatalf("err = %v, want ErrMethodMismatch (cross-RPC replay)", err)
	}
}

// TestComponentVerify_RejectsMissingMethod — the deleted unbound-token path. A
// token with no method claim is refused, not accepted: before gibson#1246 every
// component token was unbound and replayable against any RPC. Signature,
// descriptor, audience, lifetime and jti are all good; the absent method alone
// sinks it.
func TestComponentVerify_RejectsMissingMethod(t *testing.T) {
	pub, priv := mustGenKey(t)
	srv := startDescriptorServer(t, pub, "agent-1", "agent_principal:9", "acme", "active")
	v := newComponentVerifier(t, srv.URL+"/capabilitygrant/v1/keys")

	tok := mintAgentJWTClaims(t, priv, "agent-1", jwt.MapClaims{
		"iss": "host-abc", "sub": "agent-1", "aud": testAudience,
		"iat":             time.Now().Add(-time.Second).Unix(),
		"exp":             time.Now().Add(30 * time.Second).Unix(),
		"jti":             freshJTI(),
		"component_scope": "component:hello",
		// deliberately no "method"
	})
	if _, err := v.Verify(context.Background(), tok, testMethod); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed (unbound token with no method claim must be rejected)", err)
	}
}
