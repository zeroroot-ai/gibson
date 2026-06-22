package cgjwt

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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

func mintAgentJWT(t *testing.T, priv ed25519.PrivateKey, kid string, typ string, exp time.Time) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"iss":             "host-abc",
		"sub":             kid, // agent row id
		"aud":             "https://daemon/x",
		"iat":             time.Now().Add(-time.Second).Unix(),
		"exp":             exp.Unix(),
		"jti":             "jti-1",
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
	v, err := NewComponentVerifier(ComponentConfig{KeysBaseURL: base, TTL: time.Minute})
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
	id, err := v.Verify(context.Background(), tok)
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
	_, err := v.Verify(context.Background(), tok)
	if !errors.Is(err, ErrSignature) {
		t.Fatalf("err = %v, want ErrSignature", err)
	}
}

func TestComponentVerify_RejectsExpired(t *testing.T) {
	pub, priv := mustGenKey(t)
	srv := startDescriptorServer(t, pub, "agent-1", "agent_principal:9", "acme", "active")
	v := newComponentVerifier(t, srv.URL+"/capabilitygrant/v1/keys")

	tok := mintAgentJWT(t, priv, "agent-1", "agent+jwt", time.Now().Add(-time.Minute))
	_, err := v.Verify(context.Background(), tok)
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired", err)
	}
}

func TestComponentVerify_RejectsWrongTyp(t *testing.T) {
	pub, priv := mustGenKey(t)
	srv := startDescriptorServer(t, pub, "agent-1", "agent_principal:9", "acme", "active")
	v := newComponentVerifier(t, srv.URL+"/capabilitygrant/v1/keys")

	tok := mintAgentJWT(t, priv, "agent-1", "host+jwt", time.Now().Add(55*time.Second))
	_, err := v.Verify(context.Background(), tok)
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
}

func TestComponentVerify_RejectsInactiveAgent(t *testing.T) {
	pub, priv := mustGenKey(t)
	srv := startDescriptorServer(t, pub, "agent-1", "agent_principal:9", "acme", "revoked")
	v := newComponentVerifier(t, srv.URL+"/capabilitygrant/v1/keys")

	tok := mintAgentJWT(t, priv, "agent-1", "agent+jwt", time.Now().Add(55*time.Second))
	_, err := v.Verify(context.Background(), tok)
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
	_, err := v.Verify(context.Background(), tok)
	if !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("err = %v, want ErrUnknownKey (no principal binding)", err)
	}
}

func TestComponentVerify_UnknownKid404(t *testing.T) {
	pub, priv := mustGenKey(t)
	srv := startDescriptorServer(t, pub, "agent-1", "agent_principal:9", "acme", "active")
	v := newComponentVerifier(t, srv.URL+"/capabilitygrant/v1/keys")

	// Token kid the server 404s.
	tok := mintAgentJWT(t, priv, "missing", "agent+jwt", time.Now().Add(55*time.Second))
	_, err := v.Verify(context.Background(), tok)
	if !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("err = %v, want ErrUnknownKey", err)
	}
}
