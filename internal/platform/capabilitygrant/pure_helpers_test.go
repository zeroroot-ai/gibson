package capabilitygrant

// pure_helpers_test.go covers the package's pure, infra-free helpers that were
// previously untested (0% coverage): the capability-name / FGA-prefix parsers,
// the agent-id and JWK-thumbprint generators, the sql.Null* converters, and the
// per-kid key-descriptor renderer plus Minter.PublicKeyJWKS. These are
// security-relevant string/crypto routines, so a regression here is exactly the
// kind that silently breaks identity verification. No DB / FGA / network.

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"
)

// --- service.go: parseCapabilityName -----------------------------------------

func TestParseCapabilityName(t *testing.T) {
	cases := []struct {
		in                        string
		wantRef, wantKind, wantNm string
		wantOK                    bool
	}{
		{"read:tool:scanner", "component:scanner", "tool", "scanner", true},
		{"exec:plugin:gitlab", "component:gitlab", "plugin", "gitlab", true},
		// SplitN(_,3) keeps extra colons in the name segment.
		{"read:tool:a:b:c", "component:a:b:c", "tool", "a:b:c", true},
		// Empty verb is permitted — only kind and name must be non-empty.
		{":tool:scanner", "component:scanner", "tool", "scanner", true},
		// Invalid shapes.
		{"tool:scanner", "", "", "", false},
		{"read::scanner", "", "", "", false},
		{"read:tool:", "", "", "", false},
		{"", "", "", "", false},
		{"singletoken", "", "", "", false},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			ref, kind, nm, ok := parseCapabilityName(c.in)
			if ok != c.wantOK || ref != c.wantRef || kind != c.wantKind || nm != c.wantNm {
				t.Fatalf("parseCapabilityName(%q) = (%q,%q,%q,%v), want (%q,%q,%q,%v)",
					c.in, ref, kind, nm, ok, c.wantRef, c.wantKind, c.wantNm, c.wantOK)
			}
		})
	}
}

// --- service.go: stripFGATypePrefix ------------------------------------------

func TestStripFGATypePrefix(t *testing.T) {
	cases := []struct {
		s, typeName, want string
	}{
		{"tenant:acme", "tenant", "acme"},
		{"component:scanner:v2", "component", "scanner:v2"}, // only first prefix stripped
		{"acme", "tenant", "acme"},                          // no prefix → unchanged
		{"user:alice", "tenant", "user:alice"},              // wrong prefix → unchanged
		{"tenant:", "tenant", "tenant:"},                    // prefix with empty remainder → unchanged
		{"tenant:x", "tenant", "x"},
	}
	for _, c := range cases {
		t.Run(c.s+"|"+c.typeName, func(t *testing.T) {
			if got := stripFGATypePrefix(c.s, c.typeName); got != c.want {
				t.Fatalf("stripFGATypePrefix(%q,%q) = %q, want %q", c.s, c.typeName, got, c.want)
			}
		})
	}
}

// --- service.go: newAgentID --------------------------------------------------

var agentIDRe = regexp.MustCompile(`^agt_[0-9a-f]{16}$`)

func TestNewAgentID(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		id, err := newAgentID()
		if err != nil {
			t.Fatalf("newAgentID: %v", err)
		}
		if !agentIDRe.MatchString(id) {
			t.Fatalf("newAgentID = %q, want match %s", id, agentIDRe)
		}
		if seen[id] {
			t.Fatalf("newAgentID produced a duplicate: %q", id)
		}
		seen[id] = true
	}
}

// --- service.go: jwkThumbprint -----------------------------------------------

var hostIDRe = regexp.MustCompile(`^host_[0-9a-f]{16}$`)

func TestJWKThumbprint(t *testing.T) {
	a := json.RawMessage(`{"kty":"OKP","crv":"Ed25519","x":"AAAA"}`)
	b := json.RawMessage(`{"kty":"OKP","crv":"Ed25519","x":"BBBB"}`)

	ta, err := jwkThumbprint(a)
	if err != nil {
		t.Fatalf("jwkThumbprint(a): %v", err)
	}
	if !hostIDRe.MatchString(ta) {
		t.Fatalf("jwkThumbprint = %q, want match %s", ta, hostIDRe)
	}

	// Deterministic for identical input.
	ta2, _ := jwkThumbprint(a)
	if ta != ta2 {
		t.Fatalf("jwkThumbprint not deterministic: %q != %q", ta, ta2)
	}

	// Different input → different thumbprint (collision would be a real bug).
	tb, _ := jwkThumbprint(b)
	if ta == tb {
		t.Fatalf("distinct JWKs produced the same thumbprint %q", ta)
	}

	// Empty JWK is rejected.
	if _, err := jwkThumbprint(json.RawMessage(nil)); err == nil {
		t.Fatal("jwkThumbprint(empty) should error")
	}
}

// --- store.go: nullableString / nullableTime ---------------------------------

func TestNullableString(t *testing.T) {
	if ns := nullableString(""); ns.Valid {
		t.Fatalf("nullableString(\"\") should be NULL, got %+v", ns)
	}
	ns := nullableString("hello")
	if !ns.Valid || ns.String != "hello" {
		t.Fatalf("nullableString(\"hello\") = %+v, want valid \"hello\"", ns)
	}
}

func TestNullableTime(t *testing.T) {
	if nt := nullableTime(nil); nt.Valid {
		t.Fatalf("nullableTime(nil) should be NULL, got %+v", nt)
	}
	now := time.Now()
	nt := nullableTime(&now)
	if !nt.Valid || !nt.Time.Equal(now) {
		t.Fatalf("nullableTime(&now) = %+v, want valid %v", nt, now)
	}
}

// --- mint.go: buildKeyDescriptor ---------------------------------------------

// keyDescriptor mirrors the JSON buildKeyDescriptor emits.
type keyDescriptor struct {
	Keys []struct {
		Kty, Crv, X, Kid, Use, Alg string
	} `json:"keys"`
	Principal string `json:"principal"`
	Tenant    string `json:"tenant"`
	Status    string `json:"status"`
}

func TestBuildKeyDescriptor(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	raw, err := buildKeyDescriptor(pub, "kid-1", "agent_principal:acme", "acme", "active")
	if err != nil {
		t.Fatalf("buildKeyDescriptor: %v", err)
	}
	var d keyDescriptor
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatalf("unmarshal descriptor: %v", err)
	}
	if len(d.Keys) != 1 {
		t.Fatalf("want 1 key, got %d", len(d.Keys))
	}
	k := d.Keys[0]
	if k.Kty != "OKP" || k.Crv != "Ed25519" || k.Use != "sig" || k.Alg != "EdDSA" || k.Kid != "kid-1" {
		t.Fatalf("unexpected jwk header: %+v", k)
	}
	gotPub, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		t.Fatalf("decode x: %v", err)
	}
	if !ed25519.PublicKey(gotPub).Equal(pub) {
		t.Fatal("descriptor x does not round-trip to the public key")
	}
	if d.Principal != "agent_principal:acme" || d.Tenant != "acme" || d.Status != "active" {
		t.Fatalf("authz fields wrong: principal=%q tenant=%q status=%q", d.Principal, d.Tenant, d.Status)
	}
	// The descriptor must parse back through the production single-JWK parser.
	jwkBytes, _ := json.Marshal(map[string]string{"kty": k.Kty, "crv": k.Crv, "x": k.X})
	if _, err := parseJWKEd25519(jwkBytes); err != nil {
		t.Fatalf("descriptor key not parseable by parseJWKEd25519: %v", err)
	}
}

func TestBuildKeyDescriptor_OmitsEmptyAuthzFields(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	raw, err := buildKeyDescriptor(pub, "kid", "", "", "")
	if err != nil {
		t.Fatalf("buildKeyDescriptor: %v", err)
	}
	s := string(raw)
	for _, field := range []string{"principal", "tenant", "status"} {
		if strings.Contains(s, field) {
			t.Fatalf("empty %q should be omitted, got %s", field, s)
		}
	}
}

// --- mint.go: Minter.PublicKeyJWKS -------------------------------------------

func TestMinterPublicKeyJWKS(t *testing.T) {
	master := strings.Repeat("m", 32)
	m, err := NewMinter(context.Background(), Config{
		Issuer:      "https://test.daemon",
		Audience:    "test-daemon",
		KeyProvider: kpAdapter{[]byte(master)},
		KeyID:       "k1",
	})
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}

	body, err := m.PublicKeyJWKS()
	if err != nil {
		t.Fatalf("PublicKeyJWKS: %v", err)
	}
	var set struct {
		Keys []struct{ Kid, X, Kty, Crv string } `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil {
		t.Fatalf("unmarshal JWKS: %v", err)
	}
	if len(set.Keys) != 1 || set.Keys[0].Kid != "k1" {
		t.Fatalf("want single key kid=k1, got %+v", set.Keys)
	}
	pub, err := base64.RawURLEncoding.DecodeString(set.Keys[0].X)
	if err != nil {
		t.Fatalf("decode x: %v", err)
	}
	if !ed25519.PublicKey(pub).Equal(m.PublicKey()) {
		t.Fatal("JWKS x does not match the minter public key")
	}
}
