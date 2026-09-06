// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- service.go: parseCapabilityName -----------------------------------------

func TestParseCapabilityName(t *testing.T) {
	cases := []struct {
		in                        string
		wantRef, wantKind, wantNm string
		wantOK                    bool
	}{
		{"read:tool:scanner", "component:tool/scanner", "tool", "scanner", true},
		{"exec:plugin:gitlab", "component:plugin/gitlab", "plugin", "gitlab", true},
		// SplitN(_,3) keeps extra colons in the name segment.
		{"read:tool:a:b:c", "component:tool/a:b:c", "tool", "a:b:c", true},
		// Empty verb is permitted — only kind and name must be non-empty.
		{":tool:scanner", "component:tool/scanner", "tool", "scanner", true},
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

// TestJWKThumbprint_IsRFC7638 pins the host id to the value a CLIENT computes.
//
// The client signs its host+jwt with `iss` set to this, and the daemon looks the
// host up by that value, so anything the client cannot derive means every
// re-registration is an unknown-host 401 and the persisted host key never works
// (gibson#1207). The previous implementation hashed the raw JWK bytes and
// truncated to 8 — a "host_<hex>" id no client could produce.
func TestJWKThumbprint_IsRFC7638(t *testing.T) {
	// The exact JWK a live @zerocool/sdk host key put on the wire, with the
	// expected value computed independently by that SDK.
	wire := json.RawMessage(`{"crv":"Ed25519","x":"9MHYIq9gnPsXY0iGgWxMHfhoZmEDkrdah6ZnsDRuswA","kty":"OKP"}`)
	const want = "hvGAcvaHcyHh25fZLhJtXzXlGmQx0-wKFyvMYoMTa48"

	got, err := jwkThumbprint(wire)
	if err != nil {
		t.Fatalf("jwkThumbprint: %v", err)
	}
	if got != want {
		t.Fatalf("thumbprint = %q, want %q — the daemon must derive the same id the client signs", got, want)
	}
}

func TestJWKThumbprint_IgnoresFieldOrder(t *testing.T) {
	// RFC 7638 hashes canonical members in lexicographic order. Hashing the raw
	// bytes made the id depend on how the client happened to serialise its JWK,
	// which also made the "content-addressed, so re-registration is idempotent"
	// claim false.
	canonical := json.RawMessage(`{"crv":"Ed25519","kty":"OKP","x":"AAAA"}`)
	shuffled := json.RawMessage(`{"x":"AAAA","kty":"OKP","crv":"Ed25519"}`)
	spaced := json.RawMessage(`{ "kty" : "OKP", "crv" : "Ed25519", "x" : "AAAA" }`)

	a, err := jwkThumbprint(canonical)
	if err != nil {
		t.Fatalf("jwkThumbprint: %v", err)
	}
	for name, variant := range map[string]json.RawMessage{"shuffled": shuffled, "spaced": spaced} {
		got, gErr := jwkThumbprint(variant)
		if gErr != nil {
			t.Fatalf("jwkThumbprint(%s): %v", name, gErr)
		}
		if got != a {
			t.Errorf("%s JWK thumbprinted to %q, want %q — the same key must have one id", name, got, a)
		}
	}
}

func TestJWKThumbprint_DistinctKeysDistinctIDs(t *testing.T) {
	a, _ := jwkThumbprint(json.RawMessage(`{"kty":"OKP","crv":"Ed25519","x":"AAAA"}`))
	b, _ := jwkThumbprint(json.RawMessage(`{"kty":"OKP","crv":"Ed25519","x":"BBBB"}`))
	if a == b {
		t.Fatal("two different keys share a host id")
	}
}

func TestJWKThumbprint_RejectsAKeyTypeTheVerifierWouldRefuse(t *testing.T) {
	// Minting an id for a key the verifier cannot parse produces a host record
	// that can never authenticate — a 401 with a valid-looking registration
	// behind it.
	if _, err := jwkThumbprint(json.RawMessage(`{"kty":"EC","crv":"P-256","x":"AAAA"}`)); err == nil {
		t.Error("expected an error for a non-Ed25519 host key")
	}
	if _, err := jwkThumbprint(json.RawMessage(`{"kty":"OKP","crv":"Ed25519"}`)); err == nil {
		t.Error("expected an error for a JWK with no x coordinate")
	}
}

// --- service.go: capsWithinCeiling -------------------------------------------

func TestCapsWithinCeiling(t *testing.T) {
	caps := []Capability{
		{Name: "execute:tool:nmap"},
		{Name: "read:agent:recon"},
	}

	t.Run("empty ceiling leaves the FGA resolution unmodified", func(t *testing.T) {
		got := capsWithinCeiling(caps, nil)
		assert.Equal(t, caps, got)
	})

	t.Run("narrows to named entries only", func(t *testing.T) {
		got := capsWithinCeiling(caps, []string{"execute:tool:nmap"})
		require.Len(t, got, 1)
		assert.Equal(t, "execute:tool:nmap", got[0].Name)
	})

	t.Run("cannot widen: a ceiling entry FGA never produced grants nothing", func(t *testing.T) {
		got := capsWithinCeiling(caps, []string{"execute:tool:nmap", "execute:tool:never-granted"})
		require.Len(t, got, 1)
		assert.Equal(t, "execute:tool:nmap", got[0].Name)
	})

	t.Run("ceiling naming nothing FGA granted yields zero capabilities", func(t *testing.T) {
		got := capsWithinCeiling(caps, []string{"execute:tool:never-granted"})
		assert.Empty(t, got)
	})
}

// --- service.go: appendSessionCapabilities -----------------------------------

func TestAppendSessionCapabilities(t *testing.T) {
	t.Run("empty ceiling adds nothing", func(t *testing.T) {
		caps := []Capability{{Name: "execute:tool:nmap"}}
		got := appendSessionCapabilities(caps, nil)
		assert.Equal(t, caps, got)
	})

	t.Run("adds mission:delegate when the ceiling names it, unlike capsWithinCeiling which cannot", func(t *testing.T) {
		caps := []Capability{{Name: "execute:tool:nmap"}}
		got := appendSessionCapabilities(caps, []string{"mission:delegate"})
		require.Len(t, got, 2)
		names := []string{got[0].Name, got[1].Name}
		assert.Contains(t, names, "execute:tool:nmap")
		assert.Contains(t, names, "mission:delegate")
	})

	t.Run("adds both reserved names when both are ceiling entries", func(t *testing.T) {
		got := appendSessionCapabilities(nil, []string{"mission:delegate", "mission:originate"})
		require.Len(t, got, 2)
	})

	t.Run("an unreserved ceiling entry is not added — it can only narrow elsewhere", func(t *testing.T) {
		got := appendSessionCapabilities(nil, []string{"execute:tool:never-granted"})
		assert.Empty(t, got, "appendSessionCapabilities must never treat an arbitrary ceiling entry as grantable")
	})

	t.Run("does not duplicate a reserved capability already present", func(t *testing.T) {
		caps := []Capability{{Name: "mission:delegate", Description: "original"}}
		got := appendSessionCapabilities(caps, []string{"mission:delegate"})
		require.Len(t, got, 1)
		assert.Equal(t, "original", got[0].Description, "must not overwrite an existing entry")
	})

	t.Run("carries a non-empty description for both reserved names", func(t *testing.T) {
		got := appendSessionCapabilities(nil, []string{"mission:delegate", "mission:originate"})
		for _, c := range got {
			assert.NotEmpty(t, c.Description, "capability %q must carry a description for the audit trail", c.Name)
			assert.Empty(t, c.ComponentRef, "a session capability is not scoped to any component")
		}
	})
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
