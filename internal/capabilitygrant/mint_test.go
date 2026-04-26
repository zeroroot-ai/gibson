package capabilitygrant

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/zero-day-ai/gibson/internal/types"
	"github.com/zero-day-ai/sdk/capabilitygrant"
)

// fixedKeyProvider is a test double for crypto.KeyProvider returning
// a fixed master key.
type fixedKeyProvider struct{ key []byte }

func (f *fixedKeyProvider) GetEncryptionKey(ctx context.Context) ([]byte, error) {
	return f.key, nil
}
func (f *fixedKeyProvider) Name() string                                    { return "test" }
func (f *fixedKeyProvider) Health(ctx context.Context) any                  { return nil }
func (f *fixedKeyProvider) Close() error                                    { return nil }

// Adapt to crypto.KeyProvider's actual signature with HealthStatus by
// using struct{} placeholder. The mint.go code only calls
// GetEncryptionKey, so satisfying that one method is enough at
// compile time via interface widening. The test imports cast to the
// real interface via a tiny wrapper.

func TestMinter_HappyPath(t *testing.T) {
	master := strings.Repeat("k", 32)
	m, err := NewMinter(context.Background(), Config{
		Issuer:      "https://test.daemon",
		Audience:    "test-daemon",
		KeyProvider: kpAdapter{[]byte(master)},
		KeyID:       "k1",
	})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := m.Mint(MintRequest{
		Subject:     "agent-1",
		Tenant:      "acme",
		MissionID:   "m",
		TaskID:      "t",
		AllowedRPCs: []string{"/x.S/Y"},
		TTL:         5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Verify the JWT with the SDK verifier (round-trip).
	v, err := capabilitygrant.Verify(context.Background(), staticFetcher{kid: "k1", pub: m.PublicKey()}, tok, capabilitygrant.VerifyOptions{
		ExpectedIssuer:   "https://test.daemon",
		ExpectedAudience: "test-daemon",
	})
	if err != nil {
		t.Fatalf("round-trip verify failed: %v", err)
	}
	if v.Subject != "agent-1" || v.Tenant.String() != "acme" {
		t.Errorf("claims wrong: %+v", v)
	}
	if !v.AllowsMethod("/x.S/Y") {
		t.Error("AllowsMethod should hit")
	}
}

func TestMinter_RejectsTooShortMaster(t *testing.T) {
	_, err := NewMinter(context.Background(), Config{
		Issuer: "x", Audience: "y", KeyID: "k1",
		KeyProvider: kpAdapter{[]byte("short")},
	})
	if err == nil || !strings.Contains(err.Error(), "≥32") {
		t.Fatalf("expected size error, got %v", err)
	}
}

func TestMinter_RejectsMissingFields(t *testing.T) {
	master := strings.Repeat("k", 32)
	cases := []Config{
		{},
		{Issuer: "x"},
		{Issuer: "x", Audience: "y"},
		{Issuer: "x", Audience: "y", KeyProvider: kpAdapter{[]byte(master)}},
	}
	for i, c := range cases {
		if _, err := NewMinter(context.Background(), c); err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
}

func TestMintRequest_Validation(t *testing.T) {
	master := strings.Repeat("k", 32)
	m, _ := NewMinter(context.Background(), Config{
		Issuer: "x", Audience: "y", KeyID: "k", KeyProvider: kpAdapter{[]byte(master)},
	})
	if _, err := m.Mint(MintRequest{}); err == nil {
		t.Error("expected error on empty request")
	}
	if _, err := m.Mint(MintRequest{Subject: "a", Tenant: "b", MissionID: "c", TaskID: "d"}); err == nil {
		t.Error("expected error: AllowedRPCs required")
	}
}

func TestMintRequest_TTLCappedAtMax(t *testing.T) {
	master := strings.Repeat("k", 32)
	m, _ := NewMinter(context.Background(), Config{
		Issuer: "x", Audience: "y", KeyID: "k", KeyProvider: kpAdapter{[]byte(master)},
	})
	tok, _ := m.Mint(MintRequest{
		Subject: "a", Tenant: "b", MissionID: "c", TaskID: "d",
		AllowedRPCs: []string{"/x/y"},
		TTL:         1 * time.Hour, // > MaxLifetime
	})
	parsed, _ := jwt.Parse(tok, func(t *jwt.Token) (any, error) { return m.PublicKey(), nil })
	mc := parsed.Claims.(jwt.MapClaims)
	iat := int64(mc["iat"].(float64))
	exp := int64(mc["exp"].(float64))
	if exp-iat != int64(MaxLifetime.Seconds()) {
		t.Errorf("expected TTL capped at %s, got %d seconds", MaxLifetime, exp-iat)
	}
}

func TestJWKSHandler_ServesPubKey(t *testing.T) {
	master := strings.Repeat("k", 32)
	m, _ := NewMinter(context.Background(), Config{
		Issuer: "x", Audience: "y", KeyID: "k1", KeyProvider: kpAdapter{[]byte(master)},
	})
	h, err := NewJWKSHandler(m)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var js struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&js); err != nil {
		t.Fatal(err)
	}
	if len(js.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(js.Keys))
	}
	k := js.Keys[0]
	if k["kty"] != "OKP" || k["crv"] != "Ed25519" || k["kid"] != "k1" || k["alg"] != "EdDSA" {
		t.Errorf("jwk fields wrong: %+v", k)
	}
	x, err := base64.RawURLEncoding.DecodeString(k["x"])
	if err != nil {
		t.Fatal(err)
	}
	if string(x) != string(m.PublicKey()) {
		t.Error("public key mismatch")
	}
}

func TestDeriveEd25519_Deterministic(t *testing.T) {
	master := []byte(strings.Repeat("X", 32))
	p1, q1, err := deriveEd25519FromMaster(master)
	if err != nil {
		t.Fatal(err)
	}
	p2, q2, err := deriveEd25519FromMaster(master)
	if err != nil {
		t.Fatal(err)
	}
	if string(p1) != string(p2) || string(q1) != string(q2) {
		t.Fatal("derivation not deterministic")
	}
	master2 := []byte(strings.Repeat("Y", 32))
	p3, _, _ := deriveEd25519FromMaster(master2)
	if string(p1) == string(p3) {
		t.Fatal("different masters must produce different keys")
	}
}

// kpAdapter satisfies the real crypto.KeyProvider interface for tests.
type kpAdapter struct{ key []byte }

func (k kpAdapter) GetEncryptionKey(_ context.Context) ([]byte, error) { return k.key, nil }
func (k kpAdapter) Name() string                                       { return "test" }
func (k kpAdapter) Health(_ context.Context) types.HealthStatus {
	return types.HealthStatus{State: types.HealthStateHealthy}
}
func (k kpAdapter) Close() error { return nil }

// staticFetcher implements capabilitygrant.JWKSFetcher with a fixed
// kid → public key.
type staticFetcher struct {
	kid string
	pub any
}

func (f staticFetcher) Fetch(_ context.Context, kid string) (any, error) {
	if kid == f.kid {
		return f.pub, nil
	}
	return nil, errors.New("not found")
}
