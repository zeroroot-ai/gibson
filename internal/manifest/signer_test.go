package manifest

import (
	"crypto/ed25519"
	"errors"
	"testing"

	manifestpb "github.com/zero-day-ai/sdk/api/gen/gibson/manifest/v1"
)

func newTestManifest() *manifestpb.CapabilityManifest {
	return &manifestpb.CapabilityManifest{
		ManifestId:      "01TESTULID",
		ManifestVersion: 42,
		TenantId:        "tenant-acme",
		Subject:         "user:alice",
		TtlSeconds:      300,
		TenantContext: &manifestpb.TenantContext{
			TenantId:          "tenant-acme",
			TenantDisplayName: "ACME",
		},
	}
}

func TestSigner_SignVerify_Roundtrip(t *testing.T) {
	k, err := GenerateSignerKey("active-1")
	if err != nil {
		t.Fatalf("GenerateSignerKey: %v", err)
	}
	s, err := NewSigner("active-1", []SignerKey{k})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	m := newTestManifest()
	if err := s.Sign(m); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(m.Signature) != ed25519.SignatureSize {
		t.Fatalf("unexpected signature size: %d", len(m.Signature))
	}
	if m.SigningKeyId != "active-1" {
		t.Fatalf("SigningKeyId = %q, want active-1", m.SigningKeyId)
	}
	if err := s.Verify(m); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestSigner_Verify_TamperedBodyFails(t *testing.T) {
	k, _ := GenerateSignerKey("k1")
	s, _ := NewSigner("k1", []SignerKey{k})

	m := newTestManifest()
	if err := s.Sign(m); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// Mutate an arbitrary body field after signing.
	m.TenantId = "tenant-other"
	err := s.Verify(m)
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("Verify returned %v, want ErrBadSignature", err)
	}
}

func TestSigner_Verify_MutatedSignatureFails(t *testing.T) {
	k, _ := GenerateSignerKey("k1")
	s, _ := NewSigner("k1", []SignerKey{k})

	m := newTestManifest()
	if err := s.Sign(m); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// Flip a byte in the signature.
	m.Signature[0] ^= 0xFF
	err := s.Verify(m)
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("Verify returned %v, want ErrBadSignature", err)
	}
}

func TestSigner_Verify_RotationTwoKeys(t *testing.T) {
	// Signer holds two keys: sign with k1 (active), verify even after
	// rotating to k2 — k1 stays in the key map as verify-only during the
	// rotation window.
	k1, _ := GenerateSignerKey("k1")
	k2, _ := GenerateSignerKey("k2")

	signer1, err := NewSigner("k1", []SignerKey{k1, k2})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	m := newTestManifest()
	if err := signer1.Sign(m); err != nil {
		t.Fatalf("Sign with k1: %v", err)
	}
	if m.SigningKeyId != "k1" {
		t.Fatalf("SigningKeyId = %q, want k1", m.SigningKeyId)
	}

	// Second Signer: verify-only on k1 (private stripped), active k2.
	k1VerifyOnly := SignerKey{Kid: "k1", Public: k1.Public}
	signer2, err := NewSigner("k2", []SignerKey{k2, k1VerifyOnly})
	if err != nil {
		t.Fatalf("NewSigner rotated: %v", err)
	}
	if err := signer2.Verify(m); err != nil {
		t.Fatalf("post-rotation verify: %v", err)
	}
}

func TestSigner_Verify_UnknownKidRejected(t *testing.T) {
	k, _ := GenerateSignerKey("k1")
	s, _ := NewSigner("k1", []SignerKey{k})
	m := newTestManifest()
	if err := s.Sign(m); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	m.SigningKeyId = "unknown-kid"
	err := s.Verify(m)
	if !errors.Is(err, ErrUnknownSigningKey) {
		t.Fatalf("Verify returned %v, want ErrUnknownSigningKey", err)
	}
}

func TestSigner_Verify_MissingSignature(t *testing.T) {
	k, _ := GenerateSignerKey("k1")
	s, _ := NewSigner("k1", []SignerKey{k})
	m := newTestManifest()
	// never signed
	err := s.Verify(m)
	if !errors.Is(err, ErrMissingSignature) {
		t.Fatalf("Verify returned %v, want ErrMissingSignature", err)
	}
}

func TestSigner_VerifyDoesNotMutateCaller(t *testing.T) {
	k, _ := GenerateSignerKey("k1")
	s, _ := NewSigner("k1", []SignerKey{k})
	m := newTestManifest()
	if err := s.Sign(m); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	sigBefore := append([]byte(nil), m.Signature...)
	kidBefore := m.SigningKeyId
	if err := s.Verify(m); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if string(m.Signature) != string(sigBefore) {
		t.Fatalf("Verify mutated m.Signature")
	}
	if m.SigningKeyId != kidBefore {
		t.Fatalf("Verify mutated m.SigningKeyId")
	}
}

func TestSigner_PublishedKeys_ActiveFirst(t *testing.T) {
	k1, _ := GenerateSignerKey("k1")
	k2, _ := GenerateSignerKey("k2")
	k3, _ := GenerateSignerKey("k3")
	s, err := NewSigner("k2", []SignerKey{k1, k2, k3})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	published := s.PublishedKeys()
	if len(published) != 3 {
		t.Fatalf("PublishedKeys len = %d, want 3", len(published))
	}
	if published[0].Kid != "k2" {
		t.Fatalf("active kid should be first, got %q", published[0].Kid)
	}
	for _, k := range published {
		if k.Kty != "OKP" || k.Crv != "Ed25519" || k.Alg != "EdDSA" {
			t.Fatalf("unexpected JWK header: %+v", k)
		}
		if k.X == "" {
			t.Fatalf("kid %q has empty x", k.Kid)
		}
	}
}

func TestNewSigner_Errors(t *testing.T) {
	k, _ := GenerateSignerKey("k1")
	cases := []struct {
		name      string
		activeKid string
		keys      []SignerKey
	}{
		{"empty active", "", []SignerKey{k}},
		{"no keys", "k1", nil},
		{"unknown active", "other", []SignerKey{k}},
		{"active verify-only", "k1", []SignerKey{{Kid: "k1", Public: k.Public}}},
		{"kid missing", "k1", []SignerKey{{Public: k.Public, Private: k.Private}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := NewSigner(c.activeKid, c.keys); err == nil {
				t.Fatalf("expected error for %s", c.name)
			}
		})
	}
}
