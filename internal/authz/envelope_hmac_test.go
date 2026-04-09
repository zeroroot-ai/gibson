package authz

import (
	"crypto/hmac"
	"testing"
	"time"
)

func TestNewEnvelopeSigner_RandomSecret(t *testing.T) {
	s1, err := NewEnvelopeSigner()
	if err != nil {
		t.Fatalf("NewEnvelopeSigner: %v", err)
	}
	s2, err := NewEnvelopeSigner()
	if err != nil {
		t.Fatalf("NewEnvelopeSigner: %v", err)
	}
	// Two separate signers should have different secrets
	if hmac.Equal(s1.secret, s2.secret) {
		t.Error("two independently created signers have identical secrets")
	}
}

func TestSign_RoundTrip(t *testing.T) {
	signer, err := NewEnvelopeSigner()
	if err != nil {
		t.Fatalf("NewEnvelopeSigner: %v", err)
	}

	ctx := signer.Sign("mission-run-01", DefaultWorkTTLSeconds)

	if ctx.RunID != "mission-run-01" {
		t.Errorf("RunID mismatch: want %q got %q", "mission-run-01", ctx.RunID)
	}
	if ctx.TTLSeconds != DefaultWorkTTLSeconds {
		t.Errorf("TTLSeconds mismatch: want %d got %d", DefaultWorkTTLSeconds, ctx.TTLSeconds)
	}
	if len(ctx.Signature) == 0 {
		t.Error("Signature must not be empty")
	}

	// Recompute and verify.
	expected := computeHMACDaemon(signer.secret, ctx.RunID, ctx.IssuedAt, ctx.TTLSeconds)
	if !hmac.Equal(expected, ctx.Signature) {
		t.Error("recomputed HMAC does not match Signature")
	}
}

func TestSign_TamperedRunIDFails(t *testing.T) {
	signer, _ := NewEnvelopeSigner()
	ctx := signer.Sign("run-original", DefaultWorkTTLSeconds)

	// Verify original passes.
	expected := computeHMACDaemon(signer.secret, ctx.RunID, ctx.IssuedAt, ctx.TTLSeconds)
	if !hmac.Equal(expected, ctx.Signature) {
		t.Fatal("original context failed verification")
	}

	// Tamper with run_id.
	tampered := computeHMACDaemon(signer.secret, "run-tampered", ctx.IssuedAt, ctx.TTLSeconds)
	if hmac.Equal(tampered, ctx.Signature) {
		t.Error("tampered run_id produced the same signature (should not happen)")
	}
}

func TestSign_IssuedAtIsFresh(t *testing.T) {
	before := time.Now().Unix()
	signer, _ := NewEnvelopeSigner()
	ctx := signer.Sign("run-id", DefaultWorkTTLSeconds)
	after := time.Now().Unix()

	if ctx.IssuedAt < before || ctx.IssuedAt > after {
		t.Errorf("IssuedAt %d is not in range [%d, %d]", ctx.IssuedAt, before, after)
	}
}

func TestNewEnvelopeSignerWithSecret_TooShort(t *testing.T) {
	_, err := NewEnvelopeSignerWithSecret([]byte("short"))
	if err == nil {
		t.Error("expected error for secret shorter than 16 bytes")
	}
}

func TestNewEnvelopeSignerWithSecret_Valid(t *testing.T) {
	secret := []byte("a-valid-16b-secret-value")
	s, err := NewEnvelopeSignerWithSecret(secret)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ctx := s.Sign("run-id", 300)
	if len(ctx.Signature) == 0 {
		t.Error("expected non-empty signature")
	}
}
