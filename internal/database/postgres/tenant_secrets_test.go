package postgres

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/datapool/envelope"
)

// ---------------------------------------------------------------------------
// secretAAD round-trip
// ---------------------------------------------------------------------------

func TestSecretAAD(t *testing.T) {
	aad := secretAAD("mykey")
	if string(aad) != "secret:mykey" {
		t.Errorf("secretAAD: want %q, got %q", "secret:mykey", string(aad))
	}
}

// ---------------------------------------------------------------------------
// ErrTenantSecretNotFound sentinel
// ---------------------------------------------------------------------------

func TestErrTenantSecretNotFoundSentinel(t *testing.T) {
	if !errors.Is(ErrTenantSecretNotFound, ErrTenantSecretNotFound) {
		t.Error("errors.Is(ErrTenantSecretNotFound, ErrTenantSecretNotFound) must be true")
	}
	wrapped := fmt.Errorf("context: %w", ErrTenantSecretNotFound)
	if !errors.Is(wrapped, ErrTenantSecretNotFound) {
		t.Error("wrapped ErrTenantSecretNotFound: errors.Is must find it")
	}
}

// ---------------------------------------------------------------------------
// ErrTenantSecretTooLarge sentinel
// ---------------------------------------------------------------------------

func TestErrTenantSecretTooLargeSentinel(t *testing.T) {
	if !errors.Is(ErrTenantSecretTooLarge, ErrTenantSecretTooLarge) {
		t.Error("errors.Is(ErrTenantSecretTooLarge, ErrTenantSecretTooLarge) must be true")
	}
}

// ---------------------------------------------------------------------------
// IsCrossTenantSecretError predicate
// ---------------------------------------------------------------------------

func TestIsCrossTenantSecretError(t *testing.T) {
	t.Run("nil error returns false", func(t *testing.T) {
		if IsCrossTenantSecretError(nil) {
			t.Error("expected false for nil error")
		}
	})
	t.Run("generic error returns false", func(t *testing.T) {
		if IsCrossTenantSecretError(errors.New("some error")) {
			t.Error("expected false for generic error")
		}
	})
	t.Run("cross-tenant error returns true", func(t *testing.T) {
		e := &crossTenantSecretError{name: "test", cause: errors.New("cause")}
		if !IsCrossTenantSecretError(e) {
			t.Error("expected true for crossTenantSecretError")
		}
	})
	t.Run("wrapped cross-tenant error returns true", func(t *testing.T) {
		inner := &crossTenantSecretError{name: "x", cause: errors.New("cause")}
		wrapped := fmt.Errorf("outer: %w", inner)
		if !IsCrossTenantSecretError(wrapped) {
			t.Error("expected true for fmt.Errorf-wrapped crossTenantSecretError")
		}
	})
}

// ---------------------------------------------------------------------------
// NewTenantSecretsOps constructor
// ---------------------------------------------------------------------------

func TestNewTenantSecretsOps(t *testing.T) {
	kek := make([]byte, 32)
	ops := NewTenantSecretsOps(nil, kek, "tenant-a")
	if ops == nil {
		t.Fatal("NewTenantSecretsOps returned nil")
	}
	if ops.tenant != "tenant-a" {
		t.Errorf("tenant: want %q, got %q", "tenant-a", ops.tenant)
	}
}

// ---------------------------------------------------------------------------
// Put validation (no database required)
// ---------------------------------------------------------------------------

func TestTenantSecretsOpsPutValidation(t *testing.T) {
	kek := make([]byte, 32)
	ops := NewTenantSecretsOps(nil, kek, "t")

	t.Run("empty name rejected", func(t *testing.T) {
		err := ops.Put(context.Background(), "", []byte("v"))
		if err == nil {
			t.Fatal("expected error for empty name")
		}
	})
	t.Run("empty value rejected", func(t *testing.T) {
		err := ops.Put(context.Background(), "key", []byte{})
		if err == nil {
			t.Fatal("expected error for empty value")
		}
	})
	t.Run("value over 1 MiB rejected with ErrTenantSecretTooLarge", func(t *testing.T) {
		big := make([]byte, (1<<20)+1) // 1 MiB + 1 byte
		// fill with non-zero bytes so envelope.Encrypt would accept them
		for i := range big {
			big[i] = 0x01
		}
		err := ops.Put(context.Background(), "big-key", big)
		if err == nil {
			t.Fatal("expected error for over-limit value")
		}
		if !errors.Is(err, ErrTenantSecretTooLarge) {
			t.Errorf("expected ErrTenantSecretTooLarge, got: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// Get validation (no database required)
// ---------------------------------------------------------------------------

func TestTenantSecretsOpsGetValidation(t *testing.T) {
	kek := make([]byte, 32)
	ops := NewTenantSecretsOps(nil, kek, "t")

	t.Run("empty name rejected", func(t *testing.T) {
		_, err := ops.Get(context.Background(), "")
		if err == nil {
			t.Fatal("expected error for empty name")
		}
	})
}

// ---------------------------------------------------------------------------
// Delete validation (no database required)
// ---------------------------------------------------------------------------

func TestTenantSecretsOpsDeleteValidation(t *testing.T) {
	kek := make([]byte, 32)
	ops := NewTenantSecretsOps(nil, kek, "t")

	t.Run("empty name rejected", func(t *testing.T) {
		err := ops.Delete(context.Background(), "")
		if err == nil {
			t.Fatal("expected error for empty name")
		}
	})
}

// ---------------------------------------------------------------------------
// Cross-tenant decrypt detection (envelope-level, no database)
// ---------------------------------------------------------------------------

// TestCrossTenantDetection verifies that when an envelope was produced with
// kekA and we attempt to decrypt with kekB, IsCrossTenantDecryptError returns
// true and TenantSecretsOps would surface a crossTenantSecretError.
func TestCrossTenantDetection(t *testing.T) {
	kekA := make([]byte, 32)
	for i := range kekA {
		kekA[i] = 0xAA
	}
	kekB := make([]byte, 32)
	for i := range kekB {
		kekB[i] = 0xBB
	}

	name := "my-secret"
	plaintext := []byte("plaintext value")
	aad := secretAAD(name)

	// Encrypt with kekA.
	env, err := envelope.Encrypt(kekA, plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Attempt decrypt with kekB — must trigger cross-tenant sentinel.
	_, decryptErr := envelope.Decrypt(kekB, env, aad)
	if !envelope.IsCrossTenantDecryptError(decryptErr) {
		t.Fatalf("expected IsCrossTenantDecryptError=true from envelope layer, got: %v", decryptErr)
	}

	// Confirm the DAO wraps it correctly.
	daoErr := &crossTenantSecretError{name: name, cause: decryptErr}
	if !IsCrossTenantSecretError(daoErr) {
		t.Error("IsCrossTenantSecretError must return true for crossTenantSecretError wrapping the envelope error")
	}
}

// ---------------------------------------------------------------------------
// SecretFilter zero-value semantics
// ---------------------------------------------------------------------------

func TestSecretFilterDefaults(t *testing.T) {
	var f *SecretFilter
	if f != nil {
		t.Error("nil filter pointer should remain nil")
	}

	f2 := &SecretFilter{}
	if f2.Limit != 0 {
		t.Errorf("zero Limit: want 0, got %d", f2.Limit)
	}
	if f2.Offset != 0 {
		t.Errorf("zero Offset: want 0, got %d", f2.Offset)
	}
	if f2.Prefix != "" {
		t.Errorf("zero Prefix: want empty, got %q", f2.Prefix)
	}
}

// ---------------------------------------------------------------------------
// ErrTenantSecretNotFound wrapping via fmt.Errorf
// ---------------------------------------------------------------------------

func TestErrNotFoundWrapping(t *testing.T) {
	wrapped := fmt.Errorf("secret %q: %w", "foo", ErrTenantSecretNotFound)
	if !errors.Is(wrapped, ErrTenantSecretNotFound) {
		t.Error("fmt.Errorf wrapped ErrTenantSecretNotFound: errors.Is must find it")
	}
}
