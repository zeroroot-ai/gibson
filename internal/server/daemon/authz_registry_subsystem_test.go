package daemon

import (
	"testing"
)

func TestParseAuthzRegistryReaders(t *testing.T) {
	t.Run("comma and space separated", func(t *testing.T) {
		ids, err := parseAuthzRegistryReaders(
			"spiffe://zeroroot.ai/platform/ext-authz, spiffe://zeroroot.ai/platform/envoy")
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if len(ids) != 2 {
			t.Fatalf("want 2 ids, got %d", len(ids))
		}
	})

	t.Run("empty string yields no ids", func(t *testing.T) {
		ids, err := parseAuthzRegistryReaders("   ")
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if len(ids) != 0 {
			t.Fatalf("want 0 ids, got %d", len(ids))
		}
	})

	t.Run("unparseable SVID is an error", func(t *testing.T) {
		_, err := parseAuthzRegistryReaders("not-a-spiffe-id")
		if err == nil {
			t.Fatal("want error for non-SPIFFE id, got nil")
		}
	})
}

func TestNewAuthzRegistrySubsystem_NilSourceSkips(t *testing.T) {
	// No SPIFFE source → (nil, nil): the endpoint MUST NOT start unsecured.
	// Logger is unused on this path, so nil is safe and keeps the test free of
	// observability wiring.
	sys, err := newAuthzRegistrySubsystem(nil, nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if sys != nil {
		t.Fatal("expected nil subsystem when no SPIFFE source (must skip, not serve unsecured)")
	}
}
