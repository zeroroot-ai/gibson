package entitlements

import (
	"context"
	"testing"
)

func TestUnlimitedProvider_AlwaysUnlimited(t *testing.T) {
	lim, err := UnlimitedProvider{}.Limits(context.Background(), "acme")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if lim != (Limits{}) {
		t.Fatalf("UnlimitedProvider must return zero Limits, got %+v", lim)
	}
}

func TestResolve_NilDegradesToUnlimited(t *testing.T) {
	p := Resolve(nil)
	if p == nil {
		t.Fatal("Resolve(nil) must not return nil")
	}
	lim, err := p.Limits(context.Background(), "acme")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if lim != (Limits{}) {
		t.Fatalf("resolved nil provider must be unlimited, got %+v", lim)
	}
}

func TestResolve_NonNilPassThrough(t *testing.T) {
	orig := UnlimitedProvider{}
	if got := Resolve(orig); got != orig {
		t.Fatalf("Resolve must return the same provider when non-nil")
	}
}

func TestConfigProvider_NilDBIsUnlimited(t *testing.T) {
	p := NewConfigProvider(nil)
	lim, err := p.Limits(context.Background(), "acme")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if lim != (Limits{}) {
		t.Fatalf("nil-DB config provider must be unlimited, got %+v", lim)
	}
}

func TestConfigProvider_EmptyTenantErrors(t *testing.T) {
	p := NewConfigProvider(nil)
	if _, err := p.Limits(context.Background(), ""); err == nil {
		t.Fatal("empty tenant must error")
	}
}

func TestConfigProvider_PrimeAndInvalidate(t *testing.T) {
	cp := NewConfigProvider(nil).(*configProvider)
	want := Limits{ConcurrentMissions: 3, ConcurrentAgents: 7, ConcurrentConnectors: 2}
	cp.Prime("acme", want)

	got, err := cp.Limits(context.Background(), "acme")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Fatalf("primed limits mismatch: got %+v want %+v", got, want)
	}

	// configProvider satisfies Invalidator.
	var inv Invalidator = cp
	inv.Invalidate("acme")

	// After invalidation with a nil DB, the tenant falls back to unlimited.
	got, err = cp.Limits(context.Background(), "acme")
	if err != nil {
		t.Fatalf("unexpected error after invalidate: %v", err)
	}
	if got != (Limits{}) {
		t.Fatalf("after invalidate (nil DB) expected unlimited, got %+v", got)
	}
}

// TestNew_DefaultsToConfigProvider verifies that when ENTITLEMENTS_ENDPOINT is
// unset New returns the OSS config-driven default.
func TestNew_DefaultsToConfigProvider(t *testing.T) {
	t.Setenv("ENTITLEMENTS_ENDPOINT", "")
	p := New(nil)
	if _, ok := p.(*configProvider); !ok {
		t.Fatalf("New with no ENTITLEMENTS_ENDPOINT must return the config-driven default, got %T", p)
	}
}

// TestNew_ReturnsGRPCProviderWhenEndpointSet verifies that when
// ENTITLEMENTS_ENDPOINT is set New attempts to build the gRPC provider.
// Because there is no real SPIRE agent in tests we expect a fallback to the
// configProvider (fail-open on dial failure) — the important check is that
// New does NOT panic and returns a usable Provider.
func TestNew_ReturnsGRPCProviderWhenEndpointSet(t *testing.T) {
	t.Setenv("ENTITLEMENTS_ENDPOINT", "localhost:50060")
	p := New(nil)
	if p == nil {
		t.Fatal("New must not return nil")
	}
	// Must be usable without panic (fail-open).
	_, _ = p.Limits(context.Background(), "acme")
}
