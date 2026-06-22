package entitlements

import (
	"context"
	"database/sql"
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

// fixedProvider is a stand-in for a registered commercial provider.
type fixedProvider struct{ lim Limits }

func (f fixedProvider) Limits(context.Context, string) (Limits, error) { return f.lim, nil }

func TestNew_DefaultsToConfigProviderWhenUnregistered(t *testing.T) {
	factory = nil // ensure no registration leaked from another test
	p := New(nil)
	if _, ok := p.(*configProvider); !ok {
		t.Fatalf("New with no registered factory must return the config-driven default, got %T", p)
	}
}

func TestRegister_OverridesNew(t *testing.T) {
	t.Cleanup(func() { factory = nil }) // package global — reset so other tests see the default
	want := Limits{ConcurrentMissions: 42}
	var gotDB bool
	Register(func(db *sql.DB) Provider {
		gotDB = db == nil // New(nil) below passes a nil handle through to the factory
		return fixedProvider{lim: want}
	})

	p := New(nil)
	if !gotDB {
		t.Fatal("registered factory was not invoked with the DB handle from New")
	}
	got, err := p.Limits(context.Background(), "acme")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Fatalf("registered provider not used: got %+v want %+v", got, want)
	}
}
