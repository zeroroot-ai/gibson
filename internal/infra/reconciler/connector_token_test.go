// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package reconciler

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/zeroroot-ai/sdk/auth"
)

type fakeFreshener struct {
	calls []ConnectorSandbox
	errs  map[string]error // keyed by connector name
}

func (f *fakeFreshener) EnsureFresh(_ context.Context, tenant auth.TenantID, connector string) (bool, error) {
	f.calls = append(f.calls, ConnectorSandbox{Tenant: tenant, Connector: connector})
	if err := f.errs[connector]; err != nil {
		return false, err
	}
	return true, nil
}

func TestConnectorTokenReconcile_RefreshesEveryDesiredConnector(t *testing.T) {
	tenantA, tenantB := auth.MustNewTenantID("tenant-a"), auth.MustNewTenantID("tenant-b")
	cat := &fakeCatalog{desired: []ConnectorSandbox{
		{Tenant: tenantA, Connector: "connector-gitlab"},
		{Tenant: tenantB, Connector: "connector-github"},
	}}
	fresh := &fakeFreshener{}
	r := NewConnectorTokenReconciler(ConnectorTokenConfig{
		Catalog: cat, Freshener: fresh, Logger: slog.Default(),
	})

	r.reconcile(context.Background())

	if len(fresh.calls) != 2 {
		t.Fatalf("freshener called %d times, want 2", len(fresh.calls))
	}
}

// One revoked grant must never stall the other connectors' refreshes.
func TestConnectorTokenReconcile_IsolatesAFailingConnector(t *testing.T) {
	tenant := auth.MustNewTenantID("tenant-a")
	cat := &fakeCatalog{desired: []ConnectorSandbox{
		{Tenant: tenant, Connector: "connector-broken"},
		{Tenant: tenant, Connector: "connector-gitlab"},
	}}
	fresh := &fakeFreshener{errs: map[string]error{"connector-broken": errors.New("invalid_grant")}}
	r := NewConnectorTokenReconciler(ConnectorTokenConfig{
		Catalog: cat, Freshener: fresh, Logger: slog.Default(),
	})

	r.reconcile(context.Background())

	if len(fresh.calls) != 2 {
		t.Fatalf("the healthy connector must still be refreshed; calls=%v", fresh.calls)
	}
}

// A failed enumeration skips the pass: acting on a partial list is how a
// healthy connector gets skipped silently.
func TestConnectorTokenReconcile_SkipsPassOnEnumerationFailure(t *testing.T) {
	cat := &fakeCatalog{err: errors.New("fga unavailable")}
	fresh := &fakeFreshener{}
	r := NewConnectorTokenReconciler(ConnectorTokenConfig{
		Catalog: cat, Freshener: fresh, Logger: slog.Default(),
	})

	r.reconcile(context.Background())

	if len(fresh.calls) != 0 {
		t.Fatalf("no refresh may run on a failed enumeration; calls=%v", fresh.calls)
	}
}

func TestConnectorTokenRun_DisabledWhenUnwired(t *testing.T) {
	r := NewConnectorTokenReconciler(ConnectorTokenConfig{Logger: slog.Default()})
	// Must return immediately rather than tick against nil deps.
	done := make(chan struct{})
	go func() { r.Run(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run must return immediately when its dependencies are unwired")
	}
}

// Run must reconcile immediately, keep ticking, and stop on cancel.
func TestConnectorTokenRun_TicksUntilCancelled(t *testing.T) {
	tenant := auth.MustNewTenantID("tenant-a")
	cat := &fakeCatalog{desired: []ConnectorSandbox{{Tenant: tenant, Connector: "connector-gitlab"}}}
	fresh := &fakeFreshener{}
	r := NewConnectorTokenReconciler(ConnectorTokenConfig{
		Catalog: cat, Freshener: fresh, Logger: slog.Default(), Interval: 5 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()

	// Generous window: at 5ms ticks, 100ms yields the immediate pass plus
	// many ticked ones even on a loaded CI box.
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done

	if len(fresh.calls) < 2 {
		t.Fatalf("Run must reconcile immediately and on ticks; got %d passes", len(fresh.calls))
	}
}

func TestNewConnectorTokenReconciler_Defaults(t *testing.T) {
	r := NewConnectorTokenReconciler(ConnectorTokenConfig{})
	if r.cfg.Logger == nil {
		t.Error("a nil logger must default")
	}
	if r.cfg.Interval != 5*time.Minute {
		t.Errorf("interval = %v, want the 5m default", r.cfg.Interval)
	}
}
