// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/infra/config"
	"github.com/zeroroot-ai/gibson/internal/platform/secrets"
	"github.com/zeroroot-ai/gibson/internal/platform/tenantprovider"
)

// newSlotManagerForTenant is the single per-tenant LLM resolver shared by the
// mission path (harness config) and the ComponentService LLM adapter (grpc.go).
// Each call returns a fresh closure carrying its own lazy sync.Once, so the
// broker store + resolver are built on first use. These tests exercise the two
// pre-resolution branches that do NOT require a live Postgres: the "store
// unavailable" guard (pool/secretsService nil) and the resolver-error path
// (the pool refuses a connection). The success path (a resolved provider Set)
// is covered by the integration suite, which has a real broker + Postgres.

// TestNewSlotManagerForTenant_StoreUnavailable asserts the closure fails closed
// with a clear error when the broker stack is not wired yet (pool or
// secretsService nil) — never a nil-pointer panic.
func TestNewSlotManagerForTenant_StoreUnavailable(t *testing.T) {
	cases := []struct {
		name string
		d    *daemonImpl
	}{
		{
			name: "pool nil",
			d:    &daemonImpl{logger: testObsLogger(), secretsService: &secrets.Service{}},
		},
		{
			name: "secretsService nil",
			d:    &daemonImpl{logger: testObsLogger(), pool: &mockPool{}},
		},
		{
			name: "both nil",
			d:    &daemonImpl{logger: testObsLogger()},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolve := tc.d.newSlotManagerForTenant()
			sm, reg, err := resolve(context.Background(), "acme")
			if err == nil {
				t.Fatal("expected an error when the broker store is unavailable, got nil")
			}
			if sm != nil || reg != nil {
				t.Fatalf("expected nil slot-manager and registry on error, got sm=%v reg=%v", sm, reg)
			}
			// The lazy once memoises the init error: a second call returns it too.
			if _, _, err2 := resolve(context.Background(), "acme"); err2 == nil {
				t.Fatal("expected the memoised init error on the second call, got nil")
			}
		})
	}
}

// TestNewSlotManagerForTenant_ResolveError asserts that once the broker store
// is wired (pool + secretsService present) the closure builds the resolver and
// surfaces a per-tenant resolution failure wrapped with the tenant id — the
// pool here refuses to hand out a connection, so resolution cannot complete.
func TestNewSlotManagerForTenant_ResolveError(t *testing.T) {
	d := &daemonImpl{
		logger:         testObsLogger(),
		config:         &config.Config{},
		pool:           &mockPool{err: errors.New("tenant data-plane not provisioned")},
		secretsService: &secrets.Service{},
	}

	resolve := d.newSlotManagerForTenant()
	sm, reg, err := resolve(context.Background(), "acme")
	if err == nil {
		t.Fatal("expected a resolve error when the pool refuses a connection, got nil")
	}
	if sm != nil || reg != nil {
		t.Fatalf("expected nil slot-manager and registry on error, got sm=%v reg=%v", sm, reg)
	}
}

// TestNewSlotManagerForTenant_IndependentInstances asserts each call returns a
// distinct closure with its own once — the mission path and the ComponentService
// adapter must not share a memoised init error.
func TestNewSlotManagerForTenant_IndependentInstances(t *testing.T) {
	d := &daemonImpl{logger: testObsLogger()}
	a := d.newSlotManagerForTenant()
	b := d.newSlotManagerForTenant()
	if _, _, err := a(context.Background(), "acme"); err == nil {
		t.Fatal("closure a: expected error, got nil")
	}
	// b has its own once; it still evaluates the guard rather than reusing a's.
	if _, _, err := b(context.Background(), "acme"); err == nil {
		t.Fatal("closure b: expected error, got nil")
	}
}

// buildSlotManagerForSet is the resolve-success tail of newSlotManagerForTenant,
// split out so it is testable with a hand-built provider Set instead of a live
// broker + Postgres. These tests pin its behaviour: it wraps the set's registry,
// carries the set's default provider into the slot manager, and installs the FGA
// model filter exactly when an authorizer is present.
func TestBuildSlotManagerForSet_EmptySet(t *testing.T) {
	d := &daemonImpl{logger: testObsLogger()}
	set := &tenantprovider.Set{Registry: llm.NewLLMRegistry()}

	sm := d.buildSlotManagerForSet(set)
	if sm == nil {
		t.Fatal("buildSlotManagerForSet returned nil")
	}
	if sm.defaultProvider != "" {
		t.Fatalf("defaultProvider = %q, want empty for a set with no default", sm.defaultProvider)
	}
	// No authorizer on the daemon => no model filter installed.
	if sm.modelFilter != nil {
		t.Fatal("modelFilter installed without an authorizer")
	}
}

func TestBuildSlotManagerForSet_CarriesDefaultProvider(t *testing.T) {
	d := &daemonImpl{logger: testObsLogger()}
	set := &tenantprovider.Set{Registry: llm.NewLLMRegistry(), DefaultName: "anthropic"}

	sm := d.buildSlotManagerForSet(set)
	if sm.defaultProvider != "anthropic" {
		t.Fatalf("defaultProvider = %q, want %q", sm.defaultProvider, "anthropic")
	}
}

func TestBuildSlotManagerForSet_InstallsModelFilterWhenAuthorized(t *testing.T) {
	d := &daemonImpl{logger: testObsLogger(), authorizer: wiringAuthorizer{}}
	set := &tenantprovider.Set{Registry: llm.NewLLMRegistry()}

	sm := d.buildSlotManagerForSet(set)
	if sm.modelFilter == nil {
		t.Fatal("modelFilter must be installed when the daemon has an authorizer (gibson#527)")
	}
}
