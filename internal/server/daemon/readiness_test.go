// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/infra/config"
	pcreadiness "github.com/zeroroot-ai/gibson/internal/infra/readiness"
	sdksecrets "github.com/zeroroot-ai/gibson/internal/infra/secrets"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/sdk/auth"
	healthhttp "github.com/zeroroot-ai/sdk/health/http"
	sdktypes "github.com/zeroroot-ai/sdk/types"
)

// readinessFakeBroker is a Broker whose Health result is controllable.
type readinessFakeBroker struct{ healthErr error }

func (b readinessFakeBroker) Get(context.Context, auth.TenantID, string) ([]byte, error) {
	return nil, nil
}
func (b readinessFakeBroker) Put(context.Context, auth.TenantID, string, []byte) error { return nil }
func (b readinessFakeBroker) Delete(context.Context, auth.TenantID, string) error      { return nil }
func (b readinessFakeBroker) List(context.Context, auth.TenantID, sdksecrets.Filter) ([]string, error) {
	return nil, nil
}
func (b readinessFakeBroker) Health(context.Context) error          { return b.healthErr }
func (b readinessFakeBroker) Probe(context.Context) error           { return nil }
func (b readinessFakeBroker) Capabilities() sdksecrets.Capabilities { return sdksecrets.Capabilities{} }

// readinessFakeReg satisfies secretsBrokerHealthChecker.
type readinessFakeReg struct {
	health    map[auth.TenantID]error
	sysBroker sdksecrets.Broker
	sysErr    error
}

func (r readinessFakeReg) Health(context.Context) map[auth.TenantID]error { return r.health }
func (r readinessFakeReg) For(context.Context, auth.TenantID) (sdksecrets.Broker, error) {
	return r.sysBroker, r.sysErr
}

func TestSecretsBrokerReadinessCheck(t *testing.T) {
	brokerErr := errors.New("secrets circuit open: secrets: unavailable")
	tA, _ := auth.NewTenantID("tenant-a")

	tests := []struct {
		name    string
		reg     readinessFakeReg
		wantErr bool
	}{
		{
			name:    "healthy system broker, no cached tenants → ready",
			reg:     readinessFakeReg{sysBroker: readinessFakeBroker{}},
			wantErr: false,
		},
		{
			name:    "cached tenant broker unhealthy → not ready",
			reg:     readinessFakeReg{health: map[auth.TenantID]error{tA: brokerErr}, sysBroker: readinessFakeBroker{}},
			wantErr: true,
		},
		{
			name:    "system broker resolvable but unhealthy → not ready",
			reg:     readinessFakeReg{sysBroker: readinessFakeBroker{healthErr: brokerErr}},
			wantErr: true,
		},
		{
			name:    "system broker unresolvable (unprovisioned) → tolerated, ready",
			reg:     readinessFakeReg{sysErr: errors.New("no broker config for system tenant")},
			wantErr: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := secretsBrokerReadinessCheck(tc.reg)(context.Background())
			if tc.wantErr && err == nil {
				t.Fatal("expected readiness failure, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected ready, got: %v", err)
			}
		})
	}
}

// fakeReadinessRegistrar records each registered readiness check.
type fakeReadinessRegistrar struct {
	checks map[string]healthhttp.CheckFunc
}

func (f *fakeReadinessRegistrar) RegisterReadinessCheck(name string, check healthhttp.CheckFunc) {
	f.checks[name] = check
}

// TestRegisterPlatformReadinessProbes: each probe registers under the "pc_"
// prefix, and its status text names internal/infra, not the removed
// platform-clients module (gibson#997).
func TestRegisterPlatformReadinessProbes(t *testing.T) {
	d := newMinimalDaemon(config.DefaultConfig())
	reg := &fakeReadinessRegistrar{checks: map[string]healthhttp.CheckFunc{}}
	probes := []pcreadiness.Probe{
		&platformReadinessProbe{name: "up", check: func(context.Context) error { return nil }},
		&platformReadinessProbe{name: "down", check: func(context.Context) error { return errors.New("refused") }},
	}
	d.registerPlatformReadinessProbes(context.Background(), reg, probes)

	if len(reg.checks) != 2 {
		t.Fatalf("registered %d checks, want 2", len(reg.checks))
	}
	up := reg.checks["pc_up"](context.Background())
	if !up.IsHealthy() || up.Message != "internal/infra/readiness probe 'up' passed" {
		t.Fatalf("pc_up = %+v", up)
	}
	down := reg.checks["pc_down"](context.Background())
	if !down.IsDegraded() || down.Message != "internal/infra/readiness probe 'down' failed: refused" {
		t.Fatalf("pc_down = %+v", down)
	}
}

// failingCheckAuthorizer fails every Check with err. Its other methods are never called.
type failingCheckAuthorizer struct {
	authz.Authorizer
	err error
}

func (f failingCheckAuthorizer) Check(context.Context, string, string, string) (bool, error) {
	return false, f.err
}

// A bad token and a wrong store ID fail the FGA readiness probes, as an outage
// does. A deny does not.
func TestFGAProbes_FailOnAnyError(t *testing.T) {
	ctx := context.Background()
	for name, err := range map[string]error{
		"unauthenticated": authz.ErrFgaUnauthenticated,
		"not found":       authz.ErrFgaNotFound,
		"outage":          authz.ErrFgaUnavailable,
	} {
		a := failingCheckAuthorizer{err: err}
		if probeErr := fgaReadinessProbe(a).check(ctx); !errors.Is(probeErr, err) {
			t.Errorf("%s: the platform probe must fail with the cause, got %v", name, probeErr)
		}
		if got := fgaHealthStatus(ctx, a); got.Status == sdktypes.StatusHealthy {
			t.Errorf("%s: the health status must not be healthy", name)
		}
	}
	allow := failingCheckAuthorizer{}
	if err := fgaReadinessProbe(allow).check(ctx); err != nil {
		t.Errorf("a deny must pass the probe: %v", err)
	}
	if got := fgaHealthStatus(ctx, allow); got.Status != sdktypes.StatusHealthy {
		t.Errorf("a deny must be healthy, got %v", got.Status)
	}
}
