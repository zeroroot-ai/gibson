// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"testing"

	sdksecrets "github.com/zeroroot-ai/gibson/internal/infra/secrets"
	"github.com/zeroroot-ai/sdk/auth"
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
