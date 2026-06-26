// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

// kek_deriver.go: a thin interface that decouples per-tenant KEK
// derivation from the underlying mechanism (Vault transit or AWS KMS).
// Each per-store provisioner holds a `KEKDeriver` field instead of the
// historical raw `MasterKEK []byte` — meaning the operator's dataplane
// code never sees the master KEK.
//
// Spec: tenant-provisioning-unification-phase2 Requirement 2.

package dataplane

import (
	"context"
	"fmt"

	gtenant "github.com/zeroroot-ai/gibson/pkg/platform/tenant"
	"github.com/zeroroot-ai/sdk/auth"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/vault"
)

// KEKDeriver returns a per-tenant 32-byte KEK. The returned slice MUST
// be zeroized by the caller when done.
//
// Implementations:
//   - vaultTransitDeriver: Calls Vault transit HMAC; the master never
//     leaves Vault.
//   - kmsHMACDeriver: Calls AWS KMS GenerateMac; the master never
//     enters the operator process.
type KEKDeriver interface {
	DeriveTenantKEK(ctx context.Context, tenantID auth.TenantID) ([]byte, error)
}

// vaultTransitDeriver is the production deriver. The transit client
// holds the (cached, context-zeroized) bytes; this struct is only the
// per-call wrapper.
type vaultTransitDeriver struct {
	client  vault.TransitClient
	keyName string
}

// NewVaultTransitDeriver constructs a deriver that derives via Vault
// transit HMAC. keyName defaults to the underlying TransitConfig.KeyName
// when empty.
func NewVaultTransitDeriver(client vault.TransitClient, keyName string) (KEKDeriver, error) {
	if client == nil {
		return nil, fmt.Errorf("dataplane/kek: vault.TransitClient required")
	}
	return &vaultTransitDeriver{client: client, keyName: keyName}, nil
}

// DeriveTenantKEK calls Vault transit HMAC with the tenant ID as
// derivation context, returning 32 bytes. Caller zeroizes.
func (d *vaultTransitDeriver) DeriveTenantKEK(ctx context.Context, tenantID auth.TenantID) ([]byte, error) {
	if tenantID.IsZero() {
		return nil, fmt.Errorf("dataplane/kek: cannot derive KEK for zero TenantID")
	}
	return d.client.Derive(ctx, d.keyName, []byte(tenantID.String()), gtenant.KEKLength)
}
