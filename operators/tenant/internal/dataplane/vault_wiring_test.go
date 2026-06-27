// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package dataplane

// vault_wiring_test.go locks in the contract that every per-resource
// provisioner (Postgres / Redis / Vector / Neo4j) writes its tenant
// credentials into the per-tenant Vault namespace at the canonical
// infra/<resource> path when the operator wires a VaultClient on its
// config struct.
//
// Until tenant-operator#189 the operator was failing to wire VaultClient
// onto the Redis + Vector configs in cmd/main.go, so every signup left
// secret/infra/redis + secret/infra/vector missing in OpenBao. The
// daemon's secrets broker then 412'd on every authenticated dashboard
// RPC. The wire-up itself is in cmd/main.go; this test is the
// regression gate that makes a future omission visible at unit-test
// time instead of at smoke-signup time.

import (
	"context"
	"sync"
	"testing"

	"github.com/alicebob/miniredis/v2"
	pdataplane "github.com/zeroroot-ai/gibson/pkg/platform/dataplane"

	vaultadmin "github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/vault"
)

// recordingVaultAdmin is the dataplane-package-local fake AdminClient.
// It satisfies vaultadmin.AdminClient via embedded interface and only
// implements the Write* methods this test asserts on; every other call
// is a no-op nil so the dataplane code paths under test don't surprise
// us with an "unimplemented" panic.
type recordingVaultAdmin struct {
	mu              sync.Mutex
	postgresWritten map[string]pdataplane.PostgresCredentials
	redisWritten    map[string]pdataplane.RedisCredentials
	vectorWritten   map[string]pdataplane.VectorCredentials
}

func newRecordingVaultAdmin() *recordingVaultAdmin {
	return &recordingVaultAdmin{
		postgresWritten: map[string]pdataplane.PostgresCredentials{},
		redisWritten:    map[string]pdataplane.RedisCredentials{},
		vectorWritten:   map[string]pdataplane.VectorCredentials{},
	}
}

// Compile-time assertion that recordingVaultAdmin satisfies AdminClient.
var _ vaultadmin.AdminClient = (*recordingVaultAdmin)(nil)

func (r *recordingVaultAdmin) EnsureTenantNamespace(_ context.Context, _ string) (vaultadmin.Edition, error) {
	return vaultadmin.EditionEnterprise, nil
}
func (r *recordingVaultAdmin) DeleteTenantNamespace(_ context.Context, _ string) error  { return nil }
func (r *recordingVaultAdmin) Ping(_ context.Context) error                             { return nil }
func (r *recordingVaultAdmin) VerifyJWTAuthMounted(_ context.Context) error             { return nil }
func (r *recordingVaultAdmin) ConfigureTenantJWTAuth(_ context.Context, _ string) error { return nil }

func (r *recordingVaultAdmin) WriteInfraNeo4j(_ context.Context, _, _, _ string) error { return nil }
func (r *recordingVaultAdmin) DeleteInfraNeo4j(_ context.Context, _ string) error      { return nil }
func (r *recordingVaultAdmin) WriteInfraNeo4jCredentials(_ context.Context, _ string, _ pdataplane.Neo4jCredentials) error {
	return nil
}

func (r *recordingVaultAdmin) WriteInfraPostgres(_ context.Context, tenantID string, creds pdataplane.PostgresCredentials) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.postgresWritten[tenantID] = creds
	return nil
}
func (r *recordingVaultAdmin) DeleteInfraPostgres(_ context.Context, _ string) error { return nil }

func (r *recordingVaultAdmin) WriteInfraRedis(_ context.Context, tenantID string, creds pdataplane.RedisCredentials) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.redisWritten[tenantID] = creds
	return nil
}
func (r *recordingVaultAdmin) DeleteInfraRedis(_ context.Context, _ string) error { return nil }

func (r *recordingVaultAdmin) WriteInfraVector(_ context.Context, tenantID string, creds pdataplane.VectorCredentials) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.vectorWritten[tenantID] = creds
	return nil
}
func (r *recordingVaultAdmin) DeleteInfraVector(_ context.Context, _ string) error { return nil }

// TestRedisProvisionWritesToVault asserts the wiring contract: a
// RedisProvisionerConfig with VaultClient set MUST trigger a
// WriteInfraRedis call on Provision. The corresponding wire-up in
// cmd/main.go is the production fix for the Vault gap in
// tenant-operator#189.
func TestRedisProvisionWritesToVault(t *testing.T) {
	t.Parallel()
	mr := miniredis.RunT(t)
	rec := newRecordingVaultAdmin()

	p, err := NewRedisProvisioner(RedisProvisionerConfig{
		Addr:        mr.Addr(),
		Password:    "tiger",
		VaultClient: rec,
	})
	if err != nil {
		t.Fatalf("NewRedisProvisioner: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })

	if err := p.Provision(context.Background(), "acme-corp"); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	rec.mu.Lock()
	defer rec.mu.Unlock()
	creds, ok := rec.redisWritten["acme-corp"]
	if !ok {
		t.Fatalf("expected WriteInfraRedis for acme-corp; got %v", rec.redisWritten)
	}
	if creds.Addr != mr.Addr() {
		t.Errorf("Addr mismatch: got %q want %q", creds.Addr, mr.Addr())
	}
	if creds.Password != "tiger" {
		t.Errorf("Password mismatch: got %q want %q", creds.Password, "tiger")
	}
	if creds.DBIndex <= 0 {
		t.Errorf("expected positive DBIndex, got %d", creds.DBIndex)
	}
}

// TestVectorProvisionWritesToVault is the Vector counterpart of the Redis
// test above. Locks in the cmd/main.go wiring fix for tenant-operator#189
// against future regressions. Updated for tenant-operator#238 to use the
// Redis VSS provisioner (replacing the removed Qdrant HTTP provisioner).
func TestVectorProvisionWritesToVault(t *testing.T) {
	t.Parallel()
	mr := miniredis.RunT(t)
	registerFTCommands(t, mr)

	rec := newRecordingVaultAdmin()
	p, err := NewRedisVSSProvisioner(RedisVSSConfig{
		Addr:        mr.Addr(),
		VaultClient: rec,
	})
	if err != nil {
		t.Fatalf("NewRedisVSSProvisioner: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })

	if err := p.Provision(context.Background(), "acme-corp"); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	rec.mu.Lock()
	defer rec.mu.Unlock()
	creds, ok := rec.vectorWritten["acme-corp"]
	if !ok {
		t.Fatalf("expected WriteInfraVector for acme-corp; got %v", rec.vectorWritten)
	}
	if creds.IndexName != "vector_idx:tenant_acme_corp" {
		t.Errorf("IndexName mismatch: got %q want vector_idx:tenant_acme_corp", creds.IndexName)
	}
}
