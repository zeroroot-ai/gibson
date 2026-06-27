// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package dataplane

import (
	"context"
	"fmt"
	"os"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/zeroroot-ai/sdk/auth"

	dpclient "github.com/zeroroot-ai/gibson/operators/tenant/internal/dataplane/client"
)

// fixedKEKDeriver is a test-only KEKDeriver that returns deterministic
// all-zero KEK bytes. It replaces the removed NewLocalHKDFDeriver in
// integration tests that only need a structurally valid deriver.
type fixedKEKDeriver struct{}

func (fixedKEKDeriver) DeriveTenantKEK(_ context.Context, tenantID auth.TenantID) ([]byte, error) {
	if tenantID.IsZero() {
		return nil, fmt.Errorf("fixedKEKDeriver: zero TenantID")
	}
	return make([]byte, 32), nil
}

// TestPostgresProvisionIdempotent verifies that calling Provision twice on the
// same tenant succeeds: the catalog-existence checks (pg_database, pg_roles)
// detect the already-created DB and role and skip the CREATE statements.
// Requires DATAPLANE_PG_ADMIN_DSN to be set; skipped otherwise (#194).
func TestPostgresProvisionIdempotent(t *testing.T) {
	pgDSN := os.Getenv("DATAPLANE_PG_ADMIN_DSN")
	if pgDSN == "" {
		t.Skip("DATAPLANE_PG_ADMIN_DSN unset — Postgres integration tests skipped (wire in CI via tenant-operator#194)")
	}

	p, err := NewPostgresProvisioner(PostgresConfig{
		AdminDSN:   pgDSN,
		KEKDeriver: fixedKEKDeriver{},
		DevMode:    true, // auto-recover dirty migrations in test environment
	})
	if err != nil {
		t.Fatalf("NewPostgresProvisioner: %v", err)
	}

	ctx := context.Background()
	const tenantID = "test-idempotent-pg-001"

	// First provision — creates DB + role + runs migrations.
	if err := p.Provision(ctx, tenantID); err != nil {
		t.Fatalf("first Provision: %v", err)
	}

	// Second provision — catalog checks detect existing objects; must succeed.
	if err := p.Provision(ctx, tenantID); err != nil {
		t.Errorf("second Provision (idempotency): %v", err)
	}

	// Cleanup: deprovision the test tenant.
	t.Cleanup(func() {
		if err := p.Deprovision(context.Background(), tenantID); err != nil {
			t.Logf("cleanup Deprovision: %v", err)
		}
	})
}

// TestPostgresDeprovisionIdempotent verifies that calling Deprovision twice on
// the same (absent) tenant returns nil both times. The DROP IF EXISTS paths
// make this safe even when the DB/role do not exist.
// Requires DATAPLANE_PG_ADMIN_DSN to be set; skipped otherwise (#194).
func TestPostgresDeprovisionIdempotent(t *testing.T) {
	pgDSN := os.Getenv("DATAPLANE_PG_ADMIN_DSN")
	if pgDSN == "" {
		t.Skip("DATAPLANE_PG_ADMIN_DSN unset — Postgres integration tests skipped (wire in CI via tenant-operator#194)")
	}

	p, err := NewPostgresProvisioner(PostgresConfig{
		AdminDSN:   pgDSN,
		KEKDeriver: fixedKEKDeriver{},
	})
	if err != nil {
		t.Fatalf("NewPostgresProvisioner: %v", err)
	}

	ctx := context.Background()
	const tenantID = "test-idempotent-pg-002"

	// Deprovision a tenant that was never provisioned — DROP IF EXISTS must not fail.
	if err := p.Deprovision(ctx, tenantID); err != nil {
		t.Fatalf("first Deprovision on absent tenant: %v", err)
	}

	// Second deprovision — still absent, must still succeed.
	if err := p.Deprovision(ctx, tenantID); err != nil {
		t.Errorf("second Deprovision (idempotency): %v", err)
	}
}

// TestNeo4jDeprovisionIdempotent verifies that Deprovision on a tenant whose
// K8s resources do not exist returns nil. All delete operations use
// client.IgnoreNotFound so a missing resource is not an error.
// This is a unit test — no cluster or Postgres needed.
func TestNeo4jDeprovisionIdempotent(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("corev1.AddToScheme: %v", err)
	}
	if err := appsv1.AddToScheme(scheme); err != nil {
		t.Fatalf("appsv1.AddToScheme: %v", err)
	}
	k8s := fake.NewClientBuilder().WithScheme(scheme).Build()

	n := &Neo4jProvisioner{cfg: Neo4jConfig{
		K8sClient:   dpclient.New(k8s, ""),
		VaultClient: newRecordingVaultAdmin(),
	}}

	ctx := context.Background()
	const tenantID = "acme"

	// No K8s resources exist for this tenant; all IgnoreNotFound deletes
	// should succeed silently.
	if err := n.Deprovision(ctx, tenantID); err != nil {
		t.Fatalf("first Deprovision on absent tenant: %v", err)
	}

	// Second call — still absent, still no error.
	if err := n.Deprovision(ctx, tenantID); err != nil {
		t.Errorf("second Deprovision (idempotency): %v", err)
	}
}
