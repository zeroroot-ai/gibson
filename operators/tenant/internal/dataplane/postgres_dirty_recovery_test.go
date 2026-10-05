// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package dataplane

import (
	"strings"
	"testing"

	"github.com/golang-migrate/migrate/v4"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
)

// TestRecoverFromDirtyMigrations_ProdSurfacesPermanent verifies the
// production-safe path: a dirty schema_migrations is NOT auto-recovered;
// instead the function returns a permanent error so the saga sets a
// manual-recovery condition rather than retrying.
//
// We exercise this branch with a nil *migrate.Migrate because the prod
// path never touches the migrator — it returns before any Force()/Up()
// call. This unit test stays hermetic (no real Postgres).
func TestRecoverFromDirtyMigrations_ProdSurfacesPermanent(t *testing.T) {
	p := &pgProvisioner{cfg: PostgresConfig{}}
	err := p.recoverFromDirtyMigrations(nil, migrate.ErrDirty{Version: 3}, "tenant_acme")
	if err == nil {
		t.Fatal("expected non-nil error in prod mode")
	}
	if !clients.IsPermanent(err) {
		t.Errorf("prod-mode dirty must be permanent (saga sets Blocked + recovery condition), got transient")
	}
	if !strings.Contains(err.Error(), "manual recovery required") {
		t.Errorf("error must mention manual recovery, got: %v", err)
	}
	if !strings.Contains(err.Error(), "version 3") {
		t.Errorf("error must include the dirty version, got: %v", err)
	}
	if !strings.Contains(err.Error(), "tenant_acme") {
		t.Errorf("error must include the dbName so operators can act, got: %v", err)
	}
}
