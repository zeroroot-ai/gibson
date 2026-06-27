// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package dataplane

import (
	"errors"
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
	p := &pgProvisioner{cfg: PostgresConfig{DevMode: false}}
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

// TestRecoverFromDirtyMigrations_DevPathAttemptsForce verifies that
// the dev path actually calls m.Force() (and not WrapPermanent). We
// can't run a real migrate.Migrate without Postgres, so we exercise the
// branch via a nil *migrate.Migrate which panics-or-errors on Force —
// either way, the prod-path WrapPermanent shouldn't fire.
//
// The intent is: "in DevMode, do NOT return ErrPermanent without
// trying recovery first". The integration coverage of force+up+success
// lives in the e2e suite against a real Postgres.
func TestRecoverFromDirtyMigrations_DevPathDoesNotShortCircuitToPermanent(t *testing.T) {
	p := &pgProvisioner{cfg: PostgresConfig{DevMode: true}}
	defer func() {
		// nil-deref is expected when Force is called against a nil migrator.
		// The signal we want is: the function REACHED Force, i.e. didn't
		// short-circuit through WrapPermanent.
		if r := recover(); r == nil {
			t.Fatal("expected nil *migrate.Migrate to panic on Force; if it didn't, recovery logic may have been refactored")
		}
	}()
	_ = p.recoverFromDirtyMigrations(nil, migrate.ErrDirty{Version: 3}, "tenant_acme")
}

// TestRecoverFromDirtyMigrations_PermanentErrUnwrapsToDirty verifies the
// permanent error chain still exposes the underlying migrate.ErrDirty
// via errors.As. Diagnostic tooling (Loki query, kubectl get tenant -o
// yaml, the dashboard's Tenant detail page) should be able to recognise
// the underlying class to render a friendly recovery hint instead of
// the raw "manual recovery required" prose.
func TestRecoverFromDirtyMigrations_PermanentErrUnwrapsToDirty(t *testing.T) {
	p := &pgProvisioner{cfg: PostgresConfig{DevMode: false}}
	err := p.recoverFromDirtyMigrations(nil, migrate.ErrDirty{Version: 7}, "tenant_acme")
	var dirty migrate.ErrDirty
	if !errors.As(err, &dirty) {
		t.Fatalf("expected migrate.ErrDirty in error chain, got: %v", err)
	}
	if dirty.Version != 7 {
		t.Errorf("dirty.Version: got %d, want 7", dirty.Version)
	}
}
