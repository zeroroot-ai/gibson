// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package migrations

import (
	"io/fs"
	"strconv"
	"strings"
	"testing"
)

func TestEmbed_TenantHasExpectedFiles(t *testing.T) {
	t.Parallel()
	// 11: 009 is session_context (component session-context store,
	// gibson#1184), 010 is banks (banks of always-on coding agents, ADR-0019,
	// gibson#1708), 011 is jobs (the job queue, gibson#1710).
	upCount, downCount := countSQL(t, Tenant, tenantDir)
	if upCount != 11 {
		t.Errorf("tenant: expected 11 up.sql files, got %d", upCount)
	}
	if downCount != 11 {
		t.Errorf("tenant: expected 11 down.sql files, got %d", downCount)
	}
}

func TestEmbed_PlatformHasExpectedFiles(t *testing.T) {
	t.Parallel()
	// 23: 020 is bootstrap-token-consumption, 021 is signup-verification
	// (gibson#1228, merged), 022 is audit_log hash chain, 023 indexes
	// capability_grant_agents(tenant_id, principal_ref) for the mission:delegate
	// / mission:originate capability check (gibson#1186 slice C).
	// golang-migrate tracks a single integer and only moves forward, so
	// leaving a gap would let a later-landing migration be skipped forever.
	upCount, downCount := countSQL(t, Platform, platformDir)
	if upCount != 23 {
		t.Errorf("platform: expected 23 up.sql files, got %d", upCount)
	}
	if downCount != 23 {
		t.Errorf("platform: expected 23 down.sql files, got %d", downCount)
	}
}

func TestEmbed_UpDownPairing(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name string
		fsys fs.FS
		dir  string
	}{
		{"tenant", Tenant, tenantDir},
		{"platform", Platform, platformDir},
	} {
		entries, err := fs.ReadDir(c.fsys, c.dir)
		if err != nil {
			t.Fatalf("%s: read dir: %v", c.name, err)
		}
		ups, downs := map[string]bool{}, map[string]bool{}
		for _, e := range entries {
			n := e.Name()
			switch {
			case strings.HasSuffix(n, ".up.sql"):
				ups[strings.TrimSuffix(n, ".up.sql")] = true
			case strings.HasSuffix(n, ".down.sql"):
				downs[strings.TrimSuffix(n, ".down.sql")] = true
			}
		}
		for stem := range ups {
			if !downs[stem] {
				t.Errorf("%s: missing %s.down.sql for %s.up.sql", c.name, stem, stem)
			}
		}
		for stem := range downs {
			if !ups[stem] {
				t.Errorf("%s: missing %s.up.sql for %s.down.sql", c.name, stem, stem)
			}
		}
	}
}

// TenantMaxVersion must match the highest NNN in postgres/tenant/*.up.sql.
// Bump alongside any added tenant migration:
//
//	...
//	007 — (prior tenant baseline)
//	008 — provider_embedding_capability (BYO-embedder columns, gibson#937)
//	009 — session_context (component session-context store, gibson#1184)
//	010 — banks (banks of always-on coding agents, ADR-0019, gibson#1708)
func TestTenantMaxVersion(t *testing.T) {
	t.Parallel()
	v, err := TenantMaxVersion()
	if err != nil {
		t.Fatalf("TenantMaxVersion: %v", err)
	}
	if v != 11 {
		t.Errorf("TenantMaxVersion: got %d, want 11", v)
	}
}

// PlatformMaxVersion must match the highest NNN in
// postgres/platform/*.up.sql. Bump alongside any added migration:
//
//	001 — tenant_secrets_broker_config
//	002 — plugin_install
//	003 — tenant_quotas_simplify
//	004 — tenant_id_text (UUID → TEXT, gibson#99)
//	...
//	011 — component_install (ADR-0046)
//	012 — connector_manifest (gibson#722)
//	013 — connector_sandbox (gibson#722)
//	014 — connector_sandbox_principal (gibson#723)
//	015 — webhook_idempotency (dashboard#780/#785)
//	016 — pending_tenant_provisioning (operator-pull provisioning, gibson#948)
//	017 — tenant_status
//	018 — tenant_admin_ops
//	019 — component_install_content_trust (ADR-0010 / gibson#997)
//	020 — bootstrap_token_consumption (one-time enrollment credential, ADR-0045)
//	021 — signup_verification (require a verified email before provisioning, gibson#1228)
//	022 — audit_log_hash_chain (audit_log DDL + per-tenant hash chain)
//	023 — capability_grant_principal_index (indexes capability_grant_agents on
//	      (tenant_id, principal_ref) for the mission:delegate / mission:originate
//	      capability check, gibson#1186 slice C)
//
// The sequence must stay CONTIGUOUS. golang-migrate records a single integer
// version, and `up` only ever moves forward from it — so a migration that lands
// numbered BELOW the version a database has already reached is never applied,
// silently. Leaving a hole for an in-flight PR to fill later is therefore not a
// safe way to avoid a merge conflict: it converts a loud conflict into a
// migration that quietly never runs. Whichever PR merges second renumbers.
func TestPlatformMaxVersion(t *testing.T) {
	t.Parallel()
	v, err := PlatformMaxVersion()
	if err != nil {
		t.Fatalf("PlatformMaxVersion: %v", err)
	}
	if v != 23 {
		t.Errorf("PlatformMaxVersion: got %d, want 23", v)
	}
}

// TestPlatformVersionsAreContiguous guards the hazard described above: a gap in
// the platform sequence means some migration is unreachable on a database that
// has passed it.
func TestPlatformVersionsAreContiguous(t *testing.T) {
	t.Parallel()
	entries, err := fs.ReadDir(Platform, platformDir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	seen := map[int]bool{}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".up.sql") {
			continue
		}
		n, convErr := strconv.Atoi(strings.SplitN(e.Name(), "_", 2)[0])
		if convErr != nil {
			t.Fatalf("migration %q does not start with a version number", e.Name())
		}
		seen[n] = true
	}
	for v := 1; v <= len(seen); v++ {
		if !seen[v] {
			t.Errorf("platform migration %03d is missing: the sequence must be contiguous, "+
				"or golang-migrate will silently skip whatever later fills the gap", v)
		}
	}
}

func TestNewTenantSource_OpensAndCloses(t *testing.T) {
	t.Parallel()
	d, err := NewTenantSource()
	if err != nil {
		t.Fatalf("NewTenantSource: %v", err)
	}
	defer d.Close()
	first, err := d.First()
	if err != nil {
		t.Fatalf("First: %v", err)
	}
	if first != 1 {
		t.Errorf("first version: got %d, want 1", first)
	}
}

func TestNewPlatformSource_OpensAndCloses(t *testing.T) {
	t.Parallel()
	d, err := NewPlatformSource()
	if err != nil {
		t.Fatalf("NewPlatformSource: %v", err)
	}
	defer d.Close()
	first, err := d.First()
	if err != nil {
		t.Fatalf("First: %v", err)
	}
	if first != 1 {
		t.Errorf("first version: got %d, want 1", first)
	}
}

func TestParseVersionPrefix(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in      string
		want    uint
		wantErr bool
	}{
		{"001_credentials.up.sql", 1, false},
		{"042_foo.up.sql", 42, false},
		{"README.md", 0, true},
		{"_no_prefix.sql", 0, true},
		{"abc_not_numeric.sql", 0, true},
	}
	for _, c := range cases {
		got, err := parseVersionPrefix(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("parseVersionPrefix(%q) err=%v wantErr=%v", c.in, err, c.wantErr)
			continue
		}
		if !c.wantErr && got != c.want {
			t.Errorf("parseVersionPrefix(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func countSQL(t *testing.T, fsys fs.FS, dir string) (up, down int) {
	t.Helper()
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	for _, e := range entries {
		switch {
		case strings.HasSuffix(e.Name(), ".up.sql"):
			up++
		case strings.HasSuffix(e.Name(), ".down.sql"):
			down++
		}
	}
	return up, down
}
