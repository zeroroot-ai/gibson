// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package migrations

import (
	"errors"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
)

func TestEmbed_TenantHasExpectedFiles(t *testing.T) {
	t.Parallel()
	// 23: 009 is session_context (component session-context store,
	// gibson#1184), 010 is banks (banks of always-on coding agents, ADR-0119,
	// gibson#1708), 011 is jobs (the job queue, gibson#1710), 012 drops
	// provider_config_meta, the default-provider pointer that shadowed
	// provider_configs.is_default (gibson#505), 013 is timeline_events (the
	// full history of the Timeline, ADR-0163, gibson#786), 014 is the idle
	// time of a bank member (ADR-0119, gibson#809), 015 is timeline_export
	// (the export and retention of that history, gibson#992), 016 is the
	// stored context window of the saved default model (gibson#1193), 017
	// lets a finding have no mission (gibson#1378), 018 is the evidence of a
	// finding (gibson#1380), 019 is the Agent Skill tables (gibson#1370), 020 is the outside agent table and 021 adds its CA
	// bundle column (gibson#1403), 022 is the mission definitions published for
	// inbound A2A calls (gibson#1408), 023 drops the count limit of those
	// publications (gibson#1567), and 024 maps the old finding statuses to
	// the four of ADR-0178 (gibson#1556 review m11), and 025 is the loop
	// grant of a bank member (gibson#1612).
	upCount, downCount := countSQL(t, Tenant, tenantDir)
	if upCount != 25 {
		t.Errorf("tenant: expected 25 up.sql files, got %d", upCount)
	}
	if downCount != 25 {
		t.Errorf("tenant: expected 25 down.sql files, got %d", downCount)
	}
}

func TestEmbed_PlatformHasExpectedFiles(t *testing.T) {
	t.Parallel()
	// 50: 020 is bootstrap-token-consumption, 021 is signup-verification
	// (gibson#1228, merged), 022 is audit_log hash chain, 023 indexes
	// capability_grant_agents(tenant_id, principal_ref) for the mission:delegate
	// / mission:originate capability check (gibson#1186 slice C), 024 adds the
	// admin-approval registration rung's state (ADR-0074, gibson#22), 025 adds
	// tenant_quotas.concurrent_connectors (gibson#13), 026 adds
	// component_install.principal_ref, the FGA user a component registered
	// as, which the secret-binding admin RPCs address (gibson#154), 027 makes tenant_zitadel_orgs.zitadel_org_id
	// unique so ext-authz's org->tenant lookup is unambiguous (ADR-0093
	// decision 4, hosted#195), 028 drops connector_sandbox and
	// webhook_idempotency, which no Go code read (gibson#506), 041 drops
	// the three component_install columns the plugin manifest fed (sdk#129),
	// 049 drops tenant_quotas, which no code reads (gibson#1530), 050
	// drops the tier columns, which no code reads (gibson#1531), and 051 and
	// 052 add the endpoint, the OAuth client and the variables that a tenant
	// gives for a connector (gibson#1534, gibson#1538, gibson#1508).
	// golang-migrate tracks a single integer and only moves forward, so
	// leaving a gap would let a later-landing migration be skipped forever.
	upCount, downCount := countSQL(t, Platform, platformDir)
	if upCount != 52 {
		t.Errorf("platform: expected 52 up.sql files, got %d", upCount)
	}
	if downCount != 52 {
		t.Errorf("platform: expected 52 down.sql files, got %d", downCount)
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
//	010 — banks (banks of always-on coding agents, ADR-0119, gibson#1708)
//	023 — drop_inbound_mission_limit (gibson#1567)
//	024 — finding_status_values (the old statuses to the four, gibson#1556)
//	025 — loop_grants (the loop grant of a bank member, gibson#1612)
func TestTenantMaxVersion(t *testing.T) {
	t.Parallel()
	v, err := TenantMaxVersion()
	if err != nil {
		t.Fatalf("TenantMaxVersion: %v", err)
	}
	if v != 25 {
		t.Errorf("TenantMaxVersion: got %d, want 25", v)
	}
}

// PlatformMaxVersion must match the highest NNN in
// postgres/platform/*.up.sql. Bump alongside any added migration:
//
//	001 — tenant_secrets_broker_config
//	002 — plugin_install
//	003 — tenant_quotas_simplify (dropped by 049)
//	004 — tenant_id_text (UUID → TEXT, gibson#99)
//	...
//	011 — component_install (ADR-0046)
//	012 — connector_manifest (gibson#722)
//	013 — connector_sandbox (gibson#722; dropped by 028)
//	014 — connector_sandbox_principal (gibson#723; dropped by 028)
//	015 — webhook_idempotency (dashboard#780/#785)
//	016 — pending_tenant_provisioning (operator-pull provisioning, gibson#948)
//	017 — tenant_status
//	018 — tenant_admin_ops
//	019 — component_install_content_trust (ADR-0110 / gibson#997)
//	020 — bootstrap_token_consumption (one-time enrollment credential, ADR-0045)
//	021 — signup_verification (require a verified email before provisioning, gibson#1228)
//	022 — audit_log_hash_chain (audit_log DDL + per-tenant hash chain)
//	023 — capability_grant_principal_index (indexes capability_grant_agents on
//	      (tenant_id, principal_ref) for the mission:delegate / mission:originate
//	      capability check, gibson#1186 slice C)
//	024 — signup_admin_approval (the ADR-0074 approval registration rung: a
//	      deactivated owner account plus an attributable decision, gibson#22)
//	025 — add_concurrent_connectors_to_tenant_quotas (gibson#13; table dropped
//	      by 049)
//	026 — component_install_principal_ref (the FGA user a component registered
//	      as, which the secret-binding admin RPCs address, gibson#154)
//	027 — tenant_zitadel_orgs_org_unique (one Zitadel org maps to at most one
//	      tenant, so ext-authz's org->tenant lookup is unambiguous, ADR-0093
//	      decision 4, hosted#195)
//	...
//	049 — drop_tenant_quotas (no code reads the plan quotas, gibson#1530)
//	050 — drop_plan_tier_columns (no code reads a tier, gibson#1531)
//	051 — tenant_connector_config (endpoint and OAuth client of a tenant, gibson#1534)
//	052 — tenant_connector_variables (variables of a Hosted connector, gibson#1508)
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
	if v != 52 {
		t.Errorf("PlatformMaxVersion: got %d, want 52", v)
	}
}

// TestVersionsAreContiguousAndUnique guards the hazard described above: a gap
// or two up files with one version leave a migration that golang-migrate
// never applies. It reads the real platform and tenant sets.
func TestVersionsAreContiguousAndUnique(t *testing.T) {
	t.Parallel()
	for name, set := range map[string]struct {
		fsys fs.FS
		dir  string
	}{
		"platform": {Platform, platformDir},
		"tenant":   {Tenant, tenantDir},
	} {
		if err := CheckVersions(set.fsys, set.dir); err != nil {
			t.Errorf("%s migrations: %v", name, err)
		}
	}
}

// TestCheckVersions_Fixture is the failing fixture of the guard: a duplicate
// version names both files and the next free number, and a gap names the
// missing version.
func TestCheckVersions_Fixture(t *testing.T) {
	t.Parallel()
	file := &fstest.MapFile{Data: []byte("SELECT 1;")}
	dup := fstest.MapFS{
		"m/001_a.up.sql":   file,
		"m/002_b.up.sql":   file,
		"m/002_c.up.sql":   file,
		"m/002_c.down.sql": file,
		"m/README.md":      file,
		"m/003_d.up.sql":   file,
		"m/003_d.down.sql": file,
		"m/001_a.down.sql": file,
		"m/002_b.down.sql": file,
	}
	err := CheckVersions(dup, "m")
	if !errors.Is(err, ErrDuplicateVersion) {
		t.Fatalf("duplicate version: got %v, want ErrDuplicateVersion", err)
	}
	for _, want := range []string{"002_b.up.sql", "002_c.up.sql", "next free number, 004"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("duplicate error %q does not name %q", err, want)
		}
	}

	gap := fstest.MapFS{"m/001_a.up.sql": file, "m/003_c.up.sql": file}
	err = CheckVersions(gap, "m")
	if !errors.Is(err, ErrVersionGap) || !strings.Contains(err.Error(), "002") {
		t.Fatalf("gap: got %v, want ErrVersionGap naming 002", err)
	}

	if _, err := scanMaxVersion(dup, "m"); !errors.Is(err, ErrDuplicateVersion) {
		t.Fatalf("scanMaxVersion must refuse a duplicate version, got %v", err)
	}
	if err := CheckVersions(fstest.MapFS{"m/001_a.up.sql": file, "m/002_b.up.sql": file}, "m"); err != nil {
		t.Fatalf("a clean set: %v", err)
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
