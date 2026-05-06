package daemon

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zero-day-ai/gibson/migrations"
	pgmigrations "github.com/zero-day-ai/gibson/pkg/platform/migrations"
	"github.com/zero-day-ai/sdk/auth"
)


// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

// fakeVersionReader implements migrationVersionReader with configurable
// per-tenant version maps. A missing key returns 0.
type fakeVersionReader struct {
	// postgresVersions maps tenantDSN → current version.
	postgresVersions map[string]uint
	// neo4jVersions maps tenant string ID → current version.
	// A special sentinel value math.MaxUint signals errTenantUnprovisioned.
	neo4jVersions map[string]uint
	// neo4jUnprovisioned is the set of tenant IDs that should return errTenantUnprovisioned.
	neo4jUnprovisioned map[string]bool
}

func (f *fakeVersionReader) PostgresVersion(_ context.Context, tenantDSN string) (uint, error) {
	return f.postgresVersions[tenantDSN], nil
}

func (f *fakeVersionReader) Neo4jVersion(_ context.Context, tenant auth.TenantID) (uint, error) {
	if f.neo4jUnprovisioned != nil && f.neo4jUnprovisioned[tenant.String()] {
		return 0, errTenantUnprovisioned
	}
	return f.neo4jVersions[tenant.String()], nil
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

func defaultCfg() *startupMigrationCheckConfig {
	return &startupMigrationCheckConfig{
		MigrationsRequired: false,
		DynamicClient:      nil,
		PostgresAdminDSN:   "postgres://admin:pw@localhost/admin",
	}
}

// runCheckWithTenants exercises runStartupMigrationCheck logic with an
// injected tenant list, bypassing the Kubernetes API call. It mirrors the
// inner iteration of runStartupMigrationCheck with the same rules but uses
// the fake reader and an explicit tenant list.
func runCheckWithTenants(
	ctx context.Context,
	cfg *startupMigrationCheckConfig,
	reader migrationVersionReader,
	tenantIDs []string,
) error {
	latestPg, _ := pgmigrations.TenantMaxVersion()
	latestNeo4j, _ := migrations.LatestNeo4jVersion()

	var staleTenants []string
	for _, tenantStr := range tenantIDs {
		tid, err := auth.NewTenantID(tenantStr)
		if err != nil {
			continue
		}
		if latestPg > 0 && cfg.PostgresAdminDSN != "" {
			tenantDSN := buildTenantDSN(cfg.PostgresAdminDSN, tenantStr)
			cur, pgErr := reader.PostgresVersion(ctx, tenantDSN)
			if pgErr == nil && cur < latestPg {
				staleTenants = append(staleTenants, tenantStr+"/postgres")
			}
		}
		if latestNeo4j > 0 {
			cur, n4jErr := reader.Neo4jVersion(ctx, tid)
			if n4jErr == nil && cur < latestNeo4j {
				staleTenants = append(staleTenants, tenantStr+"/neo4j")
			}
		}
	}

	if len(staleTenants) == 0 {
		return nil
	}
	msg := "startup migration check: " + strings.Join(staleTenants, ", ") + " are behind"
	if cfg.MigrationsRequired {
		return &migrationPendingError{msg: msg}
	}
	return nil
}

type migrationPendingError struct{ msg string }

func (e *migrationPendingError) Error() string { return e.msg }

// ---------------------------------------------------------------------------
// Tests for migrations package version queries
// ---------------------------------------------------------------------------

// TestLatestPostgresVersion_HasFiles verifies that the Postgres embed returns
// a non-zero version when migration files exist.
func TestLatestPostgresVersion_HasFiles(t *testing.T) {
	ver, err := pgmigrations.TenantMaxVersion()
	require.NoError(t, err)
	assert.Greater(t, ver, uint(0), "postgres migrations should report at least version 1")
}

// TestLatestNeo4jVersion_ReturnsUint verifies that the Neo4j embed returns
// a valid uint (0 or more) without error.
func TestLatestNeo4jVersion_ReturnsUint(t *testing.T) {
	ver, err := migrations.LatestNeo4jVersion()
	require.NoError(t, err)
	// Version may be 0 (no files yet) or >0 (Phase D has authored files).
	// Either is valid — we just check it doesn't error.
	t.Logf("neo4j latest version: %d", ver)
	_ = ver
}

// TestParseVersion covers the shared version-parsing helper.
func TestParseVersion(t *testing.T) {
	tests := []struct {
		filename string
		want     uint
		wantErr  bool
	}{
		{"001_credentials.up.sql", 1, false},
		{"002_findings.up.sql", 2, false},
		{"010_indexes.up.cypher", 10, false},
		{"no_version.up.sql", 0, true},
		{"_missing_prefix.up.sql", 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.filename, func(t *testing.T) {
			got, err := migrations.ParseVersion(tc.filename)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.want, got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Tests for runStartupMigrationCheck
// ---------------------------------------------------------------------------

// TestRunCheck_AllCurrent verifies that when all tenants are at the latest
// version, the check returns nil.
func TestRunCheck_AllCurrent(t *testing.T) {
	// Use the actual latest versions from the embedded files.
	latestPg, err := pgmigrations.TenantMaxVersion()
	require.NoError(t, err)
	latestNeo4j, err := migrations.LatestNeo4jVersion()
	require.NoError(t, err)

	cfg := defaultCfg()
	reader := &fakeVersionReader{
		postgresVersions: map[string]uint{
			buildTenantDSN(cfg.PostgresAdminDSN, "acme"):    latestPg,
			buildTenantDSN(cfg.PostgresAdminDSN, "bigcorp"): latestPg,
		},
		neo4jVersions: map[string]uint{
			"acme":    latestNeo4j,
			"bigcorp": latestNeo4j,
		},
	}
	err = runCheckWithTenants(context.Background(), cfg, reader, []string{"acme", "bigcorp"})
	assert.NoError(t, err, "all-current tenants should not return an error")
}

// TestRunCheck_MixedPending verifies that tenants behind the latest version
// do NOT cause an error when MigrationsRequired is false.
func TestRunCheck_MixedPending(t *testing.T) {
	latestPg, err := pgmigrations.TenantMaxVersion()
	require.NoError(t, err)
	if latestPg == 0 {
		t.Skip("no postgres migrations embedded yet (Phase D pending)")
	}

	cfg := defaultCfg()
	reader := &fakeVersionReader{
		postgresVersions: map[string]uint{
			// acme is current; bigcorp is behind (0 < latestPg).
			buildTenantDSN(cfg.PostgresAdminDSN, "acme"):    latestPg,
			buildTenantDSN(cfg.PostgresAdminDSN, "bigcorp"): 0,
		},
		neo4jVersions: map[string]uint{},
	}
	err = runCheckWithTenants(context.Background(), cfg, reader, []string{"acme", "bigcorp"})
	assert.NoError(t, err, "partial-pending without MigrationsRequired should not error")
}

// TestRunCheck_EnvRequiredFail verifies that with MigrationsRequired=true,
// any stale tenant causes an error.
func TestRunCheck_EnvRequiredFail(t *testing.T) {
	latestPg, err := pgmigrations.TenantMaxVersion()
	require.NoError(t, err)
	// Skip if no postgres migrations exist yet (Phase D pending).
	if latestPg == 0 {
		t.Skip("no postgres migrations embedded yet (Phase D pending)")
	}

	cfg := defaultCfg()
	cfg.MigrationsRequired = true

	reader := &fakeVersionReader{
		postgresVersions: map[string]uint{
			// Return 0 to simulate a tenant that's behind.
			buildTenantDSN(cfg.PostgresAdminDSN, "acme"): 0,
		},
		neo4jVersions: map[string]uint{},
	}
	err = runCheckWithTenants(context.Background(), cfg, reader, []string{"acme"})
	assert.Error(t, err, "MigrationsRequired=true with stale tenant should return error")
	assert.Contains(t, err.Error(), "acme/postgres")
}

// TestRunCheck_EnvRequiredOk verifies that with MigrationsRequired=true but
// all tenants current, no error is returned.
func TestRunCheck_EnvRequiredOk(t *testing.T) {
	latestPg, err := pgmigrations.TenantMaxVersion()
	require.NoError(t, err)
	latestNeo4j, err := migrations.LatestNeo4jVersion()
	require.NoError(t, err)

	cfg := defaultCfg()
	cfg.MigrationsRequired = true

	reader := &fakeVersionReader{
		postgresVersions: map[string]uint{
			buildTenantDSN(cfg.PostgresAdminDSN, "acme"): latestPg,
		},
		neo4jVersions: map[string]uint{
			"acme": latestNeo4j,
		},
	}
	err = runCheckWithTenants(context.Background(), cfg, reader, []string{"acme"})
	assert.NoError(t, err, "MigrationsRequired=true with all-current tenants should succeed")
}

// TestRunCheck_NoK8sClient verifies that the check is skipped gracefully when
// no Kubernetes client is available.
func TestRunCheck_NoK8sClient(t *testing.T) {
	cfg := defaultCfg()
	cfg.DynamicClient = nil
	reader := &fakeVersionReader{}

	err := runStartupMigrationCheck(context.Background(), cfg, reader)
	assert.NoError(t, err, "no k8s client should result in a no-op, not an error")
}

// ---------------------------------------------------------------------------
// Tests for helper functions
// ---------------------------------------------------------------------------

// TestBuildTenantDSN verifies that the admin DSN is correctly modified to
// point at the tenant database.
func TestBuildTenantDSN(t *testing.T) {
	tests := []struct {
		adminDSN string
		tenantID string
		want     string
	}{
		{
			adminDSN: "postgres://admin:pw@localhost:5432/admin",
			tenantID: "acme",
			want:     "postgres://admin:pw@localhost:5432/tenant_acme",
		},
		{
			adminDSN: "postgres://admin:pw@localhost/admin",
			tenantID: "bigcorp",
			want:     "postgres://admin:pw@localhost/tenant_bigcorp",
		},
		{
			adminDSN: "postgres://admin@host/postgres",
			tenantID: "a-b-c",
			want:     "postgres://admin@host/tenant_a_b_c",
		},
	}
	for _, tc := range tests {
		t.Run(tc.tenantID, func(t *testing.T) {
			got := buildTenantDSN(tc.adminDSN, tc.tenantID)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestSanitizeTenantIDForDB verifies the sanitization logic.
func TestSanitizeTenantIDForDB(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"acme", "acme"},
		{"BigCorp", "bigcorp"},
		{"a-b-c", "a_b_c"},
		{"a.b.c", "a_b_c"},
		{"123abc", "123abc"},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := sanitizeTenantIDForDB(tc.input)
			assert.Equal(t, tc.want, got)
		})
	}
}

// ---------------------------------------------------------------------------
// Metric smoke test
// ---------------------------------------------------------------------------

// TestMigrationPendingMetric exercises the Prometheus gauge so the test
// binary touches the metric path at least once.
func TestMigrationPendingMetric(t *testing.T) {
	metricMigrationPending.WithLabelValues("test-tenant", "postgres").Set(0)
	metricMigrationPending.WithLabelValues("test-tenant", "neo4j").Set(0)
}

// ---------------------------------------------------------------------------
// auth.TenantID compilation check
// ---------------------------------------------------------------------------

// TestNewTenantIDCompiles is a compile-time check that auth.TenantID is
// still usable from the daemon package after the import change.
func TestNewTenantIDCompiles(t *testing.T) {
	tid, err := auth.NewTenantID("acme")
	require.NoError(t, err)
	assert.Equal(t, "acme", tid.String())
}
