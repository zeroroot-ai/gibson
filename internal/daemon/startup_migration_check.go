package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/zero-day-ai/sdk/auth"

	"github.com/zero-day-ai/gibson/internal/datapool"
	"github.com/zero-day-ai/gibson/internal/tenants"
	"github.com/zero-day-ai/gibson/migrations"
	pgmigrations "github.com/zero-day-ai/gibson/pkg/platform/migrations"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	// metricMigrationPending tracks, per-tenant per-store, whether there are
	// pending migrations. Value is 1 when pending, 0 when current.
	metricMigrationPending = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "gibson_tenant_migration_pending",
		Help: "1 if the tenant's schema version is behind the latest local migration, 0 if current.",
	}, []string{"tenant", "store"})

	// metricNeo4jMigrationDrift tracks, per-tenant, the version delta between
	// the latest embedded Neo4j migration and the tenant's actual schema version.
	// Value is delta (latestNeo4j - actual); 0 when in sync.
	metricNeo4jMigrationDrift = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "gibson_tenant_neo4j_migration_drift",
		Help: "Version delta between latest embedded Neo4j migration and tenant actual schema version. 0 = in sync.",
	}, []string{"tenant"})

	// errTenantUnprovisioned is a package-level sentinel returned by
	// pgAndNeo4jVersionReader.Neo4jVersion when pool.For returns a
	// *datapool.NotProvisionedError. Callers map this to a DEBUG log + skip.
	errTenantUnprovisioned = errors.New("tenant not yet provisioned")
)

// startupMigrationCheckConfig carries configuration for the migration check
// performed at daemon boot.
type startupMigrationCheckConfig struct {
	// MigrationsRequired controls fail-fast behaviour. When true, any tenant
	// DB that is behind causes the daemon to return an error (exit 1). When
	// false (default), the daemon logs WARN and continues.
	MigrationsRequired bool

	// DynamicClient is the Kubernetes dynamic client used to enumerate tenants.
	// When nil, the check is a no-op (dev mode without a cluster).
	DynamicClient dynamic.Interface

	// Logger is the structured logger.
	Logger *slog.Logger

	// K8sNamespace is the namespace where Tenant CRDs live. Empty = cluster-scoped.
	K8sNamespace string

	// PostgresAdminDSN is used to query schema_migrations in each tenant DB.
	// When empty, Postgres migration checks are skipped.
	PostgresAdminDSN string

	// Concurrency controls how many tenant migration checks run in parallel.
	// Default 4 when zero; capped at 16.
	Concurrency int
}

// migrationVersionReader is the interface the startup check uses to read the
// current schema version from a single tenant DB. Abstracted for testing.
type migrationVersionReader interface {
	// PostgresVersion returns the current schema_migrations version for the
	// given tenant. Returns 0 when no migrations have been applied.
	PostgresVersion(ctx context.Context, tenantDSN string) (uint, error)

	// Neo4jVersion returns the current _SchemaVersion.version for the given
	// tenant. Returns 0 when no version node exists. Returns errTenantUnprovisioned
	// when the tenant's data-plane is not yet provisioned (caller should skip with DEBUG).
	Neo4jVersion(ctx context.Context, tenant auth.TenantID) (uint, error)
}

// startupMigrationCheck scans all provisioned tenants and checks whether their
// schema versions match the latest local migration files.
//
// It is called during daemon startup after the Kubernetes client is initialised
// but before the gRPC server begins serving.
//
// Behaviour:
//   - For each provisioned tenant, query Postgres schema_migrations and Neo4j
//     :_SchemaVersion to get the current version.
//   - Compare against the latest version present in the embedded migration files.
//   - Emit metric gibson_tenant_migration_pending{tenant, store} = 1 for each
//     tenant whose schema is behind.
//   - If GIBSON_REQUIRE_MIGRATIONS=true (config or env) and any tenant is behind,
//     return a non-nil error describing the tenant(s) and the command to run.
//   - Otherwise log a structured WARN per stale tenant and return nil.
func (d *daemonImpl) startupMigrationCheck(ctx context.Context) error {
	requireMigrations := os.Getenv("GIBSON_REQUIRE_MIGRATIONS") == "true"

	cfg, err := d.buildMigrationCheckConfig(requireMigrations)
	if err != nil {
		// Non-fatal: log and continue. The daemon should not fail to start
		// because it cannot enumerate tenants in dev environments without k8s.
		d.logger.Warn(ctx, "startup migration check: failed to build config (check skipped)",
			"error", err)
		return nil
	}

	return runStartupMigrationCheck(ctx, cfg, &pgAndNeo4jVersionReader{cfg: cfg, pool: d.pool})
}

// runStartupMigrationCheck is the testable core of the startup check.
// Production code calls this via startupMigrationCheck; tests inject a fake
// versionReader.
func runStartupMigrationCheck(
	ctx context.Context,
	cfg *startupMigrationCheckConfig,
	reader migrationVersionReader,
) error {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	// Determine the latest versions from embedded migration files.
	// Per-tenant Postgres migrations live under pkg/platform/migrations
	// (spec gibson-postgres-migrations); Neo4j stays on the legacy
	// migrations package until a follow-on spec moves it.
	latestPostgres, err := pgmigrations.TenantMaxVersion()
	if err != nil {
		logger.WarnContext(ctx, "startup migration check: could not determine latest postgres version",
			"error", err)
	}
	latestNeo4j, err := migrations.LatestNeo4jVersion()
	if err != nil {
		logger.WarnContext(ctx, "startup migration check: could not determine latest neo4j version",
			"error", err)
	}

	// No migration files exist yet (Phase D pending) → nothing to check.
	if latestPostgres == 0 && latestNeo4j == 0 {
		logger.InfoContext(ctx, "startup migration check: no embedded migrations found (Phase D pending); check skipped")
		return nil
	}

	// Enumerate tenants.
	if cfg.DynamicClient == nil {
		logger.InfoContext(ctx, "startup migration check: no Kubernetes client (dev mode); check skipped")
		return nil
	}

	lister := tenants.NewK8sLister(cfg.DynamicClient, cfg.K8sNamespace)
	tenants, err := lister.ListTenants(ctx)
	if err != nil {
		logger.WarnContext(ctx, "startup migration check: could not list tenants (check skipped)",
			"error", err)
		return nil
	}

	if len(tenants) == 0 {
		logger.InfoContext(ctx, "startup migration check: no provisioned tenants; check skipped")
		return nil
	}

	// Determine worker concurrency: default 4, max 16.
	concurrency := cfg.Concurrency
	if concurrency <= 0 {
		concurrency = 4
	}
	if concurrency > 16 {
		concurrency = 16
	}

	// Apply a 30-second total deadline for the entire per-tenant sweep.
	sweepCtx, sweepCancel := context.WithTimeout(ctx, 30*time.Second)
	defer sweepCancel()

	type result struct {
		staleKey string // non-empty if stale; e.g. "acme/postgres"
	}

	resultsCh := make(chan result, len(tenants)*2)
	workCh := make(chan auth.TenantID, len(tenants))

	for _, tid := range tenants {
		workCh <- tid
	}
	close(workCh)

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for tid := range workCh {
				tenantStr := tid.String()

				select {
				case <-sweepCtx.Done():
					return
				default:
				}

				if latestPostgres > 0 && cfg.PostgresAdminDSN != "" {
					tenantDSN := buildTenantDSN(cfg.PostgresAdminDSN, tenantStr)
					cur, pgErr := reader.PostgresVersion(sweepCtx, tenantDSN)
					if pgErr != nil {
						logger.WarnContext(sweepCtx, "startup migration check: could not read postgres version",
							"tenant", tenantStr, "error", pgErr)
					} else if cur < latestPostgres {
						metricMigrationPending.WithLabelValues(tenantStr, "postgres").Set(1)
						logger.WarnContext(sweepCtx, "startup migration check: tenant postgres schema is behind",
							"tenant", tenantStr,
							"current_version", cur,
							"latest_version", latestPostgres,
							"action", "run: gibson-migrate up --tenant "+tenantStr+" --store postgres",
						)
						resultsCh <- result{staleKey: tenantStr + "/postgres"}
					} else {
						metricMigrationPending.WithLabelValues(tenantStr, "postgres").Set(0)
						resultsCh <- result{}
					}
				}

				if latestNeo4j > 0 {
					cur, n4jErr := reader.Neo4jVersion(sweepCtx, tid)
					if errors.Is(n4jErr, errTenantUnprovisioned) {
						logger.DebugContext(sweepCtx, "startup migration check: skipping migration check for unprovisioned tenant",
							"tenant", tenantStr)
						resultsCh <- result{}
					} else if n4jErr != nil {
						logger.WarnContext(sweepCtx, "startup migration check: could not read neo4j version",
							"tenant", tenantStr, "error", n4jErr)
						resultsCh <- result{}
					} else if cur < latestNeo4j {
						delta := int64(latestNeo4j) - int64(cur)
						metricMigrationPending.WithLabelValues(tenantStr, "neo4j").Set(1)
						metricNeo4jMigrationDrift.WithLabelValues(tenantStr).Set(float64(delta))
						logger.ErrorContext(sweepCtx, "startup migration check: tenant neo4j schema is behind",
							"tenant", tenantStr,
							"expected_version", latestNeo4j,
							"actual_version", cur,
							"delta", delta,
							"action", "run: gibson-migrate up --tenant "+tenantStr+" --store neo4j",
						)
						resultsCh <- result{staleKey: tenantStr + "/neo4j"}
					} else {
						metricMigrationPending.WithLabelValues(tenantStr, "neo4j").Set(0)
						metricNeo4jMigrationDrift.WithLabelValues(tenantStr).Set(0)
						resultsCh <- result{}
					}
				}
			}
		}()
	}

	wg.Wait()
	close(resultsCh)

	var staleTenants []string
	for r := range resultsCh {
		if r.staleKey != "" {
			staleTenants = append(staleTenants, r.staleKey)
		}
	}

	if len(staleTenants) == 0 {
		logger.InfoContext(ctx, "startup migration check: all tenant schemas are current")
		return nil
	}

	msg := fmt.Sprintf(
		"startup migration check: %d tenant store(s) are behind: [%s]; "+
			"run: gibson-migrate up --all to apply pending migrations",
		len(staleTenants), strings.Join(staleTenants, ", "),
	)

	if cfg.MigrationsRequired {
		return fmt.Errorf("%s (GIBSON_REQUIRE_MIGRATIONS=true — daemon refusing to start)", msg)
	}

	logger.WarnContext(ctx, msg)
	return nil
}

// buildMigrationCheckConfig constructs a startupMigrationCheckConfig from the
// daemon's own configuration and environment variables.
func (d *daemonImpl) buildMigrationCheckConfig(requireMigrations bool) (*startupMigrationCheckConfig, error) {
	cfg := &startupMigrationCheckConfig{
		MigrationsRequired: requireMigrations,
		Logger:             d.logger.Slog(),
		PostgresAdminDSN:   os.Getenv("POSTGRES_ADMIN_DSN"),
		K8sNamespace:       os.Getenv("GIBSON_K8S_NAMESPACE"),
	}

	// Build a Kubernetes dynamic client for tenant enumeration.
	var k8sCfg *rest.Config
	var err error
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig != "" {
		k8sCfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	} else {
		k8sCfg, err = rest.InClusterConfig()
	}
	if err != nil {
		// Not an error in dev environments without a cluster.
		return cfg, nil
	}

	dynClient, err := dynamic.NewForConfig(k8sCfg)
	if err != nil {
		return cfg, fmt.Errorf("build k8s dynamic client: %w", err)
	}
	cfg.DynamicClient = dynClient
	return cfg, nil
}

// buildTenantDSN constructs a per-tenant Postgres DSN by replacing the
// database component of the admin DSN with the tenant database name.
func buildTenantDSN(adminDSN, tenantID string) string {
	dbName := "tenant_" + sanitizeTenantIDForDB(tenantID)
	if idx := strings.LastIndex(adminDSN, "/"); idx >= 0 {
		if idx > strings.Index(adminDSN, "://") {
			return adminDSN[:idx+1] + dbName
		}
	}
	return adminDSN + "/" + dbName
}

// sanitizeTenantIDForDB returns a sanitized form of the tenant ID safe for use
// in Postgres database names and Neo4j database names.
func sanitizeTenantIDForDB(id string) string {
	var sb strings.Builder
	for _, r := range strings.ToLower(id) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			sb.WriteRune(r)
		} else {
			sb.WriteRune('_')
		}
	}
	return sb.String()
}

// pgAndNeo4jVersionReader is the production implementation of
// migrationVersionReader. It queries real databases.
type pgAndNeo4jVersionReader struct {
	cfg  *startupMigrationCheckConfig
	pool datapool.Pool
}

// PostgresVersion queries the schema_migrations table in the given tenant DSN
// and returns the highest applied version. Returns 0 when the table doesn't
// exist yet or the DB is unreachable.
func (r *pgAndNeo4jVersionReader) PostgresVersion(ctx context.Context, tenantDSN string) (uint, error) {
	return queryPostgresVersion(ctx, tenantDSN)
}

// Neo4jVersion acquires a per-tenant connection from the pool and queries the
// :_SchemaVersion node. Returns errTenantUnprovisioned when the tenant's
// data-plane is not yet provisioned (caller maps this to a DEBUG log + skip).
// Returns 0 when pool is nil (Neo4j check disabled).
func (r *pgAndNeo4jVersionReader) Neo4jVersion(ctx context.Context, tenant auth.TenantID) (uint, error) {
	if r.pool == nil {
		return 0, nil
	}
	conn, err := r.pool.For(ctx, tenant)
	if err != nil {
		var notProvisioned *datapool.NotProvisionedError
		if errors.As(err, &notProvisioned) {
			return 0, errTenantUnprovisioned
		}
		return 0, fmt.Errorf("startup migration check: acquire pool conn for tenant %s: %w", tenant, err)
	}
	defer conn.Release()
	return queryNeo4jVersionViaSession(ctx, conn.Neo4j)
}
