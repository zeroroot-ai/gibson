package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/zero-day-ai/gibson/internal/datapool/admin"
	"github.com/zero-day-ai/gibson/migrations"

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

	// Neo4jURI, Neo4jUser, Neo4jPassword are used to query :_SchemaVersion
	// nodes in each tenant Neo4j database. When Neo4jURI is empty, Neo4j
	// checks are skipped.
	Neo4jURI      string
	Neo4jUser     string
	Neo4jPassword string
}

// migrationVersionReader is the interface the startup check uses to read the
// current schema version from a single tenant DB. Abstracted for testing.
type migrationVersionReader interface {
	// PostgresVersion returns the current schema_migrations version for the
	// given tenant. Returns 0 when no migrations have been applied.
	PostgresVersion(ctx context.Context, tenantDSN string) (uint, error)

	// Neo4jVersion returns the current _SchemaVersion.version for the given
	// tenant database. Returns 0 when no version node exists.
	Neo4jVersion(ctx context.Context, tenantDB string) (uint, error)
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

	return runStartupMigrationCheck(ctx, cfg, &pgAndNeo4jVersionReader{cfg: cfg})
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
	// The migrations package embeds the files from the module root migrations/ directory.
	latestPostgres, err := migrations.LatestPostgresVersion()
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

	lister := admin.NewK8sTenantLister(cfg.DynamicClient, cfg.K8sNamespace)
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

	var staleTenants []string

	for _, tid := range tenants {
		tenantStr := tid.String()

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if latestPostgres > 0 && cfg.PostgresAdminDSN != "" {
			tenantDSN := buildTenantDSN(cfg.PostgresAdminDSN, tenantStr)
			cur, err := reader.PostgresVersion(ctx, tenantDSN)
			if err != nil {
				logger.WarnContext(ctx, "startup migration check: could not read postgres version",
					"tenant", tenantStr, "error", err)
			} else if cur < latestPostgres {
				metricMigrationPending.WithLabelValues(tenantStr, "postgres").Set(1)
				logger.WarnContext(ctx, "startup migration check: tenant postgres schema is behind",
					"tenant", tenantStr,
					"current_version", cur,
					"latest_version", latestPostgres,
					"action", "run: gibson-migrate up --tenant "+tenantStr+" --store postgres",
				)
				staleTenants = append(staleTenants, tenantStr+"/postgres")
			} else {
				metricMigrationPending.WithLabelValues(tenantStr, "postgres").Set(0)
			}
		}

		if latestNeo4j > 0 && cfg.Neo4jURI != "" {
			tenantDB := "tenant_" + sanitizeTenantIDForDB(tenantStr)
			cur, err := reader.Neo4jVersion(ctx, tenantDB)
			if err != nil {
				logger.WarnContext(ctx, "startup migration check: could not read neo4j version",
					"tenant", tenantStr, "error", err)
			} else if cur < latestNeo4j {
				metricMigrationPending.WithLabelValues(tenantStr, "neo4j").Set(1)
				logger.WarnContext(ctx, "startup migration check: tenant neo4j schema is behind",
					"tenant", tenantStr,
					"current_version", cur,
					"latest_version", latestNeo4j,
					"action", "run: gibson-migrate up --tenant "+tenantStr+" --store neo4j",
				)
				staleTenants = append(staleTenants, tenantStr+"/neo4j")
			} else {
				metricMigrationPending.WithLabelValues(tenantStr, "neo4j").Set(0)
			}
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
		Neo4jURI:           os.Getenv("NEO4J_ADMIN_URI"),
		Neo4jUser:          os.Getenv("NEO4J_ADMIN_USER"),
		Neo4jPassword:      os.Getenv("NEO4J_ADMIN_PASSWORD"),
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
	cfg *startupMigrationCheckConfig
}

// PostgresVersion queries the schema_migrations table in the given tenant DSN
// and returns the highest applied version. Returns 0 when the table doesn't
// exist yet or the DB is unreachable.
func (r *pgAndNeo4jVersionReader) PostgresVersion(ctx context.Context, tenantDSN string) (uint, error) {
	return queryPostgresVersion(ctx, tenantDSN)
}

// Neo4jVersion queries the :_SchemaVersion node in the given tenant database.
func (r *pgAndNeo4jVersionReader) Neo4jVersion(ctx context.Context, tenantDB string) (uint, error) {
	return queryNeo4jVersion(ctx, r.cfg.Neo4jURI, r.cfg.Neo4jUser, r.cfg.Neo4jPassword, tenantDB)
}
