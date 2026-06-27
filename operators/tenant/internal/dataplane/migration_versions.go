// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package dataplane

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "github.com/lib/pq" // Postgres driver (database/sql)
	neo4j "github.com/neo4j/neo4j-go-driver/v5/neo4j"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	gibsonmigrations "github.com/zeroroot-ai/gibson/migrations"
	pgmigrations "github.com/zeroroot-ai/gibson/pkg/platform/migrations"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/metrics"
	tenantns "github.com/zeroroot-ai/gibson/operators/tenant/internal/tenant"
)

const (
	// migrationVersionConnectTimeout caps the per-subsystem connectivity
	// probe so a single unreachable tenant cannot block reconcile work.
	migrationVersionConnectTimeout = 3 * time.Second
)

// ErrTenantUnprovisioned signals that a tenant's data plane is not yet
// ready and the migration-version probe should be skipped silently.
var ErrTenantUnprovisioned = errors.New("dataplane/migration-version: tenant not yet provisioned")

// VersionReader reads the current schema version from a single
// per-tenant data-plane store. Implementations exist for Postgres
// (queries schema_migrations) and Neo4j (queries the singleton
// :_SchemaVersion node). The interface is package-public so callers
// can inject fakes from tests.
type VersionReader interface {
	// Postgres returns the highest applied migration version from the
	// schema_migrations table in the tenant's per-tenant Postgres DB.
	// Returns 0 when the table is missing or the DB is unreachable;
	// returns a non-nil error only on programmer mistakes (bad DSN
	// shape). Network or readiness problems do NOT surface as errors —
	// the metric simply reports the last-known state for that subsystem.
	Postgres(ctx context.Context, tenantID string) (uint, error)

	// Neo4j returns the highest version present on the per-tenant
	// :_SchemaVersion node. Returns 0 when the node is absent.
	// Returns ErrTenantUnprovisioned when the tenant's Neo4j endpoint
	// or secret is not yet present (silent skip; not a real error).
	Neo4j(ctx context.Context, tenantID string) (uint, error)
}

// MigrationMetricEmitter emits gibson_tenant_migration_pending for a
// single tenant after a successful Ready reconcile. It is the
// operator-side replacement for the daemon's deleted startup migration
// check (ADR-0023 / gibson#208 S6).
//
// Lifecycle: a single emitter is constructed in cmd/main.go and
// injected into the TenantReconciler. The reconciler invokes Emit
// only on successful Ready transitions; failures inside Emit are
// logged and swallowed so a stuck migration-version probe never
// blocks the saga.
type MigrationMetricEmitter struct {
	reader VersionReader
}

// NewMigrationMetricEmitter constructs an emitter that reads from the
// supplied VersionReader. Pass NewProductionVersionReader for the
// real wiring; tests pass a fake.
func NewMigrationMetricEmitter(reader VersionReader) *MigrationMetricEmitter {
	return &MigrationMetricEmitter{reader: reader}
}

// Emit reads the per-subsystem schema versions for the given tenant,
// compares each against the latest embedded migration shipped with the
// operator binary, and updates the gibson_tenant_migration_pending
// gauge.
//
// Behaviour:
//   - Postgres reachable + behind latest      → gauge[tenant,postgres] = 1
//   - Postgres reachable + at latest          → gauge[tenant,postgres] = 0
//   - Postgres unreachable / DB missing       → gauge unchanged (last known)
//   - Neo4j reachable + behind latest         → gauge[tenant,neo4j]    = 1
//   - Neo4j reachable + at latest             → gauge[tenant,neo4j]    = 0
//   - Neo4j unprovisioned (no Secret / Service) → gauge unchanged
//
// Failures inside this method are recorded only in the returned error
// (which the caller logs at WARN). They never propagate to the saga
// runner. Callers MUST construct via NewMigrationMetricEmitter; a nil
// receiver or nil reader is a programmer mistake — the reconciler
// gates the call site on r.MigrationEmitter != nil so the production
// path never reaches here unset.
func (e *MigrationMetricEmitter) Emit(ctx context.Context, tenantID string) error {
	latestPostgres, perr := pgmigrations.TenantMaxVersion()
	latestNeo4j, nerr := gibsonmigrations.LatestNeo4jVersion()
	if perr != nil && nerr != nil {
		return fmt.Errorf("dataplane/migration-version: no embedded migration files: postgres=%v neo4j=%v", perr, nerr)
	}

	var firstErr error

	if perr == nil && latestPostgres > 0 {
		current, err := e.reader.Postgres(ctx, tenantID)
		switch {
		case err != nil:
			firstErr = fmt.Errorf("postgres: %w", err)
		case current < latestPostgres:
			metrics.MigrationPending.WithLabelValues(tenantID, "postgres").Set(1)
		default:
			metrics.MigrationPending.WithLabelValues(tenantID, "postgres").Set(0)
		}
	}

	if nerr == nil && latestNeo4j > 0 {
		current, err := e.reader.Neo4j(ctx, tenantID)
		switch {
		case errors.Is(err, ErrTenantUnprovisioned):
			// Silent skip — no metric update.
		case err != nil:
			if firstErr == nil {
				firstErr = fmt.Errorf("neo4j: %w", err)
			}
		case current < latestNeo4j:
			metrics.MigrationPending.WithLabelValues(tenantID, "neo4j").Set(1)
		default:
			metrics.MigrationPending.WithLabelValues(tenantID, "neo4j").Set(0)
		}
	}

	return firstErr
}

// productionVersionReader is the real VersionReader. It connects to
// each tenant's data plane with short timeouts and treats every
// network problem as "missing data" rather than a hard error.
type productionVersionReader struct {
	adminDSN  string
	k8sClient client.Client
}

// NewProductionVersionReader wires a VersionReader that talks to real
// Postgres + Neo4j endpoints. adminDSN is the platform-admin Postgres
// DSN already used by PostgresProvisioner — the per-tenant DSN is
// derived via buildTenantAdminDSN.
func NewProductionVersionReader(adminDSN string, k8sClient client.Client) VersionReader {
	return &productionVersionReader{adminDSN: adminDSN, k8sClient: k8sClient}
}

// Postgres opens a fresh connection per call. The reconcile cadence
// is low (seconds at minimum), so a connection-per-emit is cheaper
// than maintaining a pool of admin connections to every tenant DB.
func (r *productionVersionReader) Postgres(ctx context.Context, tenantID string) (uint, error) {
	if r.adminDSN == "" {
		return 0, nil
	}
	names, err := tenantNames(tenantID)
	if err != nil {
		return 0, err
	}
	dbName := names.PostgresDB()
	dsn, err := buildTenantAdminDSN(r.adminDSN, dbName)
	if err != nil {
		return 0, err
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		// Driver-shape error — not a network error. Surface.
		return 0, fmt.Errorf("dataplane/migration-version: open postgres: %w", err)
	}
	defer func() { _ = db.Close() }()

	pingCtx, cancel := context.WithTimeout(ctx, migrationVersionConnectTimeout)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		// DB unreachable — treat as missing, not an error.
		return 0, nil
	}

	var version uint
	row := db.QueryRowContext(ctx, "SELECT COALESCE(MAX(version), 0) FROM schema_migrations")
	if err := row.Scan(&version); err != nil {
		// schema_migrations table absent — fresh DB.
		return 0, nil
	}
	return version, nil
}

// Neo4j opens a fresh driver per call. The reconcile cadence is low
// enough that the driver-construct cost (a single TCP handshake +
// auth roundtrip) is acceptable; the alternative — caching drivers
// per tenant — leaks goroutines on tenant deletion.
func (r *productionVersionReader) Neo4j(ctx context.Context, tenantID string) (uint, error) {
	if r.k8sClient == nil {
		return 0, nil
	}

	tenantNS, err := tenantns.NamespaceFor(ctx, r.k8sClient, tenantID)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return 0, ErrTenantUnprovisioned
		}
		return 0, fmt.Errorf("dataplane/migration-version: resolve namespace: %w", err)
	}

	// Reuse the per-tenant Tenant CR to confirm the tenant exists.
	var tenant gibsonv1alpha1.Tenant
	if err := r.k8sClient.Get(ctx, types.NamespacedName{Name: tenantID}, &tenant); err != nil {
		if apierrors.IsNotFound(err) {
			return 0, ErrTenantUnprovisioned
		}
		return 0, fmt.Errorf("dataplane/migration-version: get Tenant: %w", err)
	}

	names, err := tenantNames(tenantID)
	if err != nil {
		return 0, err
	}

	secret := &corev1.Secret{}
	secretKey := client.ObjectKey{Namespace: tenantNS, Name: names.Neo4jSecret()}
	if err := r.k8sClient.Get(ctx, secretKey, secret); err != nil {
		if apierrors.IsNotFound(err) {
			return 0, ErrTenantUnprovisioned
		}
		return 0, fmt.Errorf("dataplane/migration-version: get Neo4j secret: %w", err)
	}
	rawAuth, ok := secret.Data["NEO4J_AUTH"]
	if !ok {
		return 0, ErrTenantUnprovisioned
	}
	password := strings.TrimPrefix(string(rawAuth), "neo4j/")

	boltURI := fmt.Sprintf("bolt://%s.%s.svc.cluster.local:%d", names.Neo4jService(), tenantNS, neo4jBoltPort)

	connectCtx, cancel := context.WithTimeout(ctx, migrationVersionConnectTimeout)
	defer cancel()

	driver, err := neo4j.NewDriverWithContext(boltURI, neo4j.BasicAuth("neo4j", password, ""))
	if err != nil {
		// Driver-construct failure (bad URI). Surface.
		return 0, fmt.Errorf("dataplane/migration-version: build neo4j driver: %w", err)
	}
	defer func() { _ = driver.Close(context.Background()) }()

	if err := driver.VerifyConnectivity(connectCtx); err != nil {
		// Endpoint unreachable — treat as missing.
		return 0, nil
	}

	session := driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer func() { _ = session.Close(context.Background()) }()

	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, "MATCH (v:_SchemaVersion) RETURN v.version AS version LIMIT 1", nil)
		if err != nil {
			return nil, err
		}
		if res.Next(ctx) {
			ver, _ := res.Record().Get("version")
			return ver, nil
		}
		return nil, res.Err()
	})
	if err != nil || result == nil {
		return 0, nil
	}

	switch v := result.(type) {
	case int64:
		if v >= 0 {
			return uint(v), nil
		}
	case float64:
		if v >= 0 {
			return uint(v), nil
		}
	}
	return 0, nil
}
