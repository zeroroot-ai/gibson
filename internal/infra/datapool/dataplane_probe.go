package datapool

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/zeroroot-ai/gibson/internal/platform/secrets/configstore"
	"github.com/zeroroot-ai/sdk/auth"
)

// DataPlaneProbe answers two structural questions about a tenant's data-plane
// readiness without consulting the Kubernetes control plane. Production
// wires the composite probe below; tests inject fakes via the same interface.
//
// Both methods return (false, nil) for the negative case and (true, nil) for
// the positive case. Errors are reserved for genuine probe failures (e.g.
// the platform Postgres connection is unreachable) — they propagate up so
// the caller can distinguish "tenant not provisioned" from "infrastructure
// problem."
//
// Spec: ADR-0023 (gibson daemon does not consume the Kubernetes API).
// Replaces the previous K8s-Tenant-CRD-GET probe shape that crashed the
// daemon on 2026-05-19 when one tenant CRD was stuck mid-teardown.
type DataPlaneProbe interface {
	// BrokerConfigExists returns true if the platform's
	// tenant_secrets_broker_config table has a row for the given tenant.
	// The row's existence is the necessary precondition for the daemon to
	// be able to construct a per-tenant Vault provider and resolve the
	// per-tenant Postgres DSN. Without the row, every per-tenant operation
	// fails downstream — the probe surfaces it early.
	BrokerConfigExists(ctx context.Context, tenant auth.TenantID) (bool, error)

	// Pingable returns true if the tenant's per-tenant Postgres database
	// exists in the cluster. The check runs against the platform admin
	// connection (a single SELECT against pg_database) so it does not
	// require per-tenant credentials and does not depend on a tenant
	// pool already being constructed (which would be a chicken-and-egg
	// dependency since the probe gates pool construction).
	Pingable(ctx context.Context, tenant auth.TenantID) (bool, error)
}

// brokerConfigReader is the narrow slice of configstore.Store that the
// composite probe needs. Stating it as an interface lets tests inject a
// fake without standing up a real configstore + KEK.
type brokerConfigReader interface {
	GetRaw(ctx context.Context, tenant auth.TenantID) (provider string, configJSON []byte, err error)
}

// platformPGQuerier is the narrow slice of *pgxpool.Pool the composite
// probe needs for the Pingable check (a single SELECT against pg_database).
type platformPGQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// compositeProbe is the production DataPlaneProbe. It composes a
// configstore reader (for broker_config row existence) and a platform
// Postgres querier (for per-tenant database existence). Both dependencies
// are already wired in the daemon's startup path; the probe is a thin
// orchestration layer with no I/O of its own beyond delegating to them.
type compositeProbe struct {
	broker brokerConfigReader
	pg     platformPGQuerier
}

// NewCompositeProbe constructs a production DataPlaneProbe. broker is the
// configstore handle for tenant_secrets_broker_config row lookups. pg is
// the platform admin connection pool used to query pg_database for the
// per-tenant database's existence.
func NewCompositeProbe(broker brokerConfigReader, pg platformPGQuerier) DataPlaneProbe {
	return &compositeProbe{broker: broker, pg: pg}
}

func (p *compositeProbe) BrokerConfigExists(ctx context.Context, tenant auth.TenantID) (bool, error) {
	_, _, err := p.broker.GetRaw(ctx, tenant)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, configstore.ErrNotFound) {
		return false, nil
	}
	return false, fmt.Errorf("dataplane_probe: broker config read: %w", err)
}

// perTenantDBName mirrors the operator's per-tenant DB naming convention.
// Keep this aligned with the saga's data-plane provisioning step; if the
// operator changes the format, this function must change in lockstep.
func perTenantDBName(tenant auth.TenantID) string {
	return "tenant_" + tenant.String()
}

func (p *compositeProbe) Pingable(ctx context.Context, tenant auth.TenantID) (bool, error) {
	dbName := perTenantDBName(tenant)
	var exists bool
	err := p.pg.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)`,
		dbName,
	).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("dataplane_probe: pg_database probe for %s: %w", dbName, err)
	}
	return exists, nil
}
