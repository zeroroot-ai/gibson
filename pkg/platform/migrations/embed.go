// Package migrations is the single source of truth for Gibson's
// embedded Postgres schema migrations. The package exposes two
// embed.FS values — Tenant and Platform — each scoped to one
// physical database:
//
//   - Tenant carries the migrations applied to every per-tenant
//     Postgres database the tenant-operator provisions
//     (`tenant_<slug>` databases).
//
//   - Platform carries the migrations applied to the dashboard /
//     control-plane Postgres database on chart install / upgrade.
//
// Consumers (the operator's pgProvisioner, the gibson-migrate CLI,
// the daemon's startup gate) construct golang-migrate sources from
// these embed.FSs via the helpers in source.go. The SQL files
// never leave the binary at runtime — there is no filesystem
// MigrationsDir or chart-mounted ConfigMap to keep in sync.
//
// Adding a new migration is a single drop-in: place
// `NNN_short_slug.up.sql` and `NNN_short_slug.down.sql` in the
// matching subdirectory under postgres/, increment NNN, rebuild.
//
// Spec: gibson-postgres-migrations Requirement 2.
package migrations

import "embed"

// Tenant carries the per-tenant Postgres migrations. Apply via
// NewTenantSource() against each tenant's Postgres DSN.
//
//go:embed all:postgres/tenant
var Tenant embed.FS

// Platform carries the dashboard / control-plane Postgres
// migrations. Apply via NewPlatformSource() against the dashboard
// Postgres DSN.
//
//go:embed all:postgres/platform
var Platform embed.FS
