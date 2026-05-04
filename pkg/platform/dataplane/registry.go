// Package dataplane defines platform-internal string constants that the
// gibson daemon and the tenant-operator must agree on. Constants only —
// no functions, no types beyond plain strings.
//
// Why a separate sub-package: per-tenant naming lives in
// gibson/pkg/platform/tenant; this package holds the cross-tenant /
// shared-store identifiers (Redis hash keys, Postgres database names,
// Vault key names) that don't vary per tenant. Splitting them keeps the
// tenant.Names surface focused.
package dataplane

const (
	// RedisIndexHashKey is the key (in shared Redis DB 0) of the hash that
	// maps tenant slugs to their per-tenant logical-DB index. The operator
	// HSETs into it at provision time; the daemon HGETs from it at runtime.
	//
	// Replaces the historical mismatch between operator's "tenant_db_index"
	// and daemon's "tenant:index" which produced silent provisioning
	// failures. See spec tenant-provisioning-unification Requirement 1.4.
	RedisIndexHashKey = "gibson:tenant:index"

	// PlatformDB is the Postgres database name that hosts platform-internal
	// rows (tenant_quotas, audit events, capability grants, plugin install
	// state). Renamed from the historical "gibson_dashboard" to reflect
	// what it actually is — the daemon writes most of these rows; the
	// dashboard chart simply owns the StatefulSet. See spec
	// tenant-provisioning-unification Requirement 6.3.
	PlatformDB = "gibson_platform"

	// LegacyPlatformDB is the previous name of PlatformDB. Used by the
	// chart's pre-upgrade rename Job to detect a pre-rename cluster.
	// Remove this constant once all production clusters have completed
	// the rename (likely two release cycles).
	LegacyPlatformDB = "gibson_dashboard"

	// VaultMasterKEKKey is the Vault transit key name used by the operator
	// to derive per-tenant KEKs in production. The chart's Vault bootstrap
	// Job creates this key. See spec Requirement 5.1.
	VaultMasterKEKKey = "master-kek"
)
