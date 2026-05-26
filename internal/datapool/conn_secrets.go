package datapool

import dbpostgres "github.com/zeroroot-ai/gibson/internal/database/postgres"

// Secrets returns a TenantSecretsOps bound to this Conn's Postgres pool and
// per-tenant KEK. The returned ops struct is valid only while the Conn is held
// (before Release is called); callers must not cache or share it.
//
// Put/Get/Delete/ListNames on the returned TenantSecretsOps never store
// plaintext values. See internal/database/postgres.TenantSecretsOps for the
// envelope format.
//
// The tenant string is embedded so that cross-tenant decrypt failures can be
// attributed to the correct tenant in the gibson_xtenant_decrypt_attempt_total
// Prometheus metric.
//
// Renamed from Credentials() / conn_credentials.go as part of secrets-broker
// Phase 2, Task 4.4. The underlying storage migrated from the credentials table
// to the unified tenant_secrets table.
func (c *Conn) Secrets() *dbpostgres.TenantSecretsOps {
	return dbpostgres.NewTenantSecretsOps(c.Postgres, c.KEK, c.Tenant.String())
}
