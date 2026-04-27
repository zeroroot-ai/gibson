package datapool

import "github.com/zero-day-ai/gibson/internal/database"

// Credentials returns a CredentialOps bound to this Conn's Postgres pool and
// per-tenant KEK. The returned ops struct is valid only while the Conn is held
// (before Release is called); callers must not cache or share it.
//
// Put/Get/Delete on the returned CredentialOps never store plaintext
// credentials. See internal/database.CredentialOps for the envelope format.
//
// The tenant string is embedded so that cross-tenant decrypt failures can be
// attributed to the correct tenant in the gibson_xtenant_decrypt_attempt_total
// Prometheus metric.
func (c *Conn) Credentials() *database.CredentialOps {
	return database.NewCredentialOpsWithTenant(c.Postgres, c.KEK, c.Tenant.String())
}
