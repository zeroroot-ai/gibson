// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package datapool

import dbpostgres "github.com/zeroroot-ai/gibson/internal/infra/database/postgres"

// SessionContext returns a SessionContextOps bound to this Conn's Postgres
// pool and per-tenant KEK (gibson#1184 session-context store). The returned
// ops struct is valid only while the Conn is held (before Release is called);
// callers must not cache or share it.
//
// Blobs are envelope-encrypted under the per-tenant KEK — see
// internal/infra/database/postgres.SessionContextOps for the format, the
// etag compare-and-swap contract, the TTL, and the size cap.
//
// The tenant string is embedded so that cross-tenant decrypt failures can be
// attributed to the correct tenant in the gibson_xtenant_decrypt_attempt_total
// Prometheus metric, mirroring Secrets().
func (c *Conn) SessionContext() *dbpostgres.SessionContextOps {
	return dbpostgres.NewSessionContextOps(c.Postgres, c.KEK, c.Tenant.String())
}
