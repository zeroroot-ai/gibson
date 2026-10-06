// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build integration

package compliance

import (
	"context"
	"database/sql"
	"log/slog"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	"github.com/zeroroot-ai/gibson/tests/testhelpers"
)

// TestEvidence_RealPostgres writes audit records with the real writer and
// reads them back through the reader, over the real audit_log migration.
func TestEvidence_RealPostgres(t *testing.T) {
	ctx := context.Background()
	pg := testhelpers.StartPostgresTLS(t, testhelpers.PostgresOptions{User: "u", Password: "p", Database: "compliance"})
	db, err := sql.Open("postgres", pg.DSN)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	require.Eventually(t, func() bool { return db.PingContext(ctx) == nil }, 30*time.Second, 200*time.Millisecond)

	// The writer needs the hash chain (022) and the chain anchor (034).
	for _, file := range []string{"022_audit_log_hash_chain.up.sql", "034_audit_retention.up.sql"} {
		ddl, err := os.ReadFile("../../../../pkg/platform/migrations/postgres/platform/" + file)
		require.NoError(t, err)
		_, err = db.ExecContext(ctx, string(ddl))
		require.NoError(t, err, file)
	}

	w := audit.NewWriter(db, slog.Default())
	for _, action := range []string{"agent_grant_added", "plugin.enable", "agent_grant_removed", "agent_grant_added"} {
		require.NoError(t, w.WriteSync(ctx, audit.Event{TenantID: "acme", ActorID: "user-1", ActorType: "user", Action: action}))
	}
	// Another tenant's record is never read.
	require.NoError(t, w.WriteSync(ctx, audit.Event{TenantID: "beta", ActorID: "u", Action: "agent_grant_added"}))

	r, err := NewReader(db, ontology.NewDomainPackCatalog(testPack()), enabledFw())
	require.NoError(t, err)
	now := time.Now()
	q := Query{Tenant: "acme", Pack: "fw", Start: now.Add(-time.Hour), End: now.Add(time.Hour), PageSize: 2}

	var ids []string
	for {
		rep, err := r.Evidence(ctx, q)
		require.NoError(t, err)
		assert.Equal(t, int64(3), rep.Controls[1].EventCount)
		for _, e := range rep.Events {
			ids = append(ids, e.AuditRecordID)
		}
		if rep.NextPageToken == "" {
			break
		}
		q.PageToken = rep.NextPageToken
	}
	assert.Len(t, ids, 3, "three acme records match, over two pages")
}
