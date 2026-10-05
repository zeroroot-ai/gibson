// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build integration

package ontology

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/tests/testhelpers"
)

// TestImportStore_RealPostgres runs the store over migration 034.
func TestImportStore_RealPostgres(t *testing.T) {
	ctx := context.Background()
	pg := testhelpers.StartPostgresTLS(t, testhelpers.PostgresOptions{User: "u", Password: "p", Database: "packs"})
	db, err := sql.Open("postgres", pg.DSN)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	require.Eventually(t, func() bool { return db.PingContext(ctx) == nil }, 30*time.Second, 200*time.Millisecond)
	ddl, err := os.ReadFile("../../../pkg/platform/migrations/postgres/platform/034_domain_pack_imports.up.sql")
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, string(ddl))
	require.NoError(t, err)

	s, err := NewImportStore(db)
	require.NoError(t, err)
	require.NoError(t, s.Save(ctx, &DomainPack{Name: "k8s", Version: 1}, "owner"))
	require.ErrorIs(t, s.Save(ctx, &DomainPack{Name: "k8s", Version: 1}, "owner"), ErrPackExists)
	require.NoError(t, s.Save(ctx, &DomainPack{Name: "k8s", Version: 2, Author: "acme"}, "owner"))
	require.ErrorIs(t, s.Save(ctx, &DomainPack{Name: "k8s", Version: 1}, "owner"), ErrPackExists, "an older version never replaces a newer one")

	c, err := CatalogWithImports(ctx, s)
	require.NoError(t, err)
	p, ok := c.Get("k8s")
	require.True(t, ok)
	assert.Equal(t, 2, p.Version)
	assert.Equal(t, "acme", p.Author)
}
