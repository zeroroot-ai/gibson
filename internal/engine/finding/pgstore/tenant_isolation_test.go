// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package pgstore

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/finding"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// perTenantDBs gives each tenant its own database, as the data pool does: one
// Postgres database for each tenant. It records which tenants asked for a
// connection.
type perTenantDBs struct {
	dbs   map[string]*fakeDB
	asked []string
}

func (p *perTenantDBs) For(_ context.Context, tenant string) (conn, error) {
	p.asked = append(p.asked, tenant)
	db, ok := p.dbs[tenant]
	if !ok {
		db = newFakeDB()
		p.dbs[tenant] = db
	}
	return db, nil
}

// TestPerTenantFindingIDOR_CrossTenantGetReturnsNotFound writes a finding as
// tenant A, and asserts that tenant B cannot read it by id, list it by mission
// or list it by severity. The store takes its connection from the tenant of
// the call, so the other tenant reads its own database and finds nothing.
func TestPerTenantFindingIDOR_CrossTenantGetReturnsNotFound(t *testing.T) {
	pool := &perTenantDBs{dbs: map[string]*fakeDB{}}
	s := &Store{conns: pool}
	ctx := context.Background()
	mission := types.NewID()
	f := finding.NewEnhancedFinding(agent.NewFinding("secret finding", "d", agent.SeverityHigh), mission, "recon")
	f.Check = finding.Check{Kind: finding.CheckScan}
	require.NoError(t, s.Store(ctx, "tenant-a", f))

	got, err := s.Get(ctx, "tenant-a", f.ID)
	require.NoError(t, err)
	assert.Equal(t, "secret finding", got.Title, "the owner reads its finding")

	_, err = s.Get(ctx, "tenant-b", f.ID)
	require.ErrorIs(t, err, finding.ErrNotFound, "another tenant gets not found, not a denial and not the row")
	_, err = s.GetWithEvidence(ctx, "tenant-b", f.ID)
	require.ErrorIs(t, err, finding.ErrNotFound)

	byMission, err := s.List(ctx, "tenant-b", mission, nil)
	require.NoError(t, err)
	assert.Empty(t, byMission)
	bySeverity, err := s.ListBySeverity(ctx, "tenant-b", agent.SeverityHigh)
	require.NoError(t, err)
	assert.Empty(t, bySeverity)

	// Each call asked the pool for the tenant of the call and for no other.
	assert.Contains(t, pool.asked, "tenant-a")
	assert.Contains(t, pool.asked, "tenant-b")
	assert.Len(t, pool.dbs["tenant-a"].rows, 1)
	assert.Empty(t, pool.dbs["tenant-b"].rows, "nothing of tenant A reached the database of tenant B")
}
