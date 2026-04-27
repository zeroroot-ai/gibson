package datapool

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/sdk/auth"
)

// TestPool_GetOrCreateEntry_SameInstance verifies that concurrent calls for
// the same tenant always return the same *tenantEntry (no double-init).
func TestPool_GetOrCreateEntry_SameInstance(t *testing.T) {
	p := &pool{}

	tenant := auth.MustNewTenantID("acme")

	e1 := p.getOrCreateEntry(tenant)
	e2 := p.getOrCreateEntry(tenant)
	e3 := p.getOrCreateEntry(tenant)

	assert.Same(t, e1, e2, "must return same tenantEntry for same tenant")
	assert.Same(t, e2, e3, "must return same tenantEntry on repeated calls")
}

// TestPool_GetOrCreateEntry_DifferentTenants verifies different tenants get
// different entries.
func TestPool_GetOrCreateEntry_DifferentTenants(t *testing.T) {
	p := &pool{}

	acme := auth.MustNewTenantID("acme")
	bigcorp := auth.MustNewTenantID("bigcorp")

	eA := p.getOrCreateEntry(acme)
	eB := p.getOrCreateEntry(bigcorp)

	assert.NotSame(t, eA, eB)
}

// TestPool_ActiveConnCount verifies the active conn counter increments and
// decrements correctly.
func TestPool_ActiveConnCount(t *testing.T) {
	p := &pool{}
	tenant := auth.MustNewTenantID("counter")

	assert.Equal(t, int64(0), p.activeConnCount(tenant))

	entry := p.getOrCreateEntry(tenant)
	entry.activeConns.Add(1)
	assert.Equal(t, int64(1), p.activeConnCount(tenant))

	entry.activeConns.Add(1)
	assert.Equal(t, int64(2), p.activeConnCount(tenant))

	entry.activeConns.Add(-1)
	assert.Equal(t, int64(1), p.activeConnCount(tenant))
}

// TestPool_EvictTenant verifies that evicting a tenant removes its entry.
func TestPool_EvictTenant(t *testing.T) {
	p := &pool{
		pg: newPgPerTenant(DefaultConfig()),
	}
	tenant := auth.MustNewTenantID("evict")
	p.getOrCreateEntry(tenant)

	_, ok := p.tenantEntries.Load(tenant)
	require.True(t, ok)

	p.evictTenant(tenant)

	_, ok = p.tenantEntries.Load(tenant)
	assert.False(t, ok, "tenant entry must be removed after eviction")
}

// TestPool_Admin_Stub verifies that Admin returns "not implemented" until
// Phase E lands.
func TestPool_Admin_Stub(t *testing.T) {
	p := &pool{}
	_, err := p.Admin(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not yet implemented")
}
