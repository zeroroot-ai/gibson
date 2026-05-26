package datapool

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/zeroroot-ai/sdk/auth"
)

// TestEvictor_EvictsIdleTenant verifies that a tenant with no active conns
// and an expired idle TTL is evicted on the next sweep.
func TestEvictor_EvictsIdleTenant(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clk := newFakeClock(start)

	p := &pool{
		pg: newPgPerTenant(DefaultConfig()),
	}

	ev := newEvictor(p, 1*time.Minute, 30*time.Minute, clk)
	tenant := auth.MustNewTenantID("idle")

	// Create an entry that was last released 31 minutes ago.
	entry := &tenantEntry{}
	entry.lastReleased.Store(start.Add(-31 * time.Minute).UnixNano())
	entry.activeConns.Store(0)
	p.tenantEntries.Store(tenant, entry)

	ev.sweep()

	// The tenant entry should be gone after sweep.
	_, ok := p.tenantEntries.Load(tenant)
	assert.False(t, ok, "idle tenant must be evicted")
}

// TestEvictor_PinsActiveTenant verifies that a tenant with an active Conn
// checked out is NOT evicted even if the idle TTL has elapsed.
func TestEvictor_PinsActiveTenant(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clk := newFakeClock(start)

	p := &pool{
		pg: newPgPerTenant(DefaultConfig()),
	}

	ev := newEvictor(p, 1*time.Minute, 30*time.Minute, clk)
	tenant := auth.MustNewTenantID("active")

	// Entry last released 60 min ago but has an active conn.
	entry := &tenantEntry{}
	entry.lastReleased.Store(start.Add(-60 * time.Minute).UnixNano())
	entry.activeConns.Store(1) // PINNED
	p.tenantEntries.Store(tenant, entry)

	ev.sweep()

	// The tenant entry must still be present.
	_, ok := p.tenantEntries.Load(tenant)
	assert.True(t, ok, "active tenant must NOT be evicted")
}

// TestEvictor_DoesNotEvictWithinTTL verifies tenants within the idle TTL
// are left alone.
func TestEvictor_DoesNotEvictWithinTTL(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clk := newFakeClock(start)

	p := &pool{
		pg: newPgPerTenant(DefaultConfig()),
	}

	ev := newEvictor(p, 1*time.Minute, 30*time.Minute, clk)
	tenant := auth.MustNewTenantID("fresh")

	entry := &tenantEntry{}
	// Last released just 5 minutes ago (within 30-min TTL).
	entry.lastReleased.Store(start.Add(-5 * time.Minute).UnixNano())
	entry.activeConns.Store(0)
	p.tenantEntries.Store(tenant, entry)

	ev.sweep()

	_, ok := p.tenantEntries.Load(tenant)
	assert.True(t, ok, "tenant within TTL must not be evicted")
}

// TestEvictor_MultipleTenants verifies that only the idle tenant is evicted
// when multiple tenants have different idle times.
func TestEvictor_MultipleTenants(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clk := newFakeClock(start)

	p := &pool{
		pg: newPgPerTenant(DefaultConfig()),
	}

	ev := newEvictor(p, 1*time.Minute, 30*time.Minute, clk)

	// acme: idle for 40 min → should be evicted.
	acme := auth.MustNewTenantID("acme")
	eA := &tenantEntry{}
	eA.lastReleased.Store(start.Add(-40 * time.Minute).UnixNano())
	eA.activeConns.Store(0)
	p.tenantEntries.Store(acme, eA)

	// bigcorp: idle for only 10 min → should NOT be evicted.
	bigcorp := auth.MustNewTenantID("bigcorp")
	eB := &tenantEntry{}
	eB.lastReleased.Store(start.Add(-10 * time.Minute).UnixNano())
	eB.activeConns.Store(0)
	p.tenantEntries.Store(bigcorp, eB)

	ev.sweep()

	_, acmeOk := p.tenantEntries.Load(acme)
	_, bigcorpOk := p.tenantEntries.Load(bigcorp)

	assert.False(t, acmeOk, "acme (idle 40min) must be evicted")
	assert.True(t, bigcorpOk, "bigcorp (idle 10min) must not be evicted")
}

// TestFakeClock_Advance verifies the fake clock advances correctly.
func TestFakeClock_Advance(t *testing.T) {
	start := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	clk := newFakeClock(start)

	assert.Equal(t, start, clk.Now())
	clk.Advance(1 * time.Hour)
	assert.Equal(t, start.Add(1*time.Hour), clk.Now())
}
