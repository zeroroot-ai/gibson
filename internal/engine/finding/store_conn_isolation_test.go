// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package finding

import (
	"context"
	"os"
	"strings"
	"testing"

	goredis "github.com/redis/go-redis/v9"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// Tenant isolation of the finding store (audit C14 and C15).
//
// ConnBoundFindingStore writes keys with no tenant prefix. Its isolation is
// the connection: each tenant has its own Redis, and a store reads only
// through the connection it was built on. So the property to prove is that a
// store bound to tenant B's connection cannot read what tenant A wrote.
//
// These tests ran for months without proving it. They lived behind the
// integration tag, used miniredis, and skipped when JSON.SET failed, which
// miniredis always does. A skip is green. They now run in the one lane that
// guarantees a Redis Stack (the coverage job, GIBSON_TEST_REQUIRE_REDIS), and
// in that lane a missing Redis Stack is a FAILURE.
//
// Each tenant gets its own logical database on the one server. That is two
// connections to two keyspaces, the same shape as two tenant instances, and
// it lets the test write real documents with JSON.SET.

const (
	isolationTenantADB = 13
	isolationTenantBDB = 14
)

// requireFindingRedis returns a client on one logical database of a Redis
// with the RedisJSON module. Outside the lane that promises one, an absent
// Redis Stack skips. Inside it, an absent or module-less Redis fails.
func requireFindingRedis(t *testing.T, db int) *goredis.Client {
	t.Helper()
	required := os.Getenv("GIBSON_TEST_REQUIRE_REDIS") != ""
	if testing.Short() && !required {
		t.Skip("skipping Redis-backed test in short mode")
	}
	addr := "localhost:6379"
	if url := os.Getenv("GIBSON_TEST_REDIS_URL"); url != "" {
		addr = strings.TrimPrefix(strings.TrimPrefix(url, "redis://"), "rediss://")
	}
	rdb := goredis.NewClient(&goredis.Options{Addr: addr, DB: db})

	// JSON.SET is the command the store uses, so the probe uses it too. A
	// plain redis image answers PING and then fails every write.
	probe := "gibson:test:probe:" + types.NewID().String()
	if err := rdb.Do(context.Background(), "JSON.SET", probe, "$", `{"ok":true}`).Err(); err != nil {
		_ = rdb.Close()
		if required {
			t.Fatalf("GIBSON_TEST_REQUIRE_REDIS is set, so this lane promises a Redis Stack at %s, "+
				"but JSON.SET is unusable: %v", addr, err)
		}
		t.Skipf("Redis Stack not available at %s: %v", addr, err)
	}
	// The two databases belong to these tests. Start and end empty.
	if err := rdb.FlushDB(context.Background()).Err(); err != nil {
		t.Fatalf("flush test database %d: %v", db, err)
	}
	t.Cleanup(func() {
		_ = rdb.FlushDB(context.Background()).Err()
		_ = rdb.Close()
	})
	return rdb
}

func isolationFinding(tenant, title string, severity agent.FindingSeverity, missionID types.ID) EnhancedFinding {
	return NewEnhancedFinding(agent.Finding{
		ID:       types.NewID(),
		TenantID: tenant,
		Title:    title,
		Severity: severity,
	}, missionID, "agent-a")
}

// TestPerTenantFindingIDOR_CrossTenantGetReturnsNotFound is the critical-path
// test for the finding store (tests/criticalpath/manifest.go). Tenant A
// writes a finding. Tenant A reads it back by id and by mission, which proves
// the write happened. Tenant B, on its own connection, gets nothing for the
// same id and the same mission.
func TestPerTenantFindingIDOR_CrossTenantGetReturnsNotFound(t *testing.T) {
	ctx := context.Background()
	storeA := NewConnBoundFindingStore(requireFindingRedis(t, isolationTenantADB))
	storeB := NewConnBoundFindingStore(requireFindingRedis(t, isolationTenantBDB))

	missionID := types.NewID()
	f := isolationFinding("finding-tenant-a", "RCE in tenant-a service", agent.SeverityHigh, missionID)
	if err := storeA.Store(ctx, f); err != nil {
		t.Fatalf("tenant A cannot store its finding: %v", err)
	}

	// The positive control. Without it, an empty read from B could mean the
	// write never happened.
	own, err := storeA.Get(ctx, f.ID)
	if err != nil || own == nil || own.ID != f.ID {
		t.Fatalf("tenant A cannot read its own finding back: finding=%v err=%v", own, err)
	}
	ownList, err := storeA.List(ctx, missionID, nil)
	if err != nil || len(ownList) != 1 || ownList[0].ID != f.ID {
		t.Fatalf("tenant A lists %d finding(s) for its mission, want its one finding (err=%v)", len(ownList), err)
	}

	// C15: tenant B asks for the same id.
	if got, err := storeB.Get(ctx, f.ID); got != nil {
		t.Fatalf("tenant B read tenant A's finding by id: %+v (err=%v)", got, err)
	}
	// C14: tenant B lists the same mission.
	other, err := storeB.List(ctx, missionID, nil)
	if err != nil {
		t.Fatalf("tenant B list: %v", err)
	}
	if len(other) != 0 {
		t.Fatalf("tenant B listed %d of tenant A's finding(s)", len(other))
	}
}

// TestPerTenantFindingIDOR_SeveritySearch is the same property for the
// severity index (C14): tenant A's critical finding is in A's severity list
// and absent from B's.
func TestPerTenantFindingIDOR_SeveritySearch(t *testing.T) {
	ctx := context.Background()
	storeA := NewConnBoundFindingStore(requireFindingRedis(t, isolationTenantADB))
	storeB := NewConnBoundFindingStore(requireFindingRedis(t, isolationTenantBDB))

	f := isolationFinding("sev-tenant-a", "Critical finding in A", agent.SeverityCritical, types.NewID())
	if err := storeA.Store(ctx, f); err != nil {
		t.Fatalf("tenant A cannot store its finding: %v", err)
	}

	own, err := storeA.ListBySeverity(ctx, agent.SeverityCritical)
	if err != nil || len(own) != 1 || own[0].ID != f.ID {
		t.Fatalf("tenant A lists %d critical finding(s), want its one finding (err=%v)", len(own), err)
	}
	other, err := storeB.ListBySeverity(ctx, agent.SeverityCritical)
	if err != nil {
		t.Fatalf("tenant B severity list: %v", err)
	}
	if len(other) != 0 {
		t.Fatalf("tenant B listed %d of tenant A's critical finding(s)", len(other))
	}
}
