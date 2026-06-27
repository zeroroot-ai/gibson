// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package dataplane

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"testing"

	"github.com/alicebob/miniredis/v2"
)

func newTestRedisProvisioner(t *testing.T, maxDBs int) (*redisProvisioner, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	cfg := RedisProvisionerConfig{
		Addr:          mr.Addr(),
		MaxLogicalDBs: maxDBs,
	}
	p, err := NewRedisProvisioner(cfg)
	if err != nil {
		t.Fatalf("NewRedisProvisioner: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p, mr
}

func TestRedisProvisionAllocatesIndex(t *testing.T) {
	t.Parallel()
	p, mr := newTestRedisProvisioner(t, 4)
	ctx := context.Background()

	if err := p.Provision(ctx, "tenant-001"); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	// The master index hash must use the slug (hyphen) form, not the
	// underscore form. The daemon looks up HGET gibson:tenant:index <slug>.
	indexStr := mr.HGet(masterIndexHash, "tenant-001")
	if indexStr == "" {
		t.Fatal("expected tenant-001 to have an index in master hash")
	}
	idx, err := strconv.Atoi(indexStr)
	if err != nil {
		t.Fatalf("parse index: %v", err)
	}
	if idx <= 0 {
		t.Errorf("expected positive index, got %d", idx)
	}
}

func TestRedisProvisionIdempotent(t *testing.T) {
	t.Parallel()
	p, mr := newTestRedisProvisioner(t, 8)
	ctx := context.Background()

	if err := p.Provision(ctx, "tenant-abc"); err != nil {
		t.Fatalf("first Provision: %v", err)
	}
	first := mr.HGet(masterIndexHash, "tenant-abc")

	if err := p.Provision(ctx, "tenant-abc"); err != nil {
		t.Fatalf("second Provision: %v", err)
	}
	second := mr.HGet(masterIndexHash, "tenant-abc")

	if first != second {
		t.Errorf("index changed between provisions: %q -> %q", first, second)
	}
}

func TestRedisProvisionMultipleTenants(t *testing.T) {
	t.Parallel()
	p, mr := newTestRedisProvisioner(t, 8)
	ctx := context.Background()

	tenants := []string{"tenant-a", "tenant-b", "tenant-c"}
	for _, tid := range tenants {
		if err := p.Provision(ctx, tid); err != nil {
			t.Fatalf("Provision %q: %v", tid, err)
		}
	}

	// Each tenant must have a unique, positive index.
	seen := make(map[string]bool)
	for _, tid := range tenants {
		safe, _ := sanitizeTenantID(tid)
		v := mr.HGet(masterIndexHash, safe)
		if seen[v] {
			t.Errorf("duplicate index %q for tenant %q", v, tid)
		}
		seen[v] = true
		if v == "0" {
			t.Errorf("tenant %q got index 0 (master index reserved)", tid)
		}
	}
}

func TestRedisProvisionExhausted(t *testing.T) {
	t.Parallel()
	// maxDBs=3 means indices 1 and 2 are available (index 0 is reserved).
	p, _ := newTestRedisProvisioner(t, 3)
	ctx := context.Background()

	if err := p.Provision(ctx, "tenant-x"); err != nil {
		t.Fatalf("Provision tenant-x: %v", err)
	}
	if err := p.Provision(ctx, "tenant-y"); err != nil {
		t.Fatalf("Provision tenant-y: %v", err)
	}
	// Third unique tenant should hit the cap.
	err := p.Provision(ctx, "tenant-z")
	if !errors.Is(err, ErrRedisDBExhausted) {
		t.Errorf("expected ErrRedisDBExhausted, got: %v", err)
	}
}

func TestRedisDeprovisionRemovesMapping(t *testing.T) {
	t.Parallel()
	p, mr := newTestRedisProvisioner(t, 8)
	ctx := context.Background()

	if err := p.Provision(ctx, "tenant-del"); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	// Verify mapping exists.
	if mr.HGet(masterIndexHash, "tenant-del") == "" {
		t.Fatal("mapping should exist after Provision")
	}

	if err := p.Deprovision(ctx, "tenant-del"); err != nil {
		t.Fatalf("Deprovision: %v", err)
	}
	// Mapping should be gone.
	if v := mr.HGet(masterIndexHash, "tenant-del"); v != "" {
		t.Errorf("mapping should be removed after Deprovision, got %q", v)
	}
}

func TestRedisDeprovisionIdempotent(t *testing.T) {
	t.Parallel()
	p, _ := newTestRedisProvisioner(t, 8)
	ctx := context.Background()

	// Deprovision of a tenant that was never provisioned should be a no-op.
	if err := p.Deprovision(ctx, "tenant-never"); err != nil {
		t.Errorf("Deprovision of unknown tenant should succeed, got: %v", err)
	}
}

// TestRedisProvisioner_RecyclesSlotsAfterDeprovision regression-tests
// the bug where the INCR-based allocator never decremented its counter,
// so after N total provisions (N > maxDBs) every subsequent Provision
// returned ErrRedisDBExhausted even when most slots were free (#159).
//
// With maxDBs=4, indices 1, 2, 3 are available. Fill them, deprovision
// one, and the next Provision MUST recycle the freed slot rather than
// reporting exhaustion.
func TestRedisProvisioner_RecyclesSlotsAfterDeprovision(t *testing.T) {
	t.Parallel()
	p, mr := newTestRedisProvisioner(t, 4)
	ctx := context.Background()

	// Fill all 3 available slots.
	for _, tid := range []string{"tenant-1", "tenant-2", "tenant-3"} {
		if err := p.Provision(ctx, tid); err != nil {
			t.Fatalf("Provision %q: %v", tid, err)
		}
	}

	// A 4th unique tenant should hit the cap (slots full).
	if err := p.Provision(ctx, "tenant-overflow"); !errors.Is(err, ErrRedisDBExhausted) {
		t.Fatalf("expected ErrRedisDBExhausted with full slots, got: %v", err)
	}

	// Capture the index assigned to tenant-1, then deprovision it.
	freedStr := mr.HGet(masterIndexHash, "tenant-1")
	if freedStr == "" {
		t.Fatal("tenant-1 should have an index")
	}
	freed, err := strconv.Atoi(freedStr)
	if err != nil {
		t.Fatalf("parse freed index: %v", err)
	}

	if err := p.Deprovision(ctx, "tenant-1"); err != nil {
		t.Fatalf("Deprovision tenant-1: %v", err)
	}

	// A new tenant should now succeed AND get the recycled slot
	// (lowest-free-slot allocator picks the smallest index, which is
	// the one we just freed).
	if err := p.Provision(ctx, "tenant-recycled"); err != nil {
		t.Fatalf("Provision tenant-recycled after deprovision: %v", err)
	}
	got := mr.HGet(masterIndexHash, "tenant-recycled")
	gotIdx, err := strconv.Atoi(got)
	if err != nil {
		t.Fatalf("parse recycled index: %v", err)
	}
	if gotIdx != freed {
		t.Errorf("expected recycled slot %d, got %d", freed, gotIdx)
	}
}

// TestRedisProvisioner_FullThenEmptyThenFull cycles the allocator
// through full-allocation + complete-drain + re-allocation 3 times.
// Verifies that no spurious exhaustion appears as long as deprovision
// is keeping pace.
//
// This is the multi-round regression for #159: the old INCR counter
// would keep climbing each cycle and would falsely report exhaustion
// on cycle 2.
func TestRedisProvisioner_FullThenEmptyThenFull(t *testing.T) {
	t.Parallel()
	p, _ := newTestRedisProvisioner(t, 4) // 3 available slots
	ctx := context.Background()

	for cycle := range 3 {
		tenants := []string{
			fmt.Sprintf("c%d-tenant-a", cycle),
			fmt.Sprintf("c%d-tenant-b", cycle),
			fmt.Sprintf("c%d-tenant-c", cycle),
		}

		// Fill every available slot.
		for _, tid := range tenants {
			if err := p.Provision(ctx, tid); err != nil {
				t.Fatalf("cycle %d Provision %q: %v", cycle, tid, err)
			}
		}

		// A 4th unique tenant in this cycle must hit the cap.
		overflow := fmt.Sprintf("c%d-overflow", cycle)
		if err := p.Provision(ctx, overflow); !errors.Is(err, ErrRedisDBExhausted) {
			t.Fatalf("cycle %d: expected ErrRedisDBExhausted at full, got: %v", cycle, err)
		}

		// Drain every tenant.
		for _, tid := range tenants {
			if err := p.Deprovision(ctx, tid); err != nil {
				t.Fatalf("cycle %d Deprovision %q: %v", cycle, tid, err)
			}
		}
	}
}

// TestRedisProvisioner_RaceTwoTenantsLowestFree fires concurrent
// Provisions for distinct tenants and asserts every one succeeds with
// a unique index. The race shape being exercised: multiple goroutines
// may all compute "lowest free slot = 1" at the same instant. The
// Lua EVAL atomically scans and writes inside the single-threaded
// Redis server, so even though our Go goroutines kick off in parallel
// the actual hash mutations are serialized — no two tenants can end
// up with the same slot.
func TestRedisProvisioner_RaceTwoTenantsLowestFree(t *testing.T) {
	t.Parallel()
	p, mr := newTestRedisProvisioner(t, 8)
	ctx := context.Background()

	const goroutines = 4
	tenants := []string{"race-a", "race-b", "race-c", "race-d"}
	errs := make([]error, goroutines)

	var wg sync.WaitGroup
	wg.Add(goroutines)
	start := make(chan struct{})
	for i, tid := range tenants {
		go func(i int, tid string) {
			defer wg.Done()
			<-start
			errs[i] = p.Provision(ctx, tid)
		}(i, tid)
	}
	close(start)
	wg.Wait()

	// Every Provision must have succeeded.
	for i, err := range errs {
		if err != nil {
			t.Fatalf("tenant %q Provision: %v", tenants[i], err)
		}
	}

	// Every tenant must hold a unique, positive index.
	seen := make(map[int]string)
	for _, tid := range tenants {
		safe, _ := sanitizeTenantID(tid)
		v := mr.HGet(masterIndexHash, safe)
		if v == "" {
			t.Errorf("tenant %q has no mapping", tid)
			continue
		}
		idx, err := strconv.Atoi(v)
		if err != nil || idx <= 0 {
			t.Errorf("tenant %q has bad index %q", tid, v)
			continue
		}
		if existing, ok := seen[idx]; ok {
			t.Errorf("duplicate index %d for tenants %q and %q", idx, existing, tid)
		}
		seen[idx] = tid
	}
}

func TestRedisMasterIndexNeverAllocated(t *testing.T) {
	t.Parallel()
	p, mr := newTestRedisProvisioner(t, 8)
	ctx := context.Background()

	tenants := []string{"t1", "t2", "t3"}
	for _, tid := range tenants {
		if err := p.Provision(ctx, tid); err != nil {
			t.Fatalf("Provision %q: %v", tid, err)
		}
	}

	// No tenant should be assigned index 0.
	for _, tid := range tenants {
		safe, _ := sanitizeTenantID(tid)
		v := mr.HGet(masterIndexHash, safe)
		if v == "0" {
			t.Errorf("tenant %q assigned master DB index 0", tid)
		}
	}
}

// TestRedisProvisioner_SlugFormNotUnderscore is a regression lock for the
// sanitizeTenantID normalization bug where Underscore() was used instead of
// RedisIndexField(), causing the operator to write "zero_root" while the
// daemon reads "zero-root". The daemon does HGET gibson:tenant:index <slug>
// where slug = auth.TenantID.String() = the original hyphenated form.
//
// If this test breaks, the daemon returns FailedPrecondition
// ("no logical DB index found") for every API call — HTTP 412 on all
// dashboard requests. See: tenant-operator#<filed below>.
func TestRedisProvisioner_SlugFormNotUnderscore(t *testing.T) {
	t.Parallel()
	p, mr := newTestRedisProvisioner(t, 8)
	ctx := context.Background()

	// "zero-root" is the canonical case: underscore form "zero_root",
	// slug form "zero-root". The daemon reads "zero-root".
	if err := p.Provision(ctx, "zero-root"); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	if v := mr.HGet(masterIndexHash, "zero-root"); v == "" {
		t.Error("master index must contain slug form \"zero-root\" — daemon reads this form")
	}
	if v := mr.HGet(masterIndexHash, "zero_root"); v != "" {
		t.Errorf("master index must NOT contain underscore form \"zero_root\" (operator-daemon key mismatch), got index %q", v)
	}
}
