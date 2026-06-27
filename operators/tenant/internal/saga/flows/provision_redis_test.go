// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package flows

// Per-saga-step contract tests for the Redis-backed provisioning steps:
// InitRedisKeyspace and PublishTenantName.
//
// PRD reference: zeroroot-ai/tenant-operator#76 User Story 35 — per-step
// contract tests that stub the dependent subsystem and verify each step's
// preconditions, side-effects, and idempotency.
//
// Test shape: hermetic. Each test spins up a miniredis instance and the
// real redisstate.RedisClient against it. No docker, no Kubernetes. The
// test exercises the same code paths as production minus the network
// transport (miniredis is in-process).

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/redisstate"
)

// newRedisTestHarness creates a miniredis + real RedisClient for a single test.
// The harness is torn down automatically on t.Cleanup.
func newRedisTestHarness(t *testing.T) (*miniredis.Miniredis, redisstate.Client) {
	t.Helper()
	mr := miniredis.RunT(t)
	c, err := redisstate.NewRedisClient(redisstate.Config{Addr: mr.Addr()})
	if err != nil {
		t.Fatalf("NewRedisClient: %v", err)
	}
	return mr, c
}

// newTenantForRedisTest produces a minimal Tenant suitable for the Redis step
// tests. Uses the supplied tenantID as the CR name (the canonical tenant
// identifier in every keyspace operation).
func newTenantForRedisTest(tenantID, displayName string) *gibsonv1alpha1.Tenant {
	return &gibsonv1alpha1.Tenant{
		ObjectMeta: metav1.ObjectMeta{Name: tenantID},
		Spec: gibsonv1alpha1.TenantSpec{
			Owner:       "owner@example.com",
			DisplayName: displayName,
		},
		Status: gibsonv1alpha1.TenantStatus{Conditions: []metav1.Condition{}},
	}
}

// ---------------------------------------------------------------------------
// InitRedisKeyspace
// ---------------------------------------------------------------------------

// TestInitRedisStep_HappyPath verifies that a successful Provision call:
//   - returns done=true, err=nil;
//   - writes a non-empty "initialized" marker in Redis under the tenant's
//     keyspace (key tenant:<id>:initialized).
func TestInitRedisStep_HappyPath(t *testing.T) {
	t.Parallel()
	mr, rc := newRedisTestHarness(t)
	deps := ProvisionDeps{Redis: rc}
	tenant := newTenantForRedisTest("acme", "Acme Corp")

	step := newInitRedisStep(deps)
	done, err := step.Provision(context.Background(), tenant, nil)
	if err != nil {
		t.Fatalf("Provision: unexpected error: %v", err)
	}
	if !done {
		t.Fatal("Provision: expected done=true on success")
	}

	val, miniErr := mr.Get("tenant:acme:initialized")
	if miniErr != nil {
		t.Fatalf("expected tenant:acme:initialized to be set; miniredis error: %v", miniErr)
	}
	if val == "" {
		t.Error("tenant:acme:initialized must be a non-empty RFC3339 timestamp, got empty")
	}
}

// TestInitRedisStep_Idempotent verifies that calling Provision twice on the
// same tenant does not fail and leaves the keyspace in a consistent state.
// The saga runner may call Provision on each reconcile even when the step's
// condition is already True (e.g., on observed-generation change), so
// idempotency here is a correctness requirement.
func TestInitRedisStep_Idempotent(t *testing.T) {
	t.Parallel()
	mr, rc := newRedisTestHarness(t)
	deps := ProvisionDeps{Redis: rc}
	tenant := newTenantForRedisTest("idempotent", "Idempotent Co")

	step := newInitRedisStep(deps)

	// First invocation.
	if done, err := step.Provision(context.Background(), tenant, nil); err != nil || !done {
		t.Fatalf("first Provision: done=%v err=%v", done, err)
	}
	first, _ := mr.Get("tenant:idempotent:initialized")

	// Advance miniredis clock slightly so any time-based value would differ.
	mr.FastForward(time.Second)

	// Second invocation — must succeed (SET overwrites the key without error).
	if done, err := step.Provision(context.Background(), tenant, nil); err != nil || !done {
		t.Fatalf("second Provision: done=%v err=%v (must be idempotent)", done, err)
	}

	// Key still present; value may differ (second SET wins) but must be non-empty.
	second, err := mr.Get("tenant:idempotent:initialized")
	if err != nil {
		t.Fatalf("expected key still present after second invocation; miniredis error: %v", err)
	}
	if second == "" {
		t.Errorf("key must still carry a non-empty value after second SET; got empty")
	}
	_ = first // suppress unused-variable lint; value documented above
}

// TestInitRedisStep_RejectsWrongType verifies that passing a non-Tenant
// ConditionedObject returns an error and does not write to Redis.
func TestInitRedisStep_RejectsWrongType(t *testing.T) {
	t.Parallel()
	mr, rc := newRedisTestHarness(t)
	deps := ProvisionDeps{Redis: rc}

	step := newInitRedisStep(deps)
	ae := &gibsonv1alpha1.AgentEnrollment{
		ObjectMeta: metav1.ObjectMeta{Name: "wrong"},
	}
	done, err := step.Provision(context.Background(), ae, nil)
	if err == nil {
		t.Fatal("expected error for non-Tenant object, got nil")
	}
	if done {
		t.Fatal("expected done=false on type-mismatch")
	}
	if keys := mr.Keys(); len(keys) != 0 {
		t.Fatalf("expected no Redis writes on type-mismatch; got %v", keys)
	}
}

// TestInitRedisStep_RedisError verifies that a Redis failure (miniredis
// SetError) surfaces as a non-nil error from Provision. The saga runner
// handles any non-nil error as a failure regardless of the done value:
// the runner inspects err first, then classifies it as transient or
// permanent. A non-nil error here will cause the runner to requeue with
// backoff.
func TestInitRedisStep_RedisError(t *testing.T) {
	t.Parallel()
	mr, rc := newRedisTestHarness(t)
	deps := ProvisionDeps{Redis: rc}
	tenant := newTenantForRedisTest("erroring", "Error Corp")

	// Inject a SET error for all commands.
	mr.SetError("REDIS ERROR injected for test")

	step := newInitRedisStep(deps)
	_, err := step.Provision(context.Background(), tenant, nil)
	if err == nil {
		t.Fatal("expected error when Redis SET fails, got nil")
	}
}

// ---------------------------------------------------------------------------
// PublishTenantName
// ---------------------------------------------------------------------------

// TestPublishTenantNameStep_HappyPath verifies that a successful Provision
// call writes the tenant's DisplayName into Redis under the canonical key
// tenant:name:<id> — the key the daemon's GetTenantName handler reads.
func TestPublishTenantNameStep_HappyPath(t *testing.T) {
	t.Parallel()
	mr, rc := newRedisTestHarness(t)
	deps := ProvisionDeps{Redis: rc}
	tenant := newTenantForRedisTest("acme", "Acme Corp")

	step := newPublishTenantNameStep(deps)
	done, err := step.Provision(context.Background(), tenant, nil)
	if err != nil {
		t.Fatalf("Provision: unexpected error: %v", err)
	}
	if !done {
		t.Fatal("Provision: expected done=true on success")
	}

	val, miniErr := mr.Get("tenant:name:acme")
	if miniErr != nil {
		t.Fatalf("expected tenant:name:acme to be set; miniredis error: %v", miniErr)
	}
	if val != "Acme Corp" {
		t.Errorf("expected tenant:name:acme = %q, got %q", "Acme Corp", val)
	}
}

// TestPublishTenantNameStep_FallsBackToTenantID verifies that when
// Spec.DisplayName is empty the step falls back to using the tenant's CR name
// (the tenantID). This protects out-of-band tenants created via kubectl
// whose spec might omit DisplayName.
func TestPublishTenantNameStep_FallsBackToTenantID(t *testing.T) {
	t.Parallel()
	mr, rc := newRedisTestHarness(t)
	deps := ProvisionDeps{Redis: rc}

	// Tenant with empty DisplayName — the step should write the tenantID instead.
	tenant := newTenantForRedisTest("noname", "" /* empty DisplayName */)

	step := newPublishTenantNameStep(deps)
	done, err := step.Provision(context.Background(), tenant, nil)
	if err != nil {
		t.Fatalf("Provision: unexpected error: %v", err)
	}
	if !done {
		t.Fatal("Provision: expected done=true on success")
	}

	val, miniErr := mr.Get("tenant:name:noname")
	if miniErr != nil {
		t.Fatalf("expected tenant:name:noname to be set; miniredis error: %v", miniErr)
	}
	if val != "noname" {
		t.Errorf("expected fallback to tenant CR name %q, got %q", "noname", val)
	}
}

// TestPublishTenantNameStep_Idempotent verifies that calling Provision twice
// with the same tenant is safe: the second call overwrites the key with the
// same value and returns done=true without error.
func TestPublishTenantNameStep_Idempotent(t *testing.T) {
	t.Parallel()
	mr, rc := newRedisTestHarness(t)
	deps := ProvisionDeps{Redis: rc}
	tenant := newTenantForRedisTest("idem", "Idempotent LLC")

	step := newPublishTenantNameStep(deps)

	// First call.
	if done, err := step.Provision(context.Background(), tenant, nil); err != nil || !done {
		t.Fatalf("first Provision: done=%v err=%v", done, err)
	}
	// Second call — must not fail.
	if done, err := step.Provision(context.Background(), tenant, nil); err != nil || !done {
		t.Fatalf("second Provision (idempotent): done=%v err=%v", done, err)
	}

	val, miniErr := mr.Get("tenant:name:idem")
	if miniErr != nil {
		t.Fatalf("key must still be present after second call; miniredis error: %v", miniErr)
	}
	if val != "Idempotent LLC" {
		t.Errorf("expected %q, got %q", "Idempotent LLC", val)
	}
}

// TestPublishTenantNameStep_RejectsWrongType mirrors the analogous test for
// InitRedisKeyspace: a non-Tenant ConditionedObject must return an error and
// must not touch Redis.
func TestPublishTenantNameStep_RejectsWrongType(t *testing.T) {
	t.Parallel()
	mr, rc := newRedisTestHarness(t)
	deps := ProvisionDeps{Redis: rc}

	step := newPublishTenantNameStep(deps)
	ae := &gibsonv1alpha1.AgentEnrollment{
		ObjectMeta: metav1.ObjectMeta{Name: "wrong"},
	}
	done, err := step.Provision(context.Background(), ae, nil)
	if err == nil {
		t.Fatal("expected error for non-Tenant object, got nil")
	}
	if done {
		t.Fatal("expected done=false on type-mismatch")
	}
	if keys := mr.Keys(); len(keys) != 0 {
		t.Fatalf("expected no Redis writes on type-mismatch; got %v", keys)
	}
}

// TestPublishTenantNameStep_RedisError verifies that a Redis SET failure
// surfaces as a non-nil error from Provision. The saga runner handles any
// non-nil error as a failure regardless of the done value and retries with
// backoff. Redis network errors wrap clients.ErrUnreachable (transient),
// so the runner will not block on them.
func TestPublishTenantNameStep_RedisError(t *testing.T) {
	t.Parallel()
	mr, rc := newRedisTestHarness(t)
	deps := ProvisionDeps{Redis: rc}
	tenant := newTenantForRedisTest("erroring", "Error Corp")

	// Inject a SET error for all commands.
	mr.SetError("REDIS ERROR injected for test")

	step := newPublishTenantNameStep(deps)
	_, err := step.Provision(context.Background(), tenant, nil)
	if err == nil {
		t.Fatal("expected error when Redis SET fails, got nil")
	}
}

// TestRedisSteps_OrderInProvisionSteps locks the ordering invariant between
// the two retained Redis steps. The contract:
//
//   - PublishTenantName comes AFTER InitRedisKeyspace (the name is published
//     only after the keyspace is initialised, so readers can't see a name
//     without a keyspace).
//
// E8/gibson#805 cutover: the ProvisionSecretsBackend and DataPlaneProvisioned
// neighbours were removed (those domains moved to the TenantSecretsBackend /
// TenantDataPlane sub-CRDs), so the only remaining provision-saga ordering
// invariant is between the two Redis steps.
//
// This is complementary to TestProvisionSteps_RegistryContract (which checks
// the graph is acyclic and Requires() references are valid); this test focuses
// on the Redis-specific ordering invariant.
func TestRedisSteps_OrderInProvisionSteps(t *testing.T) {
	t.Parallel()
	_, rc := newRedisTestHarness(t)
	deps := ProvisionDeps{Redis: rc}
	steps := ProvisionSteps(deps)

	indexOf := func(name string) int {
		for i, s := range steps {
			if s.Name() == name {
				return i
			}
		}
		return -1
	}

	require := func(before, after string) {
		t.Helper()
		bi, ai := indexOf(before), indexOf(after)
		if bi < 0 {
			t.Errorf("step %q not found in ProvisionSteps", before)
			return
		}
		if ai < 0 {
			t.Errorf("step %q not found in ProvisionSteps", after)
			return
		}
		if bi >= ai {
			t.Errorf("ordering violation: %q (index %d) must come before %q (index %d)",
				before, bi, after, ai)
		}
	}

	require("InitRedisKeyspace", "PublishTenantName")
}
