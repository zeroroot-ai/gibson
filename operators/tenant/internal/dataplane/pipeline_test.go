// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package dataplane

import (
	"context"
	"errors"
	"testing"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
)

// stubStep returns a Step where Provision and Rollback record calls into the
// provided slices and optionally fail.
func stubStep(name string, called *[]string, provErr, rbErr error) Step {
	return Step{
		Name: name,
		Provision: func(_ context.Context, tenantID string) error {
			*called = append(*called, "provision:"+name)
			return provErr
		},
		Rollback: func(_ context.Context, tenantID string) error {
			*called = append(*called, "rollback:"+name)
			return rbErr
		},
		// StatusUpdate is nil — tests don't exercise CRD status patching
		// (that would require envtest/fake client).
		StatusUpdate: nil,
	}
}

// buildTestPipeline constructs a pipelineProvisioner whose steps are replaced
// with the provided stubs. The K8sClient and Recorder are left nil so CRD
// updates are skipped (no envtest needed).
func buildTestPipeline(steps []Step) *pipelineProvisioner {
	p := New(PipelineConfig{})
	p.steps = steps
	return p
}

func TestPipelineProvisionHappyPath(t *testing.T) {
	t.Parallel()
	var called []string
	steps := []Step{
		stubStep("Postgres", &called, nil, nil),
		stubStep("Neo4j", &called, nil, nil),
		stubStep("Redis", &called, nil, nil),
	}
	p := buildTestPipeline(steps)

	if err := p.Provision(context.Background(), "tenant-abc"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []string{"provision:Postgres", "provision:Neo4j", "provision:Redis"}
	for i, w := range want {
		if i >= len(called) {
			t.Fatalf("expected %d calls, got %d", len(want), len(called))
		}
		if called[i] != w {
			t.Errorf("step %d: got %q, want %q", i, called[i], w)
		}
	}
}

func TestPipelineRollbackOnStep2Failure(t *testing.T) {
	t.Parallel()
	var called []string
	failErr := errors.New("neo4j unavailable")
	steps := []Step{
		stubStep("Postgres", &called, nil, nil),
		stubStep("Neo4j", &called, failErr, nil),
		stubStep("Redis", &called, nil, nil), // should not be reached
	}
	p := buildTestPipeline(steps)

	err := p.Provision(context.Background(), "tenant-xyz")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, failErr) {
		t.Errorf("error chain should contain failErr; got: %v", err)
	}

	// Postgres provision ran, Neo4j provision failed, then Postgres rollback ran.
	// Redis provision and rollback must NOT appear.
	wantPresent := []string{"provision:Postgres", "provision:Neo4j", "rollback:Postgres"}
	wantAbsent := []string{"provision:Redis", "rollback:Redis", "rollback:Neo4j"}

	calledSet := make(map[string]bool)
	for _, c := range called {
		calledSet[c] = true
	}
	for _, w := range wantPresent {
		if !calledSet[w] {
			t.Errorf("expected %q to be called, but was not; calls: %v", w, called)
		}
	}
	for _, w := range wantAbsent {
		if calledSet[w] {
			t.Errorf("expected %q to NOT be called, but it was; calls: %v", w, called)
		}
	}
}

func TestPipelineRollbackLIFOOrder(t *testing.T) {
	t.Parallel()
	var called []string
	failErr := errors.New("vector down")
	steps := []Step{
		stubStep("Postgres", &called, nil, nil),
		stubStep("Neo4j", &called, nil, nil),
		stubStep("Redis", &called, nil, nil),
		stubStep("Vector", &called, failErr, nil),
	}
	p := buildTestPipeline(steps)

	if err := p.Provision(context.Background(), "tenant-def"); err == nil {
		t.Fatal("expected error")
	}

	// Rollbacks must be in LIFO order: Redis, Neo4j, Postgres (Vector failed so
	// no rollback for it).
	wantSuffix := []string{"rollback:Redis", "rollback:Neo4j", "rollback:Postgres"}
	if len(called) < len(wantSuffix) {
		t.Fatalf("too few calls: %v", called)
	}
	suffix := called[len(called)-len(wantSuffix):]
	for i, w := range wantSuffix {
		if suffix[i] != w {
			t.Errorf("rollback[%d]: got %q, want %q; full calls: %v", i, suffix[i], w, called)
		}
	}
}

func TestPipelineDeprovisionReverseOrder(t *testing.T) {
	t.Parallel()
	var called []string
	steps := []Step{
		stubStep("Postgres", &called, nil, nil),
		stubStep("Neo4j", &called, nil, nil),
		stubStep("Redis", &called, nil, nil),
	}
	p := buildTestPipeline(steps)

	if err := p.Deprovision(context.Background(), "tenant-ghi"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []string{"rollback:Redis", "rollback:Neo4j", "rollback:Postgres"}
	if len(called) != len(want) {
		t.Fatalf("expected %d calls, got %d: %v", len(want), len(called), called)
	}
	for i, w := range want {
		if called[i] != w {
			t.Errorf("step %d: got %q, want %q", i, called[i], w)
		}
	}
}

func TestPipelineDeprovisionCollectsErrors(t *testing.T) {
	t.Parallel()
	var called []string
	rb1Err := errors.New("redis rb error")
	steps := []Step{
		stubStep("Postgres", &called, nil, nil),
		stubStep("Neo4j", &called, nil, nil),
		stubStep("Redis", &called, nil, rb1Err),
	}
	p := buildTestPipeline(steps)

	err := p.Deprovision(context.Background(), "tenant-jkl")
	// Deprovision should continue through all steps even if one rollback errors.
	if err == nil {
		t.Fatal("expected aggregate error, got nil")
	}
	if !errors.Is(err, rb1Err) {
		t.Errorf("error should contain rb1Err; got: %v", err)
	}
	// All three rollbacks must have been called.
	if len(called) != 3 {
		t.Errorf("expected 3 rollback calls, got %d: %v", len(called), called)
	}
}

// stubStepPreExisting is like stubStep but marks the step as already provisioned
// in a prior run, so the pipeline excludes it from rollback on failure.
func stubStepPreExisting(name string, called *[]string, provErr, rbErr error) Step {
	s := stubStep(name, called, provErr, rbErr)
	s.AlreadyProvisioned = func(_ *gibsonv1alpha1.TenantDataPlaneStatus) bool { return true }
	return s
}

// TestPipelineReReconcileNoRollbackOnPreExisting verifies that when all
// earlier steps were already provisioned in a prior run and a later step
// fails, the pre-existing steps are NOT rolled back (gibson#279).
func TestPipelineReReconcileNoRollbackOnPreExisting(t *testing.T) {
	t.Parallel()
	var called []string
	vectorErr := errors.New("vector 409 conflict")
	steps := []Step{
		stubStepPreExisting("Postgres", &called, nil, nil),
		stubStepPreExisting("Neo4j", &called, nil, nil),
		stubStepPreExisting("Redis", &called, nil, nil),
		stubStep("Vector", &called, vectorErr, nil), // Vector fails; not pre-existing
	}
	p := buildTestPipeline(steps)

	err := p.Provision(context.Background(), "tenant-recon")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, vectorErr) {
		t.Errorf("error chain should contain vectorErr; got: %v", err)
	}

	// Postgres, Neo4j, Redis provision calls ran (idempotent re-confirm).
	// Vector provision failed. None of the pre-existing steps should be
	// rolled back; only Vector was new to this pass (and it failed, so
	// it has no rollback either).
	calledSet := make(map[string]bool)
	for _, c := range called {
		calledSet[c] = true
	}
	wantPresent := []string{"provision:Postgres", "provision:Neo4j", "provision:Redis", "provision:Vector"}
	wantAbsent := []string{"rollback:Postgres", "rollback:Neo4j", "rollback:Redis", "rollback:Vector"}
	for _, w := range wantPresent {
		if !calledSet[w] {
			t.Errorf("expected %q to be called; calls: %v", w, called)
		}
	}
	for _, w := range wantAbsent {
		if calledSet[w] {
			t.Errorf("expected %q NOT to be called; calls: %v", w, called)
		}
	}
}

// TestPipelineFirstPassRollbackOnFailure verifies that on the FIRST provision
// pass (no pre-existing steps), a later step failure still triggers LIFO
// rollback of all previously completed steps in this pass (existing behavior).
func TestPipelineFirstPassRollbackOnFailure(t *testing.T) {
	t.Parallel()
	var called []string
	vectorErr := errors.New("vector down")
	steps := []Step{
		stubStep("Postgres", &called, nil, nil),
		stubStep("Neo4j", &called, nil, nil),
		stubStep("Redis", &called, nil, nil),
		stubStep("Vector", &called, vectorErr, nil),
	}
	p := buildTestPipeline(steps)

	err := p.Provision(context.Background(), "tenant-first")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, vectorErr) {
		t.Errorf("error chain should contain vectorErr; got: %v", err)
	}

	// Vector failed → rollback Postgres, Neo4j, Redis in LIFO order.
	calledSet := make(map[string]bool)
	for _, c := range called {
		calledSet[c] = true
	}
	wantRolledBack := []string{"rollback:Redis", "rollback:Neo4j", "rollback:Postgres"}
	for _, w := range wantRolledBack {
		if !calledSet[w] {
			t.Errorf("expected %q to be called; calls: %v", w, called)
		}
	}
	if calledSet["rollback:Vector"] {
		t.Errorf("Vector failed so its rollback must NOT be called; calls: %v", called)
	}
	// Verify LIFO order specifically.
	var rollbacks []string
	for _, c := range called {
		if len(c) >= 9 && c[:9] == "rollback:" {
			rollbacks = append(rollbacks, c)
		}
	}
	wantOrder := []string{"rollback:Redis", "rollback:Neo4j", "rollback:Postgres"}
	for i, w := range wantOrder {
		if i >= len(rollbacks) || rollbacks[i] != w {
			t.Errorf("rollback[%d]: got %q, want %q; full rollbacks: %v", i, func() string {
				if i < len(rollbacks) {
					return rollbacks[i]
				}
				return "<missing>"
			}(), w, rollbacks)
		}
	}
}

func TestPipelineDoubleProvisionIdempotent(t *testing.T) {
	t.Parallel()
	var called []string
	steps := []Step{
		stubStep("Postgres", &called, nil, nil),
		stubStep("Neo4j", &called, nil, nil),
	}
	p := buildTestPipeline(steps)

	ctx := context.Background()
	if err := p.Provision(ctx, "tenant-idem"); err != nil {
		t.Fatalf("first Provision error: %v", err)
	}
	if err := p.Provision(ctx, "tenant-idem"); err != nil {
		t.Fatalf("second Provision error: %v", err)
	}
	// Both provisions should succeed (stubs are always idempotent).
	if len(called) != 4 {
		t.Errorf("expected 4 provision calls (2 per step × 2 runs), got %d: %v", len(called), called)
	}
}
