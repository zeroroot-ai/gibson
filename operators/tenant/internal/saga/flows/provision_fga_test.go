/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package flows

// Per-saga-step contract tests for the FGA-backed provisioning and teardown
// steps: DeleteTenantFGATuples (teardown).
//
// PRD reference: zeroroot-ai/tenant-operator#76 User Story 35 — per-step
// contract tests that stub the dependent subsystem and verify each step's
// preconditions, side-effects, and idempotency.
//
// Test shape: hermetic. Each test uses a stubFGAClient that records Write /
// Delete / Read calls in memory. No docker, no Kubernetes, no network.
// The stub satisfies the fga.Client interface exactly.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/fga"
)

// ---------------------------------------------------------------------------
// Stub
// ---------------------------------------------------------------------------

// stubFGAClient is an in-memory fga.Client for tests. It records all Write
// and Delete calls; Read returns tuples stored in the written slice so that
// Delete-after-Read flows work correctly.
type stubFGAClient struct {
	written   []fga.Tuple
	deleted   []fga.Tuple
	writeErr  error
	readErr   error
	deleteErr error
	pingCalls int
}

func (s *stubFGAClient) Write(_ context.Context, tuples []fga.Tuple) error {
	if s.writeErr != nil {
		return s.writeErr
	}
	s.written = append(s.written, tuples...)
	return nil
}

func (s *stubFGAClient) Delete(_ context.Context, tuples []fga.Tuple) error {
	if s.deleteErr != nil {
		return s.deleteErr
	}
	s.deleted = append(s.deleted, tuples...)
	// Remove deleted tuples from the written slice so subsequent reads
	// reflect the post-delete state (important for idempotency chains).
	remaining := s.written[:0]
	for _, w := range s.written {
		if !slices.Contains(tuples, w) {
			remaining = append(remaining, w)
		}
	}
	s.written = remaining
	return nil
}

func (s *stubFGAClient) Read(_ context.Context, filter fga.Tuple) ([]fga.Tuple, error) {
	if s.readErr != nil {
		return nil, s.readErr
	}
	var out []fga.Tuple
	for _, t := range s.written {
		if (filter.User == "" || filter.User == t.User) &&
			(filter.Relation == "" || filter.Relation == t.Relation) &&
			(filter.Object == "" || filter.Object == t.Object) {
			out = append(out, t)
		}
	}
	return out, nil
}

func (s *stubFGAClient) Check(_ context.Context, _, _, _ string) (bool, error) {
	return false, nil
}

func (s *stubFGAClient) Ping(_ context.Context) error {
	s.pingCalls++
	return nil
}

// ---------------------------------------------------------------------------
// DeleteTenantFGATuples — happy path
// ---------------------------------------------------------------------------

// TestDeleteTenantFGATuples_HappyPath verifies that when the FGA store
// contains tuples for the tenant, Provision reads them all and deletes them.
func TestDeleteTenantFGATuples_HappyPath(t *testing.T) {
	t.Parallel()
	stub := &stubFGAClient{
		written: []fga.Tuple{
			{User: "user:alice", Relation: "admin", Object: "tenant:acme"},
			{User: "user:bob", Relation: "member", Object: "tenant:acme"},
		},
	}
	deps := ProvisionDeps{FGA: stub}
	tenant := &gibsonv1alpha1.Tenant{
		ObjectMeta: metav1.ObjectMeta{Name: "acme"},
	}

	step := newDeleteTenantFGAStep(deps)
	done, err := step.Provision(context.Background(), tenant, nil)

	if err != nil {
		t.Fatalf("DeleteTenantFGATuples.Provision: unexpected error: %v", err)
	}
	if !done {
		t.Fatal("expected done=true on success")
	}
	if len(stub.deleted) != 2 {
		t.Fatalf("expected 2 tuples deleted, got %d: %v", len(stub.deleted), stub.deleted)
	}
	// Deleted tuples must be removed from the store's in-memory state.
	if len(stub.written) != 0 {
		t.Fatalf("expected store empty after delete, got %v", stub.written)
	}
}

// TestDeleteTenantFGATuples_NoTuples verifies that when there are no tuples
// for the tenant the step still returns done=true (idempotent teardown).
func TestDeleteTenantFGATuples_NoTuples(t *testing.T) {
	t.Parallel()
	stub := &stubFGAClient{} // empty store
	deps := ProvisionDeps{FGA: stub}
	tenant := &gibsonv1alpha1.Tenant{
		ObjectMeta: metav1.ObjectMeta{Name: "empty-tenant"},
	}

	step := newDeleteTenantFGAStep(deps)
	done, err := step.Provision(context.Background(), tenant, nil)

	if err != nil {
		t.Fatalf("unexpected error when no tuples exist: %v", err)
	}
	if !done {
		t.Fatal("expected done=true when no tuples to delete")
	}
	if len(stub.deleted) != 0 {
		t.Fatalf("Delete should not be called when Read returns empty; got %v", stub.deleted)
	}
}

// ---------------------------------------------------------------------------
// DeleteTenantFGATuples — idempotency
// ---------------------------------------------------------------------------

// TestDeleteTenantFGATuples_Idempotent verifies that calling Provision twice
// on the same tenant is safe: the second call finds no tuples (already
// deleted) and returns success without calling Delete.
func TestDeleteTenantFGATuples_Idempotent(t *testing.T) {
	t.Parallel()
	stub := &stubFGAClient{
		written: []fga.Tuple{
			{User: "user:alice", Relation: "admin", Object: "tenant:idempotent"},
		},
	}
	deps := ProvisionDeps{FGA: stub}
	tenant := &gibsonv1alpha1.Tenant{
		ObjectMeta: metav1.ObjectMeta{Name: "idempotent"},
	}
	step := newDeleteTenantFGAStep(deps)

	// First call: deletes the tuple.
	done, err := step.Provision(context.Background(), tenant, nil)
	if err != nil || !done {
		t.Fatalf("first Provision: got (%v, %v)", done, err)
	}

	// Second call: Read returns empty; Delete must not be called.
	deletedBefore := len(stub.deleted)
	done, err = step.Provision(context.Background(), tenant, nil)
	if err != nil || !done {
		t.Fatalf("second Provision: got (%v, %v)", done, err)
	}
	if len(stub.deleted) != deletedBefore {
		t.Fatalf("Delete must not be called on second Provision; deletedBefore=%d, deletedAfter=%d",
			deletedBefore, len(stub.deleted))
	}
}

// ---------------------------------------------------------------------------
// DeleteTenantFGATuples — scoping (only deletes tenant's own tuples)
// ---------------------------------------------------------------------------

// TestDeleteTenantFGATuples_ScopedToTenant verifies that the step only
// deletes tuples whose Object matches "tenant:<name>" and leaves tuples for
// other tenants untouched. The filter is critical for multi-tenant safety.
func TestDeleteTenantFGATuples_ScopedToTenant(t *testing.T) {
	t.Parallel()
	stub := &stubFGAClient{
		written: []fga.Tuple{
			// Target tenant's tuple.
			{User: "user:alice", Relation: "admin", Object: "tenant:acme"},
			// Another tenant's tuple — must NOT be deleted.
			{User: "user:bob", Relation: "admin", Object: "tenant:other-tenant"},
		},
	}
	deps := ProvisionDeps{FGA: stub}
	tenant := &gibsonv1alpha1.Tenant{
		ObjectMeta: metav1.ObjectMeta{Name: "acme"},
	}

	step := newDeleteTenantFGAStep(deps)
	done, err := step.Provision(context.Background(), tenant, nil)

	if err != nil || !done {
		t.Fatalf("Provision: got (%v, %v)", done, err)
	}
	// "tenant:other-tenant" tuple must remain.
	remaining, _ := stub.Read(context.Background(), fga.Tuple{Object: "tenant:other-tenant"})
	if len(remaining) != 1 {
		t.Fatalf("other-tenant tuple must not be deleted; remaining: %v", remaining)
	}
}

// ---------------------------------------------------------------------------
// DeleteTenantFGATuples — nil FGA client
// ---------------------------------------------------------------------------

// TestDeleteTenantFGATuples_NilFGAClientFails asserts that a nil FGA client
// causes DeleteTenantFGATuples to fail with a clear error. Enforces the
// one-code-path invariant (tenant-operator#95): the previous silent skip
// masked operator misconfiguration; teardown must fail loud when FGA is unset
// so operators see the problem before tenant data is partially cleaned up.
func TestDeleteTenantFGATuples_NilFGAClientFails(t *testing.T) {
	t.Parallel()
	deps := ProvisionDeps{FGA: nil}
	tenant := &gibsonv1alpha1.Tenant{
		ObjectMeta: metav1.ObjectMeta{Name: "acme"},
	}

	step := newDeleteTenantFGAStep(deps)
	done, err := step.Provision(context.Background(), tenant, nil)

	if err == nil {
		t.Fatal("nil FGA: expected error (operator misconfigured), got nil")
	}
	if done {
		t.Fatal("nil FGA: expected done=false on misconfiguration error")
	}
}

// ---------------------------------------------------------------------------
// DeleteTenantFGATuples — type safety
// ---------------------------------------------------------------------------

// TestDeleteTenantFGATuples_WrongTypeError verifies that passing a non-Tenant
// object returns an error and makes no FGA calls.
func TestDeleteTenantFGATuples_WrongTypeError(t *testing.T) {
	t.Parallel()
	stub := &stubFGAClient{}
	deps := ProvisionDeps{FGA: stub}
	other := &gibsonv1alpha1.AgentEnrollment{
		ObjectMeta: metav1.ObjectMeta{Name: "wrong"},
	}

	step := newDeleteTenantFGAStep(deps)
	done, err := step.Provision(context.Background(), other, nil)

	if done {
		t.Fatal("expected done=false for non-Tenant object")
	}
	if err == nil {
		t.Fatal("expected error for non-Tenant object")
	}
	if len(stub.deleted) != 0 {
		t.Fatalf("FGA.Delete must not be called for wrong type; got %d calls", len(stub.deleted))
	}
}

// ---------------------------------------------------------------------------
// DeleteTenantFGATuples — error propagation
// ---------------------------------------------------------------------------

// TestDeleteTenantFGATuples_ReadErrorPropagated verifies that a Read error
// (non-ErrNotFound) causes the step to return the error so the saga runner
// requeues with backoff.
func TestDeleteTenantFGATuples_ReadErrorPropagated(t *testing.T) {
	t.Parallel()
	wantErr := errors.New("fga read failure")
	stub := &stubFGAClient{readErr: wantErr}
	deps := ProvisionDeps{FGA: stub}
	tenant := &gibsonv1alpha1.Tenant{
		ObjectMeta: metav1.ObjectMeta{Name: "acme"},
	}

	step := newDeleteTenantFGAStep(deps)
	done, err := step.Provision(context.Background(), tenant, nil)

	if done {
		t.Fatal("expected done=false on Read error")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected wrapped wantErr in chain; got %v", err)
	}
}

// TestDeleteTenantFGATuples_ReadErrNotFoundIsSafe verifies that if Read
// returns ErrNotFound (e.g., FGA store has no tuples at all for this tenant)
// the step treats it as an already-clean state and returns done=true.
func TestDeleteTenantFGATuples_ReadErrNotFoundIsSafe(t *testing.T) {
	t.Parallel()
	stub := &stubFGAClient{readErr: fmt.Errorf("lookup: %w", clients.ErrNotFound)}
	deps := ProvisionDeps{FGA: stub}
	tenant := &gibsonv1alpha1.Tenant{
		ObjectMeta: metav1.ObjectMeta{Name: "acme"},
	}

	step := newDeleteTenantFGAStep(deps)
	done, err := step.Provision(context.Background(), tenant, nil)

	if err != nil {
		t.Fatalf("ErrNotFound from Read must be treated as success: %v", err)
	}
	if !done {
		t.Fatal("expected done=true when Read returns ErrNotFound")
	}
}

// TestDeleteTenantFGATuples_DeleteErrorPropagated verifies that a Delete
// error causes the step to return the error. The saga runner will requeue
// with backoff, which is safe since the Read-then-Delete pattern is
// deterministic: subsequent reads return the un-deleted tuples.
func TestDeleteTenantFGATuples_DeleteErrorPropagated(t *testing.T) {
	t.Parallel()
	wantErr := errors.New("fga delete failure")
	stub := &stubFGAClient{
		written:   []fga.Tuple{{User: "user:alice", Relation: "admin", Object: "tenant:acme"}},
		deleteErr: wantErr,
	}
	deps := ProvisionDeps{FGA: stub}
	tenant := &gibsonv1alpha1.Tenant{
		ObjectMeta: metav1.ObjectMeta{Name: "acme"},
	}

	step := newDeleteTenantFGAStep(deps)
	done, err := step.Provision(context.Background(), tenant, nil)

	if done {
		t.Fatal("expected done=false on Delete error")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected wrapped wantErr; got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Absence contract
// ---------------------------------------------------------------------------

// TestWriteInitialFGATuples_AbsentFromProvisionSteps asserts that the
// WriteInitialFGATuples step no longer appears in ProvisionSteps. The step
// wrote a malformed FGA tuple (user:base64(email), relation=admin) that
// matched no real FGA principal (expected user:<numeric_zitadel_sub>).
// TenantMember.acceptInvitation already writes the correct tuple via
// spec.AcceptedByUserID; this test locks the removal (tenant-operator#215).
func TestWriteInitialFGATuples_AbsentFromProvisionSteps(t *testing.T) {
	t.Parallel()
	deps := ProvisionDeps{
		FGA:   &stubFGAClient{},
		Vault: &stubVaultAdmin{},
	}
	steps := ProvisionSteps(deps)
	for _, s := range steps {
		if s.Name() == "WriteInitialFGATuples" {
			t.Fatalf("WriteInitialFGATuples must not be present in ProvisionSteps (tenant-operator#215); full order: %s",
				namesOf(steps))
		}
	}
}

// TestFGASteps_OrderInTeardownSteps locks that DeleteTenantFGATuples appears
// AFTER DeprovisionDataPlane in the teardown saga. FGA clean-up should not
// run until the data plane is deprovisioned to prevent orphaned references.
func TestFGASteps_OrderInTeardownSteps(t *testing.T) {
	t.Parallel()
	deps := ProvisionDeps{
		FGA:   &stubFGAClient{},
		Vault: &stubVaultAdmin{},
	}
	steps := TeardownSteps(deps)

	indices := map[string]int{}
	for i, s := range steps {
		indices[s.Name()] = i
	}

	required := []string{"DeprovisionDataPlane", "DeleteTenantFGATuples"}
	for _, name := range required {
		if _, ok := indices[name]; !ok {
			t.Fatalf("expected step %q in TeardownSteps; found: %v", name, namesOf(steps))
		}
	}

	if indices["DeprovisionDataPlane"] >= indices["DeleteTenantFGATuples"] {
		t.Fatalf("DeprovisionDataPlane (%d) must come before DeleteTenantFGATuples (%d); full order: %s",
			indices["DeprovisionDataPlane"],
			indices["DeleteTenantFGATuples"],
			namesOf(steps))
	}
}
