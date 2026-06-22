/*
Copyright 2026 Zero Root AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Contract tests for the RegisterTenantWithPlatform provisioning step
// (deploy#782 / gibson#715): it writes the
// (tenant:<name>, parent, system_tenant:_system) registration tuple the
// daemon's catalog fan-out enumerates.

package flows

import (
	"context"
	"errors"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/fga"
)

// testTenantName is the fixed tenant name these contract tests exercise.
const testTenantName = "acme"

func registerTenant() *gibsonv1alpha1.Tenant {
	return &gibsonv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: testTenantName}}
}

func wantParentTuple() fga.Tuple {
	return fga.Tuple{User: "tenant:" + testTenantName, Relation: "parent", Object: "system_tenant:_system"}
}

// TestRegisterTenantWithPlatform_WritesParentTuple asserts the step writes the
// tenant→system_tenant parent registration tuple when it is absent.
func TestRegisterTenantWithPlatform_WritesParentTuple(t *testing.T) {
	t.Parallel()
	stub := &stubFGAClient{}
	step := newRegisterTenantWithPlatformStep(ProvisionDeps{FGA: stub})

	done, err := step.Provision(context.Background(), registerTenant(), nil)
	if !done || err != nil {
		t.Fatalf("Provision: got (%v, %v), want (true, nil)", done, err)
	}
	want := wantParentTuple()
	if len(stub.written) != 1 || stub.written[0] != want {
		t.Fatalf("expected exactly the parent tuple written; got %v", stub.written)
	}
}

// TestRegisterTenantWithPlatform_Idempotent asserts a second Provision pass on
// an already-registered tenant writes nothing (read-before-write), which is
// what lets the step backfill pre-existing tenants on re-reconcile.
func TestRegisterTenantWithPlatform_Idempotent(t *testing.T) {
	t.Parallel()
	stub := &stubFGAClient{written: []fga.Tuple{wantParentTuple()}}
	step := newRegisterTenantWithPlatformStep(ProvisionDeps{FGA: stub})

	done, err := step.Provision(context.Background(), registerTenant(), nil)
	if !done || err != nil {
		t.Fatalf("Provision: got (%v, %v), want (true, nil)", done, err)
	}
	if len(stub.written) != 1 {
		t.Fatalf("idempotent re-run must not write a duplicate; written=%v", stub.written)
	}
}

// TestRegisterTenantWithPlatform_Deprovision asserts teardown removes the
// parent tuple (the teardown DeleteTenantFGATuples step cannot — it scopes to
// tuples whose OBJECT is tenant:<name>, but here the tenant is the USER).
func TestRegisterTenantWithPlatform_Deprovision(t *testing.T) {
	t.Parallel()
	stub := &stubFGAClient{written: []fga.Tuple{wantParentTuple()}}
	step := newRegisterTenantWithPlatformStep(ProvisionDeps{FGA: stub})

	if err := step.Deprovision(context.Background(), registerTenant(), nil); err != nil {
		t.Fatalf("Deprovision: %v", err)
	}
	if len(stub.deleted) != 1 || stub.deleted[0] != wantParentTuple() {
		t.Fatalf("expected the parent tuple deleted; deleted=%v", stub.deleted)
	}
}

// TestRegisterTenantWithPlatform_NilFGAFailsLoud asserts a nil FGA client is a
// loud misconfiguration error, not a silent skip (one-code-path discipline).
func TestRegisterTenantWithPlatform_NilFGAFailsLoud(t *testing.T) {
	t.Parallel()
	step := newRegisterTenantWithPlatformStep(ProvisionDeps{FGA: nil})

	_, err := step.Provision(context.Background(), registerTenant(), nil)
	if !errors.Is(err, clients.ErrInvalidInput) {
		t.Fatalf("nil FGA must fail with ErrInvalidInput; got %v", err)
	}
}

// TestRegisterTenantWithPlatform_PresentInProvisionSteps asserts the step is
// wired into the provision saga (so tenants are actually registered).
func TestRegisterTenantWithPlatform_PresentInProvisionSteps(t *testing.T) {
	t.Parallel()
	steps := ProvisionSteps(ProvisionDeps{FGA: &stubFGAClient{}, Vault: &stubVaultAdmin{}})
	found := false
	for _, s := range steps {
		if s.Name() == "RegisterTenantWithPlatform" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("RegisterTenantWithPlatform must be in ProvisionSteps; order: %s", namesOf(steps))
	}
}
