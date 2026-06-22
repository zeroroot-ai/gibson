/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package flows

import (
	"context"
	"errors"
	"fmt"
	"time"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/saga"
)

// ensureZitadelOrgStep provisions a Zitadel organization for the tenant.
//
// Per-org roles (owner/admin/member/viewer) are NOT created here. They are
// registered once globally for the `gibson` project by the post-install
// Helm Job from task 2.
type ensureZitadelOrgStep struct {
	saga.StepBase
	deps ProvisionDeps
}

func newEnsureZitadelOrgStep(deps ProvisionDeps) *ensureZitadelOrgStep {
	return &ensureZitadelOrgStep{
		StepBase: saga.StepBase{
			N:     "EnsureZitadelOrg",
			C:     gibsonv1alpha1.ConditionZitadelOrgReady,
			Req:   []string{"WaitForBillingConfirmation"},
			Caps:  []saga.ClientCapability{saga.CapabilityZitadelAdmin},
			Owner: "zitadel-integration",
			P99:   10 * time.Second,
		},
		deps: deps,
	}
}

func (s *ensureZitadelOrgStep) Provision(ctx context.Context, obj saga.ConditionedObject, _ *saga.Deps) (bool, error) {
	t, err := tenantOf(obj)
	if err != nil {
		return false, err
	}

	// Fast path: org already provisioned — verify it still exists in Zitadel.
	if t.Status.ZitadelOrgID != "" {
		_, err := s.deps.Zitadel.GetOrganization(ctx, t.Status.ZitadelOrgID)
		if err == nil {
			return true, nil
		}
		if !errors.Is(err, clients.ErrNotFound) {
			if clients.IsPermanent(err) {
				return false, err
			}
			return false, fmt.Errorf("ensureZitadelOrg: GetOrganization: %w", err)
		}
		// Org is gone — fall through to re-create.
		t.Status.ZitadelOrgID = ""
		t.Status.ZitadelOrgSlug = ""
	}

	orgID, err := s.deps.Zitadel.CreateOrganization(ctx, t.Spec.DisplayName, t.Name)
	if err != nil {
		if clients.IsPermanent(err) {
			return false, err
		}
		return false, fmt.Errorf("ensureZitadelOrg: CreateOrganization: %w", err)
	}

	t.Status.ZitadelOrgID = orgID
	t.Status.ZitadelOrgSlug = t.Name
	return true, nil
}

// EnsureZitadelOrgStep is the public factory kept for tests that exercise
// the step in isolation.
func EnsureZitadelOrgStep(deps ProvisionDeps) saga.Step {
	return newEnsureZitadelOrgStep(deps)
}
