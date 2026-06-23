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
	"time"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/identity"
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

	// Delegate to the shared org-ensure core (identity.EnsureOrg) so the saga
	// step and the declarative TenantIdentity controller (E8/gibson#803) are two
	// callers of ONE Zitadel-org codepath (ADR-0027). The saga passes
	// DisplayName as the org name and t.Name as the slug, exactly as before; the
	// fast-path / drift re-create logic now lives in identity.EnsureOrg.
	res, err := identity.EnsureOrg(ctx, s.deps.Zitadel, identity.Request{
		TenantID:    t.Name,
		DisplayName: t.Spec.DisplayName,
		KnownOrgID:  t.Status.ZitadelOrgID,
	})
	if err != nil {
		return false, err
	}

	t.Status.ZitadelOrgID = res.OrgID
	t.Status.ZitadelOrgSlug = res.Slug
	return true, nil
}

// EnsureZitadelOrgStep is the public factory kept for tests that exercise
// the step in isolation.
func EnsureZitadelOrgStep(deps ProvisionDeps) saga.Step {
	return newEnsureZitadelOrgStep(deps)
}
