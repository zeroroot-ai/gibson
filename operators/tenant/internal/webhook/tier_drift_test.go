/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// tier_drift_test.go — drift gate between plans.yaml and the operator's
// tier const block + validating-webhook validTiers map. Failing this
// test means someone updated plans.yaml without updating the Go side,
// or vice-versa. Spec plans-and-quotas-simplification R3.3.
package webhook

import (
	"path/filepath"
	"runtime"
	"testing"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/plans"
)

// TestTierDrift_ConstsMatchPlansYAML asserts that the set of TenantTier
// constants in api/v1alpha1, the validTiers map in this package, and the
// plan ids in plans.yaml all agree.
func TestTierDrift_ConstsMatchPlansYAML(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve test source path")
	}
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
	plansPath := filepath.Join(repoRoot, "plans", "plans.yaml")

	reg, err := plans.Load(plansPath)
	if err != nil {
		t.Fatalf("load plans.yaml: %v", err)
	}

	wantIDs := make(map[string]struct{}, len(reg.Plans))
	for _, p := range reg.Plans {
		wantIDs[string(p.ID)] = struct{}{}
	}

	// 1) Every plan id must have a TenantTier const in the api package.
	knownConsts := map[string]gibsonv1alpha1.TenantTier{
		"team":              gibsonv1alpha1.TenantPlanTeam,
		"org":               gibsonv1alpha1.TenantPlanOrg,
		"enterprise":        gibsonv1alpha1.TenantPlanEnterprise,
		"enterprise-deploy": gibsonv1alpha1.TenantPlanEnterpriseDeploy,
	}
	for id := range wantIDs {
		if _, ok := knownConsts[id]; !ok {
			t.Errorf("plans.yaml has id %q with no matching TenantPlan* const in api/v1alpha1", id)
		}
	}
	// 2) Every TenantTier const must be a plan id in plans.yaml.
	for id := range knownConsts {
		if _, ok := wantIDs[id]; !ok {
			t.Errorf("api/v1alpha1 has TenantPlan* const %q with no matching plans.yaml entry", id)
		}
	}
	// 3) Every plan id must be in the webhook's validTiers allowlist.
	for id := range wantIDs {
		tier := gibsonv1alpha1.TenantTier(id)
		if _, ok := validTiers[tier]; !ok {
			t.Errorf("plans.yaml has id %q missing from webhook validTiers", id)
		}
	}
	// 4) Every entry in validTiers must be a plan id in plans.yaml.
	for tier := range validTiers {
		if _, ok := wantIDs[string(tier)]; !ok {
			t.Errorf("webhook validTiers has %q with no matching plans.yaml entry", tier)
		}
	}
}
