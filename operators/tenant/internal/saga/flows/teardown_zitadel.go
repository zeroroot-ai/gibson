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

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/saga"
)

// removeZitadelOrgStep deletes the tenant's Zitadel organization during
// teardown.
//
// Precondition: all TenantMember CRDs referencing this tenant must be
// deleted before this step will proceed. Returning done=false (no error)
// signals the saga runner to requeue without counting it as a failure,
// giving the TenantMember controller time to finish its own cleanup.
type removeZitadelOrgStep struct {
	saga.StepBase
	deps ProvisionDeps
}

func newRemoveZitadelOrgStep(deps ProvisionDeps) *removeZitadelOrgStep {
	return &removeZitadelOrgStep{
		StepBase: saga.StepBase{
			N:     "RemoveZitadelOrg",
			C:     "ZitadelOrgDeleted",
			Req:   []string{"DeleteTenantFGATuples"},
			Caps:  []saga.ClientCapability{saga.CapabilityZitadelAdmin, saga.CapabilityKubernetes},
			Owner: "zitadel-integration",
			// P99 intentionally zero — this step blocks on TenantMember
			// CRDs being cleaned up by their own controller, which can
			// take arbitrarily long for tenants with many members.
		},
		deps: deps,
	}
}

func (s *removeZitadelOrgStep) Provision(ctx context.Context, obj saga.ConditionedObject, _ *saga.Deps) (bool, error) {
	t, err := tenantOf(obj)
	if err != nil {
		return false, err
	}

	// Nothing to clean up — org was never provisioned.
	if t.Status.ZitadelOrgID == "" {
		return true, nil
	}

	// Precondition: refuse to delete the Zitadel org while any TenantMember
	// CRDs remain in the tenant's namespace.
	if s.deps.K8sClient != nil {
		memberList := &gibsonv1alpha1.TenantMemberList{}
		if err := s.deps.K8sClient.List(ctx, memberList,
			client.InNamespace(t.Status.Namespace),
		); err != nil {
			return false, fmt.Errorf("removeZitadelOrg: list TenantMembers: %w", err)
		}
		if len(memberList.Items) > 0 {
			meta.SetStatusCondition(&t.Status.Conditions, metav1.Condition{
				Type:    "ZitadelOrgDeleted",
				Status:  metav1.ConditionFalse,
				Reason:  "WaitingForMembersRemoved",
				Message: fmt.Sprintf("%d TenantMember CRD(s) still exist in namespace %q; waiting for member controller to complete cleanup", len(memberList.Items), t.Status.Namespace),
			})
			return false, nil
		}
	}

	if err := s.deps.Zitadel.DeleteOrganization(ctx, t.Status.ZitadelOrgID); err != nil {
		if !errors.Is(err, clients.ErrNotFound) {
			return false, fmt.Errorf("removeZitadelOrg: DeleteOrganization: %w", err)
		}
	}

	t.Status.ZitadelOrgID = ""
	t.Status.ZitadelOrgSlug = ""
	meta.SetStatusCondition(&t.Status.Conditions, metav1.Condition{
		Type:    gibsonv1alpha1.ConditionZitadelOrgReady,
		Status:  metav1.ConditionFalse,
		Reason:  "Deleted",
		Message: "Zitadel organization removed during tenant teardown",
	})
	return true, nil
}

// RemoveZitadelOrgStep is the public factory kept for tests.
func RemoveZitadelOrgStep(deps ProvisionDeps) saga.Step {
	return newRemoveZitadelOrgStep(deps)
}
