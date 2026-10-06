// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// conditions.go re-exports the canonical condition helpers and reason
// constants from github.com/zeroroot-ai/gibson/pkg/platform/saga.
//
// Spec: tenant-provisioning-unification (Phase 2 task 2.2). The operator's
// saga package was the original home of these helpers; they now live in
// the platform package so the gibson daemon can use the same primitives.
// We keep operator-local symbols pointing at the platform versions so
// every existing operator call site continues to compile unchanged.

package saga

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	psaga "github.com/zeroroot-ai/gibson/pkg/platform/saga"
)

// Standard condition reasons. Values delegated to platform/saga.
const (
	ReasonPending          = psaga.ReasonPending
	ReasonInProgress       = psaga.ReasonInProgress
	ReasonReady            = psaga.ReasonReady
	ReasonSkipped          = psaga.ReasonSkipped
	ReasonUnreachable      = psaga.ReasonUnreachable
	ReasonRateLimited      = psaga.ReasonRateLimited
	ReasonConflict         = psaga.ReasonConflict
	ReasonInvalidSpec      = psaga.ReasonInvalidSpec
	ReasonAllStepsComplete = psaga.ReasonAllStepsComplete
	ReasonStepFailed       = psaga.ReasonStepFailed
)

// IsConditionTrue delegates to platform/saga.IsConditionTrue.
func IsConditionTrue(conditions []metav1.Condition, condType string) bool {
	return psaga.IsConditionTrue(conditions, condType)
}
