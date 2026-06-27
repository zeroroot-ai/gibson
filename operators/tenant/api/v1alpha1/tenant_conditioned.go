// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// GetConditions satisfies the saga.ConditionedObject interface.
func (t *Tenant) GetConditions() *[]metav1.Condition {
	return &t.Status.Conditions
}

// GetPhase satisfies the saga.ConditionedObject interface.
func (t *Tenant) GetPhase() string {
	return string(t.Status.Phase)
}

// SetPhase satisfies the saga.ConditionedObject interface.
func (t *Tenant) SetPhase(phase string) {
	t.Status.Phase = TenantPhase(phase)
}

// GetObservedGeneration satisfies the saga.ConditionedObject interface.
func (t *Tenant) GetObservedGeneration() int64 {
	return t.Status.ObservedGeneration
}

// SetObservedGeneration satisfies the saga.ConditionedObject interface.
func (t *Tenant) SetObservedGeneration(g int64) {
	t.Status.ObservedGeneration = g
}
