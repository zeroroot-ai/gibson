/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

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
