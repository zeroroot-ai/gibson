// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package clean is a fixture: its rbac marker is above a function and apart
// from the function's doc comment, where controller-gen reads it.
package clean

// Reconciler reconciles a Widget.
type Reconciler struct{}

// +kubebuilder:rbac:groups=example.io;core,resources=widgets;secrets,verbs=get;list

// Reconcile does nothing.
func (Reconciler) Reconcile() {}
