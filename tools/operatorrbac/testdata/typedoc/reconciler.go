// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package typedoc is a fixture: its rbac marker is in the doc comment of a
// type, where controller-gen ignores it.
package typedoc

// Reconciler reconciles a Widget.
//
// +kubebuilder:rbac:groups=example.io,resources=widgets,verbs=get;list
type Reconciler struct{}
