// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package v1alpha1 contains the ConnectorInstance API (ADR-0014).
// +kubebuilder:object:generate=true
// +groupName=gibson.zeroroot.ai
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	// SchemeGroupVersion is the group version for the ConnectorInstance API.
	SchemeGroupVersion = schema.GroupVersion{Group: "gibson.zeroroot.ai", Version: "v1alpha1"}
	// GroupVersion is an alias for SchemeGroupVersion.
	GroupVersion = SchemeGroupVersion
	// SchemeBuilder registers the types with a scheme. This is the standard
	// kubebuilder api-package pattern, matching operators/tenant and
	// operators/platform.
	SchemeBuilder = &scheme.Builder{GroupVersion: SchemeGroupVersion} //nolint:staticcheck // SA1019: scheme.Builder is the kubebuilder-generated api pattern used by every gibson operator
	// AddToScheme adds the types in this group-version to a scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)
