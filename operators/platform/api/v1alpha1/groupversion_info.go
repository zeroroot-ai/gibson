// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

// Package v1alpha1 contains API Schema definitions for the gibson
// v1alpha1 API group as owned by platform-operator. The same group name
// (`gibson.zeroroot.ai`) is shared with tenant-operator's CRDs; the two
// operators define different Kinds within the group.
//
// +kubebuilder:object:generate=true
// +groupName=gibson.zeroroot.ai
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	// SchemeGroupVersion is group version used to register these objects.
	SchemeGroupVersion = schema.GroupVersion{Group: "gibson.zeroroot.ai", Version: "v1alpha1"}

	// GroupVersion is an alias for SchemeGroupVersion.
	GroupVersion = SchemeGroupVersion

	// SchemeBuilder is used to add go types to the GroupVersionKind scheme.
	SchemeBuilder = &scheme.Builder{GroupVersion: SchemeGroupVersion}

	// AddToScheme adds the types in this group-version to the given scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)
