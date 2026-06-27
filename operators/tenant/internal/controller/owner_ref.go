// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package controller

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
)

// ResolveTenantOwnerRef returns the OwnerReference pointing at the Tenant
// that owns the given tenant-scoped namespace. The resolution is keyed on
// the `AnnotationOwnerTenantUID` / `AnnotationOwnerTenantName` annotations
// written by NamespaceProvisioner.ensureNamespace.
//
// When the namespace lacks the UID annotation the helper returns
// (nil, nil) — the caller decides whether to treat that as an error.
// Pre-upgrade clusters will hit this path on first reconcile and the
// parent Tenant may still be resolved by trimming the "tenant-" prefix;
// once the namespace reconciles once it will carry the annotation.
func ResolveTenantOwnerRef(
	ctx context.Context, c client.Client, namespace string,
) (*metav1.OwnerReference, error) {
	var ns corev1.Namespace
	if err := c.Get(ctx, types.NamespacedName{Name: namespace}, &ns); err != nil {
		return nil, fmt.Errorf("get namespace %q: %w", namespace, err)
	}

	uid := ns.Annotations[AnnotationOwnerTenantUID]
	name := ns.Annotations[AnnotationOwnerTenantName]

	// Fallback for pre-upgrade namespaces: derive tenant name from prefix,
	// then read UID off the live Tenant. Does NOT persist the annotation
	// here (that's the namespace reconciler's job) but unblocks children.
	if name == "" && strings.HasPrefix(namespace, "tenant-") {
		name = strings.TrimPrefix(namespace, "tenant-")
	}
	if name == "" {
		return nil, nil
	}

	// If we don't have a UID from the annotation, look up the Tenant.
	if uid == "" {
		var t gibsonv1alpha1.Tenant
		if err := c.Get(ctx, types.NamespacedName{Name: name}, &t); err != nil {
			if apierrors.IsNotFound(err) {
				// Tenant already deleted — nothing to own. Caller will
				// handle as orphan; reaper picks it up on teardown.
				return nil, nil
			}
			return nil, fmt.Errorf("get tenant %q: %w", name, err)
		}
		uid = string(t.UID)
	}

	if uid == "" {
		return nil, fmt.Errorf("tenant %q has empty uid", name)
	}

	return &metav1.OwnerReference{
		APIVersion:         gibsonv1alpha1.GroupVersion.String(),
		Kind:               "Tenant",
		Name:               name,
		UID:                types.UID(uid),
		BlockOwnerDeletion: ptr.To(false),
		Controller:         ptr.To(false),
	}, nil
}
