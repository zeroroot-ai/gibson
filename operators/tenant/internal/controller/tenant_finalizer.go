/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// deleteNamespace deletes a namespace if it exists. Returns done=true when
// the namespace is gone (not found). Returns done=false if the namespace
// exists and is Terminating (Kubernetes is still cascading).
func deleteNamespace(ctx context.Context, c client.Client, name string) (bool, error) {
	existing := &corev1.Namespace{}
	err := c.Get(ctx, types.NamespacedName{Name: name}, existing)
	if apierrors.IsNotFound(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	// If already terminating, wait for cascade.
	if existing.DeletionTimestamp != nil {
		return false, nil
	}
	// Issue deletion.
	if err := c.Delete(ctx, existing, &client.DeleteOptions{
		PropagationPolicy: ptrToPropagationPolicy(metav1.DeletePropagationForeground),
	}); err != nil && !apierrors.IsNotFound(err) {
		return false, err
	}
	return false, nil
}

func ptrToPropagationPolicy(p metav1.DeletionPropagation) *metav1.DeletionPropagation {
	return &p
}
