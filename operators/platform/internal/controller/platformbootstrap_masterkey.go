// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package controller

import (
	"context"
	"crypto/rand"
	"fmt"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/platform/api/v1alpha1"
)

const (
	masterKeyDefaultNamespace = "gibson"
	masterKeyDefaultKey       = "master-key"
	masterKeyBytes            = 32
)

// reconcileMasterKey ensures the cluster-wide master-key Secret exists.
// Generates a 32-byte random key the first time; never overwrites an
// existing value, so chart upgrades and operator restarts are
// non-destructive. Master-key is structural infrastructure (ADR-0003 one-
// code-path) and the spec is CRD-required; no `MasterKeyDisabled` skip path
// exists.
//
// Behavior:
//   - Secret missing        → create with generated key
//   - Secret exists, key missing → patch in generated key
//   - Secret exists, key present, non-empty → no-op
func (r *PlatformBootstrapReconciler) reconcileMasterKey(ctx context.Context, pb *gibsonv1alpha1.PlatformBootstrap, logger logr.Logger) (ctrl.Result, error) {
	ns := pb.Spec.MasterKey.Namespace
	if ns == "" {
		ns = masterKeyDefaultNamespace
	}
	key := pb.Spec.MasterKey.Key
	if key == "" {
		key = masterKeyDefaultKey
	}

	var sec corev1.Secret
	err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: pb.Spec.MasterKey.SecretName}, &sec)
	switch {
	case apierrors.IsNotFound(err):
		generated, gerr := generateMasterKey()
		if gerr != nil {
			setBootstrapCond(pb, gibsonv1alpha1.ConditionMasterKeyReady, metav1.ConditionFalse,
				"GenerateFailed", gerr.Error())
			return ctrl.Result{}, gerr
		}
		newSec := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      pb.Spec.MasterKey.SecretName,
				Namespace: ns,
				Labels: map[string]string{
					"app.kubernetes.io/managed-by": "platform-operator",
					"gibson.zeroroot.ai/component": "master-key",
				},
			},
			Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{key: generated},
		}
		if err := r.Create(ctx, newSec); err != nil {
			setBootstrapCond(pb, gibsonv1alpha1.ConditionMasterKeyReady, metav1.ConditionFalse,
				"CreateFailed", err.Error())
			return ctrl.Result{}, err
		}
		logger.Info("master-key Secret generated", "namespace", ns, "name", pb.Spec.MasterKey.SecretName)
		setBootstrapCond(pb, gibsonv1alpha1.ConditionMasterKeyReady, metav1.ConditionTrue,
			"Generated", fmt.Sprintf("created Secret %s/%s", ns, pb.Spec.MasterKey.SecretName))
		return ctrl.Result{}, nil
	case err != nil:
		setBootstrapCond(pb, gibsonv1alpha1.ConditionMasterKeyReady, metav1.ConditionFalse,
			"LookupFailed", err.Error())
		return ctrl.Result{}, err
	}

	// Secret exists. Check the key.
	if v, ok := sec.Data[key]; ok && len(v) > 0 {
		setBootstrapCond(pb, gibsonv1alpha1.ConditionMasterKeyReady, metav1.ConditionTrue,
			"Exists", fmt.Sprintf("Secret %s/%s has key %q (%d bytes)", ns, pb.Spec.MasterKey.SecretName, key, len(v)))
		return ctrl.Result{}, nil
	}
	// Secret exists but our key is missing/empty — patch.
	generated, gerr := generateMasterKey()
	if gerr != nil {
		setBootstrapCond(pb, gibsonv1alpha1.ConditionMasterKeyReady, metav1.ConditionFalse,
			"GenerateFailed", gerr.Error())
		return ctrl.Result{}, gerr
	}
	patch := client.MergeFrom(sec.DeepCopy())
	if sec.Data == nil {
		sec.Data = map[string][]byte{}
	}
	sec.Data[key] = generated
	if err := r.Patch(ctx, &sec, patch); err != nil {
		setBootstrapCond(pb, gibsonv1alpha1.ConditionMasterKeyReady, metav1.ConditionFalse,
			"PatchFailed", err.Error())
		return ctrl.Result{}, err
	}
	logger.Info("master-key Secret key materialised", "namespace", ns, "name", pb.Spec.MasterKey.SecretName, "key", key)
	setBootstrapCond(pb, gibsonv1alpha1.ConditionMasterKeyReady, metav1.ConditionTrue,
		"KeyMaterialised", fmt.Sprintf("patched Secret %s/%s with key %q", ns, pb.Spec.MasterKey.SecretName, key))
	return ctrl.Result{}, nil
}

// generateMasterKey returns masterKeyBytes (32) raw random bytes.
// The daemon's key provider verifies len(data) == 32 — hex-encoded
// (64 chars) or base32 (52 chars) representations are rejected as
// "invalid key size". Kubernetes Secret.Data is []byte at rest, so
// the bytes survive round-tripping intact.
func generateMasterKey() ([]byte, error) {
	b := make([]byte, masterKeyBytes)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("rand.Read: %w", err)
	}
	return b, nil
}
