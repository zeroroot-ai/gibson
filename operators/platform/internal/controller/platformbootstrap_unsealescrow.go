// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package controller implements the PlatformBootstrap and OIDCClient
// reconcilers for the gibson platform-operator.
package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/platform/api/v1alpha1"
)

const (
	unsealEscrowDefaultSecretKey = "unsealKey"
	unsealEscrowDefaultNamespace = "gibson"
	// unsealEscrowFileMode is owner-read/write only. The escrowed key unseals
	// the store that holds every tenant's KEK derivation root.
	unsealEscrowFileMode os.FileMode = 0o600
)

// fingerprint returns a SHA-256 hex digest. The digest is what goes in the
// condition message and the logs; the key itself never does.
func fingerprint(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])[:16]
}

// reconcileUnsealEscrow copies the minted OpenBao unseal key to the declared
// destination and reports ConditionUnsealKeyEscrowed.
//
// The whole design is in one sentence: escrow flips True on a VERIFIED WRITE,
// never on a claim. The write is read back and compared before the condition
// moves, so "escrowed" means the bytes are provably at the destination and not
// that something once returned success.
//
// Behaviour:
//   - destination unset            → False/EscrowNotConfigured, Ready gated
//   - destination managedExternally→ True/ManagedExternally (declared, not verified)
//   - unseal Secret absent         → False/UnsealKeyNotMinted, requeue
//   - file absent                  → write, read back, compare → True
//   - file present, same key       → no-op → True
//   - file present, DIFFERENT key  → False/EscrowConflict, and NOTHING is
//     overwritten. A destination holding another instance's key is the one
//     case where clobbering destroys the only copy of a live key.
func (r *PlatformBootstrapReconciler) reconcileUnsealEscrow(ctx context.Context, pb *gibsonv1alpha1.PlatformBootstrap, logger logr.Logger) (ctrl.Result, error) {
	spec := pb.Spec.UnsealEscrow

	switch spec.Destination {
	case "":
		setBootstrapCond(pb, gibsonv1alpha1.ConditionUnsealKeyEscrowed, metav1.ConditionFalse,
			"EscrowNotConfigured",
			"no escrow destination declared: set spec.unsealEscrow.destination "+
				"(volume|managedExternally). The unseal key currently exists only in "+
				"this cluster, so losing the cluster makes the OpenBao volume "+
				"unreadable even from a good backup (deploy#1629).")
		return ctrl.Result{}, nil

	case gibsonv1alpha1.UnsealEscrowManagedExternally:
		setBootstrapCond(pb, gibsonv1alpha1.ConditionUnsealKeyEscrowed, metav1.ConditionTrue,
			"ManagedExternally",
			"escrow is handled outside this operator (the kms seal source writes the "+
				"recovery key to Secrets Manager and verifies it before deleting the "+
				"in-cluster copy). Declared, not verified here.")
		return ctrl.Result{}, nil

	case gibsonv1alpha1.UnsealEscrowVolume:
		// handled below
	default:
		setBootstrapCond(pb, gibsonv1alpha1.ConditionUnsealKeyEscrowed, metav1.ConditionFalse,
			"EscrowDestinationInvalid",
			fmt.Sprintf("unknown spec.unsealEscrow.destination %q", spec.Destination))
		return ctrl.Result{}, nil
	}

	if spec.Volume == nil || spec.Volume.Path == "" {
		setBootstrapCond(pb, gibsonv1alpha1.ConditionUnsealKeyEscrowed, metav1.ConditionFalse,
			"EscrowPathMissing",
			"spec.unsealEscrow.destination=volume requires spec.unsealEscrow.volume.path")
		return ctrl.Result{}, nil
	}

	var ref gibsonv1alpha1.SecretKeyRef
	if spec.SourceSecret != nil {
		ref = *spec.SourceSecret
	}
	if ref.Key == "" {
		ref.Key = unsealEscrowDefaultSecretKey
	}
	if ref.Namespace == "" {
		ref.Namespace = unsealEscrowDefaultNamespace
	}
	key, found, err := r.readSecretKey(ctx, unsealEscrowDefaultNamespace, ref)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("read unseal key for escrow: %w", err)
	}
	if !found || key == "" {
		// OpenBao has not bootstrapped yet. Not an error, and not Ready:
		// there is genuinely nothing to escrow so long as no key exists.
		setBootstrapCond(pb, gibsonv1alpha1.ConditionUnsealKeyEscrowed, metav1.ConditionFalse,
			"UnsealKeyNotMinted",
			fmt.Sprintf("Secret %s/%s key %q holds no unseal key yet — waiting for "+
				"openbao-auto-init to initialise the store", ref.Namespace, ref.Name, ref.Key))
		return ctrl.Result{RequeueAfter: 15 * time.Second}, nil
	}

	fp := fingerprint(key)
	path := spec.Volume.Path

	existing, readErr := os.ReadFile(path) //nolint:gosec // operator-declared path
	switch {
	case readErr == nil:
		if string(existing) == key {
			setBootstrapCond(pb, gibsonv1alpha1.ConditionUnsealKeyEscrowed, metav1.ConditionTrue,
				"Escrowed",
				fmt.Sprintf("unseal key present at %s (sha256:%s)", path, fp))
			return ctrl.Result{}, nil
		}
		// A different key is already there. Do NOT overwrite: it may be the
		// only copy of a live instance's key, and this reconcile cannot tell
		// the difference between a stale file and someone else's store.
		logger.Error(nil, "escrow destination holds a different key",
			"path", path, "want", fp, "found", fingerprint(string(existing)))
		setBootstrapCond(pb, gibsonv1alpha1.ConditionUnsealKeyEscrowed, metav1.ConditionFalse,
			"EscrowConflict",
			fmt.Sprintf("%s already holds a DIFFERENT key (sha256:%s, want sha256:%s). "+
				"Refusing to overwrite: that file may be the only copy of another "+
				"instance's unseal key. Move it aside deliberately, then reconcile.",
				path, fingerprint(string(existing)), fp))
		return ctrl.Result{}, nil

	case os.IsNotExist(readErr):
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			setBootstrapCond(pb, gibsonv1alpha1.ConditionUnsealKeyEscrowed, metav1.ConditionFalse,
				"EscrowWriteFailed", fmt.Sprintf("create %s: %v", filepath.Dir(path), err))
			return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
		}
		if err := os.WriteFile(path, []byte(key), unsealEscrowFileMode); err != nil {
			setBootstrapCond(pb, gibsonv1alpha1.ConditionUnsealKeyEscrowed, metav1.ConditionFalse,
				"EscrowWriteFailed", fmt.Sprintf("write %s: %v", path, err))
			return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
		}
		// READ BACK. A write that returned nil proves the syscall succeeded,
		// not that the bytes are retrievable — which is the only property
		// worth gating Ready on.
		back, err := os.ReadFile(path) //nolint:gosec // operator-declared path
		if err != nil || string(back) != key {
			setBootstrapCond(pb, gibsonv1alpha1.ConditionUnsealKeyEscrowed, metav1.ConditionFalse,
				"EscrowVerifyFailed",
				fmt.Sprintf("wrote %s but could not read the same bytes back", path))
			// nilerr: returning the error would bubble it out of Reconcile and
			// bury the reason in controller logs. The whole point of this step
			// is that a failed escrow is VISIBLE on the CR and gates Ready, so
			// it is reported as a condition and retried instead.
			return ctrl.Result{RequeueAfter: 30 * time.Second}, nil //nolint:nilerr // surfaced as a condition, not an error
		}
		logger.Info("escrowed unseal key", "path", path, "sha256", fp)
		setBootstrapCond(pb, gibsonv1alpha1.ConditionUnsealKeyEscrowed, metav1.ConditionTrue,
			"Escrowed",
			fmt.Sprintf("unseal key written and verified at %s (sha256:%s)", path, fp))
		return ctrl.Result{}, nil

	default:
		setBootstrapCond(pb, gibsonv1alpha1.ConditionUnsealKeyEscrowed, metav1.ConditionFalse,
			"EscrowUnreadable", fmt.Sprintf("stat %s: %v", path, readErr))
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}
}
