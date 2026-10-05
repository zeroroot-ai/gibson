// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/platform/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/platform/internal/clients/vault"
	"github.com/zeroroot-ai/gibson/operators/platform/internal/clients/zitadel"
)

// The Zitadel admin token has one producer, this operator, and one writer of
// its Kubernetes Secret, the ExternalSecret of the chart (ADR-0014,
// gibson#794). The operator keeps the token in OpenBao at the KV v2 entry
// secret/data/gibson-zitadel-iam-admin-pat, property "pat". The
// ExternalSecret iam-admin-pat reads that entry.
const (
	adminTokenKVKey    = "gibson-zitadel-iam-admin-pat"
	adminTokenProperty = "pat"
	adminUserProperty  = "userId"

	// adminMachineUser is the name of the IAM_OWNER machine user. It is the
	// name the Zitadel setup job used, so an install from before this step
	// keeps its user.
	adminMachineUser = "iam-admin"

	// adminTokenLifetime is the life of a minted token. The step mints a new
	// one when the stored token is no longer valid.
	adminTokenLifetime = 365 * 24 * time.Hour
)

// reconcileAdminToken makes sure OpenBao holds a valid Zitadel admin token.
//
//   - First start: the entry does not exist. The step mints a token with the
//     System API key and writes it.
//   - Restore: the restored OpenBao holds the entry, and the token is valid.
//     The step mints nothing.
//   - Replace: the entry has no token, or Zitadel refuses it. The step mints a
//     new token and writes it as a new version of the entry.
//
// The step writes no Kubernetes Secret.
func (r *PlatformBootstrapReconciler) reconcileAdminToken(
	ctx context.Context, pb *gibsonv1alpha1.PlatformBootstrap, logger logr.Logger,
) (ctrl.Result, error) {
	fail := func(status metav1.ConditionStatus, reason, msg string) (ctrl.Result, error) {
		setBootstrapCond(pb, gibsonv1alpha1.ConditionAdminTokenReady, status, reason, msg)
		return ctrl.Result{RequeueAfter: requeueMedium}, nil
	}
	if pb.Spec.Zitadel.SystemClient == nil {
		return fail(metav1.ConditionFalse, "SystemClientMissing",
			"spec.zitadel.systemClient is not set, so the admin token cannot be minted")
	}
	vc, waiting, err := r.vaultClient(ctx, pb)
	if err != nil || waiting != "" {
		if waiting == "" {
			waiting = err.Error()
		}
		return fail(metav1.ConditionFalse, "VaultUnavailable", waiting)
	}
	sys, err := r.systemClient(pb)
	if err != nil {
		return fail(metav1.ConditionFalse, "SystemClientInitFailed", err.Error())
	}

	stored, err := vc.ReadKV(ctx, adminTokenKVKey)
	switch {
	case errors.Is(err, vault.ErrNotFound):
		stored = nil
	case err != nil:
		return fail(metav1.ConditionUnknown, "VaultReadFailed", err.Error())
	}
	if pat := stored[adminTokenProperty]; pat != "" {
		valid, verr := sys.AdminTokenValid(ctx, pat)
		if verr != nil {
			return fail(metav1.ConditionUnknown, "ZitadelUnreachable", verr.Error())
		}
		if valid {
			setBootstrapCond(pb, gibsonv1alpha1.ConditionAdminTokenReady, metav1.ConditionTrue,
				"TokenValid", "OpenBao holds a valid Zitadel admin token")
			return ctrl.Result{}, nil
		}
		logger.Info("the stored Zitadel admin token is not valid; minting a new one")
	}

	now := time.Now()
	if r.Now != nil {
		now = r.Now()
	}
	userID, pat, err := sys.MintAdminToken(ctx, adminMachineUser, now.Add(adminTokenLifetime))
	if err != nil {
		if zitadel.IsPermanent(err) {
			return fail(metav1.ConditionFalse, "MintRefused",
				fmt.Sprintf("Zitadel refused the mint; the system user needs the System roles SYSTEM_OWNER and IAM_OWNER: %v", err))
		}
		return fail(metav1.ConditionUnknown, "MintFailed", err.Error())
	}
	if err := vc.WriteKV(ctx, adminTokenKVKey, map[string]string{
		adminTokenProperty: pat,
		adminUserProperty:  userID,
	}); err != nil {
		return fail(metav1.ConditionUnknown, "VaultWriteFailed", err.Error())
	}
	logger.Info("minted the Zitadel admin token and stored it in OpenBao", "user_id", userID)
	setBootstrapCond(pb, gibsonv1alpha1.ConditionAdminTokenReady, metav1.ConditionTrue,
		"TokenMinted", "minted a Zitadel admin token and stored it in OpenBao")
	return ctrl.Result{}, nil
}

// vaultClient builds the OpenBao client of this pass. waiting is non-empty
// when the token is not there yet.
func (r *PlatformBootstrapReconciler) vaultClient(
	ctx context.Context, pb *gibsonv1alpha1.PlatformBootstrap,
) (vault.Client, string, error) {
	var tokenFn vault.TokenFunc
	if r.VaultToken != nil {
		tokenFn = func() (string, error) { return r.VaultToken.Token() }
	} else {
		token, ok, err := r.readSecretKey(ctx, defaultChildNamespace, pb.Spec.VaultTransit.TokenRef)
		if err != nil {
			return nil, "", err
		}
		if !ok {
			return nil, "vault admin token Secret not yet materialised", nil
		}
		tokenFn = func() (string, error) { return token, nil }
	}
	vc, err := r.VaultFactory(pb.Spec.VaultTransit.Address, tokenFn)
	if err != nil {
		return nil, "", fmt.Errorf("vault client: %w", err)
	}
	return vc, "", nil
}
