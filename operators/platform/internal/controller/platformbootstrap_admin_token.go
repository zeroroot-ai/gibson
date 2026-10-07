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
// ExternalSecret iam-admin-pat reads that entry. The login-client token
// follows the same pattern at secret/data/gibson-zitadel-login-client-pat,
// which the ExternalSecret login-client reads.
const (
	adminTokenKVKey       = "gibson-zitadel-iam-admin-pat"
	loginClientTokenKVKey = "gibson-zitadel-login-client-pat"
	// loginClientUser is the machine user of zitadel-login. The Zitadel setup
	// job creates it from FirstInstance.Org.LoginClient.
	loginClientUser    = "login-client"
	adminTokenProperty = "pat"
	adminUserProperty  = "userId"

	// The rotation fields of a token entry (ADR-0171). tokenIDProperty is the
	// id Zitadel lists the token under, mintedAtProperty the RFC 3339 time of
	// the mint, and retireAfterProperty the time after which each other token
	// of the user is removed.
	tokenIDProperty     = "patId"
	mintedAtProperty    = "mintedAt"
	retireAfterProperty = "retireOthersAfter"

	// adminMachineUser is the name of the IAM_OWNER machine user. It is the
	// name the Zitadel setup job used, so an install from before this step
	// keeps its user.
	adminMachineUser = "iam-admin"

	// tokenRotateAfter is the age at which a token gets a successor. The
	// token itself lives tokenLifetime, so a missed rotation does not end it.
	tokenRotateAfter = 30 * 24 * time.Hour
	tokenLifetime    = 90 * 24 * time.Hour

	// tokenRetireGrace is the time between the mint of a successor and the
	// removal of the old token. Each consumer reads the new token through
	// ESO (60s refresh) within it: this operator on its next pass, and
	// zitadel-login after its Reloader restart.
	tokenRetireGrace = 10 * time.Minute
)

// reconcileAdminToken makes sure OpenBao holds a valid Zitadel admin token,
// and rotates it (ADR-0171, row zitadel-bringup-tokens).
//
//   - First start: the entry does not exist. The step mints a token with the
//     System API key and writes it.
//   - Restore: the restored OpenBao holds the entry, and the token is valid.
//     The step mints nothing.
//   - Replace: the entry has no token, or Zitadel refuses it. The step mints a
//     new token and writes it as a new version of the entry.
//   - Rotate: the token is older than tokenRotateAfter, or the entry has no
//     mint time. The step mints a successor while the old token still works.
//   - Retire: tokenRetireGrace after a mint, the step removes each other
//     token of the user, so the old token is refused.
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
	res := r.rotateToken(ctx, vc, tokenRotation{
		kvKey: adminTokenKVKey,
		valid: sys.AdminTokenValid,
		mint: func(ctx context.Context, expires time.Time) (userID string, tok zitadel.PAT, err error) {
			return sys.MintAdminToken(ctx, adminMachineUser, expires)
		},
		retire: sys.RemoveOtherTokens,
	}, logger.WithValues("token", adminTokenKVKey))
	if res.err != "" {
		if res.permanent {
			return fail(metav1.ConditionFalse, res.reason,
				fmt.Sprintf("Zitadel refused the mint; the system user needs the System roles SYSTEM_OWNER and IAM_OWNER: %s", res.err))
		}
		return fail(metav1.ConditionUnknown, res.reason, res.err)
	}
	setBootstrapCond(pb, gibsonv1alpha1.ConditionAdminTokenReady, metav1.ConditionTrue, res.reason, res.message)
	return ctrl.Result{}, nil
}

// tokenRotation names one token entry of OpenBao and the Zitadel calls that
// check, mint and retire its tokens.
type tokenRotation struct {
	kvKey  string
	valid  func(ctx context.Context, pat string) (bool, error)
	mint   func(ctx context.Context, expires time.Time) (userID string, tok zitadel.PAT, err error)
	retire func(ctx context.Context, userID, keepID string) (int, error)
}

// rotationResult is the outcome of one pass of rotateToken. err is empty on
// success.
type rotationResult struct {
	reason, message, err string
	permanent            bool
}

// rotateToken keeps the entry rot.kvKey valid and rotates it. It writes only
// OpenBao and Zitadel.
func (r *PlatformBootstrapReconciler) rotateToken(
	ctx context.Context, vc vault.Client, rot tokenRotation, logger logr.Logger,
) rotationResult {
	now := time.Now()
	if r.Now != nil {
		now = r.Now()
	}
	stored, err := vc.ReadKV(ctx, rot.kvKey)
	switch {
	case errors.Is(err, vault.ErrNotFound):
		stored = nil
	case err != nil:
		return rotationResult{reason: "VaultReadFailed", err: err.Error()}
	}

	reason := "TokenMinted"
	if pat := stored[adminTokenProperty]; pat != "" {
		valid, verr := rot.valid(ctx, pat)
		if verr != nil {
			return rotationResult{reason: "ZitadelUnreachable", err: verr.Error()}
		}
		minted, perr := time.Parse(time.RFC3339, stored[mintedAtProperty])
		switch {
		case !valid:
			logger.Info("the stored Zitadel token is not valid; minting a new one")
		case perr != nil || now.Sub(minted) >= tokenRotateAfter:
			logger.Info("the stored Zitadel token is due for rotation; minting its successor")
			reason = "TokenRotated"
		default:
			return r.retireOldTokens(ctx, vc, rot, stored, now, logger)
		}
	}

	userID, tok, err := rot.mint(ctx, now.Add(tokenLifetime))
	if err != nil {
		if zitadel.IsPermanent(err) {
			return rotationResult{reason: "MintRefused", err: err.Error(), permanent: true}
		}
		return rotationResult{reason: "MintFailed", err: err.Error()}
	}
	if err := vc.WriteKV(ctx, rot.kvKey, map[string]string{
		adminTokenProperty:  tok.Token,
		adminUserProperty:   userID,
		tokenIDProperty:     tok.ID,
		mintedAtProperty:    now.UTC().Format(time.RFC3339),
		retireAfterProperty: now.Add(tokenRetireGrace).UTC().Format(time.RFC3339),
	}); err != nil {
		return rotationResult{reason: "VaultWriteFailed", err: err.Error()}
	}
	logger.Info("minted a Zitadel token and stored it in OpenBao", "user_id", userID, "token_id", tok.ID)
	return rotationResult{reason: reason, message: "minted a Zitadel token and stored it in OpenBao"}
}

// retireOldTokens removes each other token of the user once the grace of the
// last mint is over, and then clears the retire time.
func (r *PlatformBootstrapReconciler) retireOldTokens(
	ctx context.Context, vc vault.Client, rot tokenRotation, stored map[string]string, now time.Time, logger logr.Logger,
) rotationResult {
	ok := rotationResult{reason: "TokenValid", message: "OpenBao holds a valid Zitadel token"}
	after, err := time.Parse(time.RFC3339, stored[retireAfterProperty])
	if err != nil || now.Before(after) {
		return ok
	}
	userID, keepID := stored[adminUserProperty], stored[tokenIDProperty]
	if userID == "" || keepID == "" {
		return ok
	}
	n, err := rot.retire(ctx, userID, keepID)
	if err != nil {
		return rotationResult{reason: "RetireFailed", err: err.Error()}
	}
	next := make(map[string]string, len(stored))
	for k, v := range stored {
		if k != retireAfterProperty {
			next[k] = v
		}
	}
	if err := vc.WriteKV(ctx, rot.kvKey, next); err != nil {
		return rotationResult{reason: "VaultWriteFailed", err: err.Error()}
	}
	logger.Info("removed the old Zitadel tokens of the user", "user_id", userID, "removed", n)
	return ok
}

// reconcileLoginClientToken rotates the personal access token of the
// login-client machine user, which zitadel-login reads (ADR-0171). The
// Zitadel setup job mints the first token, and the iam-admin-pat-escrow job
// puts it in OpenBao. This step never stops the reconcile: a failure sets
// the condition and the next pass tries again.
func (r *PlatformBootstrapReconciler) reconcileLoginClientToken(
	ctx context.Context, pb *gibsonv1alpha1.PlatformBootstrap, logger logr.Logger,
) {
	set := func(status metav1.ConditionStatus, reason, msg string) {
		setBootstrapCond(pb, gibsonv1alpha1.ConditionLoginClientTokenReady, status, reason, msg)
	}
	if pb.Spec.Zitadel.SystemClient == nil {
		set(metav1.ConditionFalse, "SystemClientMissing", "spec.zitadel.systemClient is not set")
		return
	}
	vc, waiting, err := r.vaultClient(ctx, pb)
	if err != nil || waiting != "" {
		if waiting == "" {
			waiting = err.Error()
		}
		set(metav1.ConditionFalse, "VaultUnavailable", waiting)
		return
	}
	sys, err := r.systemClient(pb)
	if err != nil {
		set(metav1.ConditionFalse, "SystemClientInitFailed", err.Error())
		return
	}
	stored, err := vc.ReadKV(ctx, loginClientTokenKVKey)
	if errors.Is(err, vault.ErrNotFound) || (err == nil && stored[adminTokenProperty] == "") {
		// The escrow job has not stored the first token yet. The setup job
		// mints it, so this step mints nothing until then.
		set(metav1.ConditionFalse, "WaitingForEscrow", "OpenBao holds no login-client token yet")
		return
	}
	res := r.rotateToken(ctx, vc, tokenRotation{
		kvKey: loginClientTokenKVKey,
		valid: sys.TokenValid,
		mint: func(ctx context.Context, expires time.Time) (userID string, tok zitadel.PAT, err error) {
			return sys.MintUserToken(ctx, loginClientUser, expires)
		},
		retire: sys.RemoveOtherTokens,
	}, logger.WithValues("token", loginClientTokenKVKey))
	if res.err != "" {
		set(metav1.ConditionUnknown, res.reason, res.err)
		return
	}
	set(metav1.ConditionTrue, res.reason, res.message)
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
