// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/platform/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/platform/internal/clients/zitadel"
)

// defaultSetupSecretKey is the Secret key the offline setup link is written
// under when spec.platformOwner.setupSecretRef.key is unset.
const defaultSetupSecretKey = "setup-link"

// platformOwnerGivenName / platformOwnerFamilyName are the Zitadel profile
// names stamped on the Platform owner's user record. They carry no meaning
// beyond satisfying AddHumanUser's required profile fields — the account is
// addressed by email, never by name.
const (
	platformOwnerGivenName  = "Platform"
	platformOwnerFamilyName = "Owner"
)

// reconcilePlatformOwner creates the ONE human Zitadel administrator this
// install has (ADR-0093 decision 6/8, hosted#201):
//
//  1. A Zitadel human user with NO password, in the platform's own org (the
//     org that owns the gibson project) — never a tenant org, so the
//     Platform owner belongs to no tenant.
//  2. IAM_OWNER, the one instance-administrator role a human ever holds.
//  3. The FGA relation platform_owner on system_tenant:_system.
//  4. A one-time setup link through Zitadel's own invite-code flow: emailed,
//     unless spec.platformOwner.offlineSetup is true, in which case the raw
//     code is turned into a link and written to spec.platformOwner.setupSecretRef
//     instead (never a password, ADR-0093 decision 8).
//
// Raising spec.platformOwner.setupGeneration past status.observedSetupGeneration
// clears every second factor on file and repeats step 4 (ADR-0093 decision
// 12 — the Platform owner's reset is a reviewed install-value change, never a
// live-cluster action).
//
// Every step is idempotent: a reconcile that finds the user, the IAM role,
// the FGA tuple and the current generation's link already in place does
// nothing. Runs after reconcileZitadelProject (org + admin token) and
// reconcileFGAModel (store + model ids) — see the call site in Reconcile.
func (r *PlatformBootstrapReconciler) reconcilePlatformOwner(
	ctx context.Context,
	pb *gibsonv1alpha1.PlatformBootstrap,
	logger logr.Logger,
) (ctrl.Result, error) {
	po := pb.Spec.PlatformOwner
	if po.Email == "" {
		setBootstrapCond(pb, gibsonv1alpha1.ConditionPlatformOwnerReady, metav1.ConditionTrue,
			"NotConfigured", "spec.platformOwner.email not set; skipping Platform owner provisioning")
		return ctrl.Result{}, nil
	}

	pat, ok, err := r.readSecretKey(ctx, defaultChildNamespace, pb.Spec.Zitadel.AdminTokenRef)
	if err != nil {
		return ctrl.Result{}, err
	}
	if !ok {
		setBootstrapCond(pb, gibsonv1alpha1.ConditionPlatformOwnerReady, metav1.ConditionFalse,
			"WaitingForAdminToken", "Zitadel admin token Secret not yet materialised")
		return ctrl.Result{RequeueAfter: requeueMedium}, nil
	}
	zc := r.ZitadelFactory(pb.Spec.Zitadel.Issuer, pat)

	projectID, err := zc.GetProjectIDByName(ctx, pb.Spec.Zitadel.Project.Name)
	if err != nil {
		setBootstrapCond(pb, gibsonv1alpha1.ConditionPlatformOwnerReady, metav1.ConditionUnknown,
			"WaitingForProject", fmt.Sprintf("GetProjectIDByName: %v", err))
		return ctrl.Result{RequeueAfter: requeueMedium}, nil
	}
	orgID, err := zc.GetOrgIDForProject(ctx, projectID)
	if err != nil {
		setBootstrapCond(pb, gibsonv1alpha1.ConditionPlatformOwnerReady, metav1.ConditionUnknown,
			"WaitingForProject", fmt.Sprintf("GetOrgIDForProject: %v", err))
		return ctrl.Result{RequeueAfter: requeueMedium}, nil
	}

	// Step 1: the human user, no password. userJustCreated distinguishes a
	// brand-new Platform owner (which always needs its first setup link) from
	// a reconcile that found one already there (which needs a link only on a
	// setupGeneration bump).
	userID := pb.Status.PlatformOwnerUserID
	userJustCreated := false
	if userID == "" {
		userID, err = zc.EnsureHumanUserNoPassword(ctx, orgID, po.Email, platformOwnerGivenName, platformOwnerFamilyName)
		if err != nil {
			if zitadel.IsPermanent(err) {
				setBootstrapCond(pb, gibsonv1alpha1.ConditionPlatformOwnerReady, metav1.ConditionFalse,
					"ZitadelPermanentError", fmt.Sprintf("EnsureHumanUserNoPassword: %v", err))
				return ctrl.Result{}, nil
			}
			setBootstrapCond(pb, gibsonv1alpha1.ConditionPlatformOwnerReady, metav1.ConditionUnknown,
				"ZitadelTransientError", fmt.Sprintf("EnsureHumanUserNoPassword: %v", err))
			return ctrl.Result{RequeueAfter: requeueMedium}, nil
		}
		pb.Status.PlatformOwnerUserID = userID
		userJustCreated = true
		logger.Info("Platform owner user created", "email", po.Email, "userID", userID)
	}

	// Step 2: IAM_OWNER — the one instance-administrator role a human ever
	// holds (ADR-0093 decision 6/7).
	if err := zc.AddIAMMember(ctx, userID, []string{"IAM_OWNER"}); err != nil {
		if zitadel.IsPermanent(err) {
			setBootstrapCond(pb, gibsonv1alpha1.ConditionPlatformOwnerReady, metav1.ConditionFalse,
				"ZitadelPermanentError", fmt.Sprintf("AddIAMMember: %v", err))
			return ctrl.Result{}, nil
		}
		setBootstrapCond(pb, gibsonv1alpha1.ConditionPlatformOwnerReady, metav1.ConditionUnknown,
			"ZitadelTransientError", fmt.Sprintf("AddIAMMember: %v", err))
		return ctrl.Result{RequeueAfter: requeueMedium}, nil
	}

	// Step 3: the FGA relation. Reuses the store the FGA-model step already
	// ensured (Step 4 of Reconcile) rather than re-deriving it independently,
	// so the two steps can never disagree on which store holds the tuple.
	if written, result, err := r.writePlatformOwnerFGATuple(ctx, pb, userID); !written {
		return result, err
	}

	// Step 4: the setup link. Sent on first creation, or again when
	// setupGeneration has been raised past what was last observed.
	if userJustCreated || pb.Status.ObservedSetupGeneration != po.SetupGeneration {
		sent, result, err := r.sendPlatformOwnerSetupLink(ctx, pb, zc, userID, orgID, userJustCreated, logger)
		if !sent {
			return result, err
		}
		pb.Status.ObservedSetupGeneration = po.SetupGeneration
	}

	setBootstrapCond(pb, gibsonv1alpha1.ConditionPlatformOwnerReady, metav1.ConditionTrue,
		"PlatformOwnerReady", fmt.Sprintf("Platform owner %s provisioned; setupGeneration=%d", po.Email, po.SetupGeneration))
	return ctrl.Result{}, nil
}

// sendPlatformOwnerSetupLink implements Step 4 of reconcilePlatformOwner: on
// a reset (not a first-time send) it clears every factor on file so the new
// link actually forces re-enrollment (ADR-0093 decision 12), then sends the
// link by mail or writes it to the offline Secret.
//
// sent reports whether the link was actually sent/written: false means the
// caller must return (result, err) immediately (a condition was already set
// on pb), whether that is a retryable requeue or a permanent failure — Go
// has no way to make ctrl.Result{}, nil mean two different things, so the
// caller cannot tell "done, keep going" from "stopped here" without this.
func (r *PlatformBootstrapReconciler) sendPlatformOwnerSetupLink(
	ctx context.Context,
	pb *gibsonv1alpha1.PlatformBootstrap,
	zc zitadel.Client,
	userID, orgID string,
	userJustCreated bool,
	logger logr.Logger,
) (sent bool, result ctrl.Result, err error) {
	po := pb.Spec.PlatformOwner

	if !userJustCreated {
		if err := zc.ClearHumanFactors(ctx, userID); err != nil {
			if zitadel.IsPermanent(err) {
				setBootstrapCond(pb, gibsonv1alpha1.ConditionPlatformOwnerReady, metav1.ConditionFalse,
					"ZitadelPermanentError", fmt.Sprintf("ClearHumanFactors: %v", err))
				return false, ctrl.Result{}, nil
			}
			setBootstrapCond(pb, gibsonv1alpha1.ConditionPlatformOwnerReady, metav1.ConditionUnknown,
				"ZitadelTransientError", fmt.Sprintf("ClearHumanFactors: %v", err))
			return false, ctrl.Result{RequeueAfter: requeueMedium}, nil
		}
	}

	urlTemplate := setupLinkURLTemplate(pb.Spec.Zitadel.Issuer)
	if !po.OfflineSetup {
		if _, err := zc.CreateSetupInviteCode(ctx, userID, urlTemplate, true); err != nil {
			if zitadel.IsPermanent(err) {
				setBootstrapCond(pb, gibsonv1alpha1.ConditionPlatformOwnerReady, metav1.ConditionFalse,
					"ZitadelPermanentError", fmt.Sprintf("CreateSetupInviteCode: %v", err))
				return false, ctrl.Result{}, nil
			}
			setBootstrapCond(pb, gibsonv1alpha1.ConditionPlatformOwnerReady, metav1.ConditionUnknown,
				"ZitadelTransientError", fmt.Sprintf("CreateSetupInviteCode: %v", err))
			return false, ctrl.Result{RequeueAfter: requeueMedium}, nil
		}
		logger.Info("Platform owner setup link emailed", "email", po.Email)
		return true, ctrl.Result{}, nil
	}

	code, err := zc.CreateSetupInviteCode(ctx, userID, urlTemplate, false)
	if err != nil {
		if zitadel.IsPermanent(err) {
			setBootstrapCond(pb, gibsonv1alpha1.ConditionPlatformOwnerReady, metav1.ConditionFalse,
				"ZitadelPermanentError", fmt.Sprintf("CreateSetupInviteCode: %v", err))
			return false, ctrl.Result{}, nil
		}
		setBootstrapCond(pb, gibsonv1alpha1.ConditionPlatformOwnerReady, metav1.ConditionUnknown,
			"ZitadelTransientError", fmt.Sprintf("CreateSetupInviteCode: %v", err))
		return false, ctrl.Result{RequeueAfter: requeueMedium}, nil
	}
	if po.SetupSecretRef == nil {
		setBootstrapCond(pb, gibsonv1alpha1.ConditionPlatformOwnerReady, metav1.ConditionFalse,
			"MissingSetupSecretRef", "offlineSetup is true but spec.platformOwner.setupSecretRef is unset")
		return false, ctrl.Result{}, nil
	}
	link := renderSetupLink(urlTemplate, userID, orgID, code)
	if err := r.writeOfflineSetupLink(ctx, *po.SetupSecretRef, link); err != nil {
		return false, ctrl.Result{}, err
	}
	logger.Info("Platform owner offline setup link written", "secret", po.SetupSecretRef.Name)
	return true, ctrl.Result{}, nil
}

// writePlatformOwnerFGATuple writes (user:<userID>, platform_owner,
// system_tenant:_system), reusing the store spec.fgaModel already ensured.
// The model id comes from the same Secret writeFGAStoreID persists it to
// ("model_id" alongside the store id), so this can never race ahead of a
// store that reconcileFGAModel has not written yet.
//
// written reports whether the tuple is now in place: false means the caller
// must return (result, err) immediately (a condition was already set on pb),
// the same "cannot use ctrl.Result{}, nil to mean two things" reason
// sendPlatformOwnerSetupLink documents.
func (r *PlatformBootstrapReconciler) writePlatformOwnerFGATuple(
	ctx context.Context,
	pb *gibsonv1alpha1.PlatformBootstrap,
	userID string,
) (written bool, result ctrl.Result, err error) {
	storeID, ok, err := r.readSecretKey(ctx, defaultChildNamespace, pb.Spec.FGAModel.StoreNameRef)
	if err != nil {
		return false, ctrl.Result{}, err
	}
	if !ok {
		setBootstrapCond(pb, gibsonv1alpha1.ConditionPlatformOwnerReady, metav1.ConditionFalse,
			"WaitingForFGAModel", "FGA store id not yet materialised")
		return false, ctrl.Result{RequeueAfter: requeueMedium}, nil
	}
	modelRef := pb.Spec.FGAModel.StoreNameRef
	modelRef.Key = "model_id"
	modelID, ok, err := r.readSecretKey(ctx, defaultChildNamespace, modelRef)
	if err != nil {
		return false, ctrl.Result{}, err
	}
	if !ok {
		setBootstrapCond(pb, gibsonv1alpha1.ConditionPlatformOwnerReady, metav1.ConditionFalse,
			"WaitingForFGAModel", "FGA model id not yet materialised")
		return false, ctrl.Result{RequeueAfter: requeueMedium}, nil
	}

	fgaCli, err := r.FGAFactory(pb.Spec.FGAModel.APIEndpoint)
	if err != nil {
		setBootstrapCond(pb, gibsonv1alpha1.ConditionPlatformOwnerReady, metav1.ConditionFalse,
			"FGAClientInit", err.Error())
		return false, ctrl.Result{}, nil
	}
	if err := fgaCli.WriteTuple(ctx, storeID, modelID, "user:"+userID, "platform_owner", "system_tenant:_system"); err != nil {
		setBootstrapCond(pb, gibsonv1alpha1.ConditionPlatformOwnerReady, metav1.ConditionUnknown,
			"FGATransientError", fmt.Sprintf("WriteTuple: %v", err))
		return false, ctrl.Result{RequeueAfter: requeueMedium}, nil
	}
	return true, ctrl.Result{}, nil
}

// writeOfflineSetupLink creates or updates the Secret spec.platformOwner.setupSecretRef
// names, under the given key (default "setup-link"), readable only by
// whoever the chart's RBAC grants access to that Secret — cluster
// administrators, per ADR-0093 decision 8. Overwrites any previous link:
// CreateSetupInviteCode already invalidated it on the Zitadel side, so
// leaving the old value in the Secret would be a link that looks live but
// no longer works.
func (r *PlatformBootstrapReconciler) writeOfflineSetupLink(ctx context.Context, ref gibsonv1alpha1.SecretKeyRef, link string) error {
	ns := secretNamespace(ref, defaultChildNamespace)
	key := ref.Key
	if key == "" {
		key = defaultSetupSecretKey
	}
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: ref.Name, Namespace: ns},
	}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, sec, func() error {
		if sec.Data == nil {
			sec.Data = map[string][]byte{}
		}
		sec.Data[key] = []byte(link)
		sec.Type = corev1.SecretTypeOpaque
		return nil
	})
	if err != nil {
		return fmt.Errorf("write Platform owner offline setup link secret: %w", err)
	}
	return nil
}

// setupLinkURLTemplate builds the Go-template URL Zitadel substitutes
// {{.UserID}}, {{.OrgID}} and {{.Code}} into (CreateInviteCode's urlTemplate
// field) — supplied explicitly rather than relying on Zitadel's own default
// invite path, so the emitted link is the same shape whether Zitadel emails
// it or the operator embeds it in the offline Secret.
func setupLinkURLTemplate(issuer string) string {
	return strings.TrimRight(issuer, "/") + "/ui/v2/login/invite?userID={{.UserID}}&code={{.Code}}&organization={{.OrgID}}"
}

// renderSetupLink substitutes the same three placeholders setupLinkURLTemplate
// declares, for the offline path where the operator builds the link itself
// instead of letting Zitadel substitute them server-side.
func renderSetupLink(urlTemplate, userID, orgID, code string) string {
	r := strings.NewReplacer("{{.UserID}}", userID, "{{.OrgID}}", orgID, "{{.Code}}", code)
	return r.Replace(urlTemplate)
}
