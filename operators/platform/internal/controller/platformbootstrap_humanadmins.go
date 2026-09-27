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

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/platform/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/platform/internal/clients/zitadel"
)

// defaultFirstInstanceAdminPrefix is the username prefix Zitadel's own
// setup step stamps on the first instance's default human administrator
// (upstream cmd/setup/steps.yaml, FirstInstance.Org.Human.UserName:
// "zitadel-admin", suffixed with the org's generated domain because
// UserLoginMustBeDomain defaults to false — e.g.
// "zitadel-admin@zitadel.<ExternalDomain>"). The gibson chart's
// zitadel.zitadel.configmapConfig never sets FirstInstance.Org.Human (only
// Org.Machine + Org.LoginClient — see helm/gibson/values.yaml), so this
// account is created by Zitadel itself, unconditionally, on every fresh
// install, with Zitadel's own documented default first-instance password.
//
// Confirmed against the upstream v4.18.0 source: cmd/setup/03.go's
// FirstInstance.Execute dereferences instanceSetup.Org.Human.Username and
// .Email.Address unconditionally before calling SetUpInstance, so there is
// no supported chart-side way to omit Org.Human from the setup config
// without either leaving this default account in place or crashing the
// setup Job outright — see hosted#189's handoff for the full trail. This
// reconcile step is therefore the one and only control.
const defaultFirstInstanceAdminPrefix = "zitadel-admin@"

// reconcileHumanAdminsScoped makes the Platform owner permanent as the ONLY
// human Zitadel instance administrator (ADR-0093 decision 6, hosted#189).
//
// Every reconcile, once the Platform owner is known (after Step 10,
// reconcilePlatformOwner), this step lists every instance member and, for
// every HUMAN member other than the Platform owner: revokes its IAM
// membership, and — specifically for Zitadel's own default first-instance
// human admin (identified by defaultFirstInstanceAdminPrefix, see above) —
// deletes the account outright rather than leaving a de-privileged user
// record behind.
//
// Machine members (the bootstrap iam-admin identity, the login client, the
// daemon, the tenant-operator) are untouched here; their role sets are the
// other ADR-0093 slices' concern (hosted#191/#199/#200) — touching them
// would risk revoking the very bootstrap identity this reconciler
// authenticates as.
//
// Runs every reconcile, not once: nothing re-creates the default admin on
// its own, but a human could be re-added to IAM_OWNER out of band (the
// Zitadel console, a script, a future regression), and this step converges
// that back to just the Platform owner on the very next reconcile. hosted#207
// tracks the render-guard half of this same invariant for OIDCClient/
// service-user roles; this is the live, in-cluster half for humans.
func (r *PlatformBootstrapReconciler) reconcileHumanAdminsScoped(
	ctx context.Context,
	pb *gibsonv1alpha1.PlatformBootstrap,
	logger logr.Logger,
) (ctrl.Result, error) {
	if pb.Spec.PlatformOwner.Email == "" {
		setBootstrapCond(pb, gibsonv1alpha1.ConditionHumanAdminsScoped, metav1.ConditionTrue,
			"NotConfigured", "spec.platformOwner.email not set; nothing to scope human Zitadel admins against")
		return ctrl.Result{}, nil
	}
	if pb.Status.PlatformOwnerUserID == "" {
		// Defensive: reconcilePlatformOwner (Step 10) runs immediately before
		// this step and only returns a zero Result once the Platform owner's
		// userID is persisted, so this branch should not be reachable in
		// practice. Refuse to touch any human Zitadel membership until the
		// Platform owner is known — proceeding here could remove every human
		// admin, including a Platform owner this step cannot yet identify.
		setBootstrapCond(pb, gibsonv1alpha1.ConditionHumanAdminsScoped, metav1.ConditionFalse,
			"WaitingForPlatformOwner", "status.platformOwnerUserID not yet set")
		return ctrl.Result{RequeueAfter: requeueMedium}, nil
	}

	pat, ok, err := r.readSecretKey(ctx, defaultChildNamespace, pb.Spec.Zitadel.AdminTokenRef)
	if err != nil {
		return ctrl.Result{}, err
	}
	if !ok {
		setBootstrapCond(pb, gibsonv1alpha1.ConditionHumanAdminsScoped, metav1.ConditionFalse,
			"WaitingForAdminToken", "Zitadel admin token Secret not yet materialised")
		return ctrl.Result{RequeueAfter: requeueMedium}, nil
	}
	zc := r.ZitadelFactory(pb.Spec.Zitadel.Issuer, pat)

	projectID, err := zc.GetProjectIDByName(ctx, pb.Spec.Zitadel.Project.Name)
	if err != nil {
		setBootstrapCond(pb, gibsonv1alpha1.ConditionHumanAdminsScoped, metav1.ConditionUnknown,
			"WaitingForProject", fmt.Sprintf("GetProjectIDByName: %v", err))
		return ctrl.Result{RequeueAfter: requeueMedium}, nil
	}
	orgID, err := zc.GetOrgIDForProject(ctx, projectID)
	if err != nil {
		setBootstrapCond(pb, gibsonv1alpha1.ConditionHumanAdminsScoped, metav1.ConditionUnknown,
			"WaitingForProject", fmt.Sprintf("GetOrgIDForProject: %v", err))
		return ctrl.Result{RequeueAfter: requeueMedium}, nil
	}

	members, err := zc.SearchIAMMembers(ctx)
	if err != nil {
		if zitadel.IsPermanent(err) {
			setBootstrapCond(pb, gibsonv1alpha1.ConditionHumanAdminsScoped, metav1.ConditionFalse,
				"ZitadelPermanentError", fmt.Sprintf("SearchIAMMembers: %v", err))
			return ctrl.Result{}, nil
		}
		setBootstrapCond(pb, gibsonv1alpha1.ConditionHumanAdminsScoped, metav1.ConditionUnknown,
			"ZitadelTransientError", fmt.Sprintf("SearchIAMMembers: %v", err))
		return ctrl.Result{RequeueAfter: requeueMedium}, nil
	}

	removed := 0
	for _, m := range members {
		if m.UserType != zitadel.ZitadelUserTypeHuman {
			continue // machine members are the other slices' concern.
		}
		if m.UserID == pb.Status.PlatformOwnerUserID {
			continue // keep the Platform owner.
		}
		keepGoing, result, err := r.removeHumanAdmin(ctx, pb, zc, m, orgID, logger)
		if !keepGoing {
			return result, err
		}
		removed++
	}

	setBootstrapCond(pb, gibsonv1alpha1.ConditionHumanAdminsScoped, metav1.ConditionTrue,
		"Scoped", fmt.Sprintf("the Platform owner is the only human Zitadel administrator; removed %d other human admin(s) this pass", removed))
	return ctrl.Result{}, nil
}

// removeHumanAdmin revokes m's IAM membership and, when m is identified as
// Zitadel's own default first-instance human admin, deletes the account
// outright.
//
// keepGoing reports whether the caller should keep processing the
// remaining members: false means a condition was already set on pb and the
// caller must return (result, err) immediately, whether that is a
// retryable requeue or a permanent failure — mirroring
// sendPlatformOwnerSetupLink's sent/result/err contract in
// platformbootstrap_platformowner.go, for the same reason: Go has no way to
// make ctrl.Result{}, nil mean two different things.
func (r *PlatformBootstrapReconciler) removeHumanAdmin(
	ctx context.Context,
	pb *gibsonv1alpha1.PlatformBootstrap,
	zc zitadel.Client,
	m zitadel.IAMMember,
	orgID string,
	logger logr.Logger,
) (keepGoing bool, result ctrl.Result, err error) {
	if rmErr := zc.RemoveIAMMember(ctx, m.UserID); rmErr != nil {
		if zitadel.IsPermanent(rmErr) {
			setBootstrapCond(pb, gibsonv1alpha1.ConditionHumanAdminsScoped, metav1.ConditionFalse,
				"ZitadelPermanentError", fmt.Sprintf("RemoveIAMMember user=%s: %v", m.UserID, rmErr))
			return false, ctrl.Result{}, nil
		}
		setBootstrapCond(pb, gibsonv1alpha1.ConditionHumanAdminsScoped, metav1.ConditionUnknown,
			"ZitadelTransientError", fmt.Sprintf("RemoveIAMMember user=%s: %v", m.UserID, rmErr))
		return false, ctrl.Result{RequeueAfter: requeueMedium}, nil
	}
	r.Recorder.Eventf(pb, corev1.EventTypeWarning, "HumanAdminRemoved",
		"revoked Zitadel instance-administrator membership from human user %s (%s); the Platform owner is the only human Zitadel administrator",
		m.UserID, m.PreferredLoginName)
	logger.Info("revoked human Zitadel instance-administrator membership",
		"userID", m.UserID, "preferredLoginName", m.PreferredLoginName)

	if !isDefaultFirstInstanceAdmin(m, orgID) {
		return true, ctrl.Result{}, nil
	}
	if delErr := zc.DeleteUser(ctx, m.UserID); delErr != nil {
		if zitadel.IsPermanent(delErr) {
			setBootstrapCond(pb, gibsonv1alpha1.ConditionHumanAdminsScoped, metav1.ConditionFalse,
				"ZitadelPermanentError", fmt.Sprintf("DeleteUser user=%s: %v", m.UserID, delErr))
			return false, ctrl.Result{}, nil
		}
		setBootstrapCond(pb, gibsonv1alpha1.ConditionHumanAdminsScoped, metav1.ConditionUnknown,
			"ZitadelTransientError", fmt.Sprintf("DeleteUser user=%s: %v", m.UserID, delErr))
		return false, ctrl.Result{RequeueAfter: requeueMedium}, nil
	}
	r.Recorder.Eventf(pb, corev1.EventTypeWarning, "DefaultAdminDeleted",
		"deleted Zitadel's default first-instance human administrator user %s (%s)",
		m.UserID, m.PreferredLoginName)
	logger.Info("deleted Zitadel's default first-instance human admin",
		"userID", m.UserID, "preferredLoginName", m.PreferredLoginName)
	return true, ctrl.Result{}, nil
}

// isDefaultFirstInstanceAdmin reports whether m is the human administrator
// Zitadel's own setup step creates on every fresh install (see
// defaultFirstInstanceAdminPrefix). Three signals, ALL required, so this
// can never match a real tenant user or the Platform owner: human, created
// in the first-instance org (the same org that owns the gibson project —
// orgID, resolved the same way reconcilePlatformOwner resolves it), and
// named with Zitadel's documented default username prefix.
func isDefaultFirstInstanceAdmin(m zitadel.IAMMember, orgID string) bool {
	return m.UserType == zitadel.ZitadelUserTypeHuman &&
		m.UserResourceOwner == orgID &&
		strings.HasPrefix(m.PreferredLoginName, defaultFirstInstanceAdminPrefix)
}
