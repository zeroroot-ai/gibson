// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"fmt"
	"slices"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/zeroroot-ai/gibson/operators/internal/audit"
	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/platform/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/platform/internal/clients/zitadel"
)

const (
	// loginClientUsername is the username Zitadel's own setup step gives
	// the login client machine user (upstream cmd/setup/steps.yaml,
	// FirstInstance.Org.LoginClient.Machine.Username). The chart never
	// overrides it. Zitadel keeps usernames unique inside an org, so the
	// username plus the first-instance org names exactly one account.
	loginClientUsername = "login-client"

	// loginClientRole is the one instance role the login client needs: it
	// lets the login app create sessions on behalf of a user.
	loginClientRole = "IAM_LOGIN_CLIENT"
)

// reconcileMachineAdminsScoped makes the declared service accounts the ONLY
// machine Zitadel instance administrators (ADR-0093 decision 6, hosted#207).
//
// Every reconcile, this step lists every instance member and, for every
// MACHINE member:
//
//   - a platform service account (platformServiceSubjects: iam-admin plus
//     every MACHINE_USER OIDCClient child) is left alone. The OIDCClient
//     controller already sets each child's roles to exactly its declared
//     spec.roles, and iam-admin is the identity this reconciler itself
//     authenticates as.
//   - Zitadel's own login client keeps its membership, with its roles set to
//     exactly IAM_LOGIN_CLIENT.
//   - any other machine member loses its IAM membership. The account itself
//     stays: a machine user without a membership administers nothing.
//
// This is what makes an UPGRADE converge, not only a fresh install. A
// machine user that an older chart declared (and a newer one dropped) keeps
// its Zitadel membership forever otherwise, because no OIDCClient CR is left
// to revoke it. Human members are reconcileHumanAdminsScoped's concern.
func (r *PlatformBootstrapReconciler) reconcileMachineAdminsScoped(
	ctx context.Context,
	pb *gibsonv1alpha1.PlatformBootstrap,
	logger logr.Logger,
) (ctrl.Result, error) {
	subjects, wait, err := r.platformServiceSubjects(ctx, pb)
	if err != nil {
		return ctrl.Result{}, err
	}
	if wait != nil {
		// Refuse to touch any machine membership until every declared
		// service account is known: an in-flight child is already a member,
		// and removing it here would fight the OIDCClient controller.
		setBootstrapCond(pb, gibsonv1alpha1.ConditionMachineAdminsScoped, metav1.ConditionFalse, wait.reason, wait.message)
		return ctrl.Result{RequeueAfter: wait.requeue}, nil
	}
	declared := make(map[string]bool, len(subjects))
	for _, userID := range subjects {
		declared[userID] = true
	}

	pat, ok, err := r.readSecretKey(ctx, defaultChildNamespace, pb.Spec.Zitadel.AdminTokenRef)
	if err != nil {
		return ctrl.Result{}, err
	}
	if !ok {
		setBootstrapCond(pb, gibsonv1alpha1.ConditionMachineAdminsScoped, metav1.ConditionFalse,
			"WaitingForAdminToken", "Zitadel admin token Secret not yet materialised")
		return ctrl.Result{RequeueAfter: requeueMedium}, nil
	}
	zc := r.ZitadelFactory(r.ZitadelURL, pat)

	projectID, err := zc.GetProjectIDByName(ctx, pb.Spec.Zitadel.Project.Name)
	if err != nil {
		setBootstrapCond(pb, gibsonv1alpha1.ConditionMachineAdminsScoped, metav1.ConditionUnknown,
			"WaitingForProject", fmt.Sprintf("GetProjectIDByName: %v", err))
		return ctrl.Result{RequeueAfter: requeueMedium}, nil
	}
	orgID, err := zc.GetOrgIDForProject(ctx, projectID)
	if err != nil {
		setBootstrapCond(pb, gibsonv1alpha1.ConditionMachineAdminsScoped, metav1.ConditionUnknown,
			"WaitingForProject", fmt.Sprintf("GetOrgIDForProject: %v", err))
		return ctrl.Result{RequeueAfter: requeueMedium}, nil
	}

	members, err := zc.SearchIAMMembers(ctx)
	if err != nil {
		return machineAdminsZitadelError(pb, "SearchIAMMembers", err), nil
	}

	removed := 0
	for _, m := range members {
		if m.UserType != zitadel.ZitadelUserTypeMachine || declared[m.UserID] {
			continue
		}
		if isLoginClient(m, orgID) {
			if slices.Equal(m.Roles, []string{loginClientRole}) {
				continue
			}
			resetFields := map[string]string{"change": "reset_login_client_roles", "user_id": m.UserID}
			if rerr := r.recordBefore(ctx, pb, pendingRecord(audit.ActionPlatformBootstrap, pb, "", "", resetFields)); rerr != nil {
				return ctrl.Result{}, rerr
			}
			if aerr := zc.AddIAMMember(ctx, m.UserID, []string{loginClientRole}); aerr != nil {
				failedChange(pb, resetFields, aerr)
				return machineAdminsZitadelError(pb, "AddIAMMember user="+m.UserID, aerr), nil
			}
			r.Recorder.Eventf(pb, corev1.EventTypeWarning, "LoginClientRolesReset",
				"reset the Zitadel login client %s roles from %v to [%s]", m.UserID, m.Roles, loginClientRole)
			logger.Info("reset the Zitadel login client roles", "userID", m.UserID, "was", m.Roles)
			continue
		}
		rmFields := map[string]string{"change": "remove_machine_iam_member", "user_id": m.UserID, "login_name": m.PreferredLoginName}
		if rerr := r.recordBefore(ctx, pb, pendingRecord(audit.ActionPlatformBootstrap, pb, "", "", rmFields)); rerr != nil {
			return ctrl.Result{}, rerr
		}
		if rerr := zc.RemoveIAMMember(ctx, m.UserID); rerr != nil {
			failedChange(pb, rmFields, rerr)
			return machineAdminsZitadelError(pb, "RemoveIAMMember user="+m.UserID, rerr), nil
		}
		r.Recorder.Eventf(pb, corev1.EventTypeWarning, "MachineAdminRemoved",
			"revoked Zitadel instance-administrator membership %v from undeclared machine user %s (%s)",
			m.Roles, m.UserID, m.PreferredLoginName)
		logger.Info("revoked undeclared machine Zitadel instance-administrator membership",
			"userID", m.UserID, "preferredLoginName", m.PreferredLoginName, "roles", m.Roles)
		removed++
	}

	setBootstrapCond(pb, gibsonv1alpha1.ConditionMachineAdminsScoped, metav1.ConditionTrue,
		"Scoped", fmt.Sprintf("only declared service accounts and the login client are machine Zitadel administrators; removed %d other machine admin(s) this pass", removed))
	return ctrl.Result{}, nil
}

// machineAdminsZitadelError sets the condition for a failed Zitadel call and
// returns the Result the reconcile must return: no requeue for a permanent
// error (the state needs a fix, not time), a medium requeue otherwise.
func machineAdminsZitadelError(pb *gibsonv1alpha1.PlatformBootstrap, op string, err error) ctrl.Result {
	if zitadel.IsPermanent(err) {
		setBootstrapCond(pb, gibsonv1alpha1.ConditionMachineAdminsScoped, metav1.ConditionFalse,
			"ZitadelPermanentError", fmt.Sprintf("%s: %v", op, err))
		return ctrl.Result{}
	}
	setBootstrapCond(pb, gibsonv1alpha1.ConditionMachineAdminsScoped, metav1.ConditionUnknown,
		"ZitadelTransientError", fmt.Sprintf("%s: %v", op, err))
	return ctrl.Result{RequeueAfter: requeueMedium}
}

// isLoginClient reports whether m is the login client Zitadel's setup step
// creates (see loginClientUsername). Both signals are required: a machine
// user, created in the first-instance org, with the fixed username.
func isLoginClient(m zitadel.IAMMember, orgID string) bool {
	return m.UserType == zitadel.ZitadelUserTypeMachine &&
		m.UserResourceOwner == orgID &&
		m.PreferredLoginName == loginClientUsername
}
