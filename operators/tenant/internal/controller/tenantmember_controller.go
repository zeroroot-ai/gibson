// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/zeroroot-ai/gibson/internal/platform/tenantrole"
	"github.com/zeroroot-ai/gibson/operators/internal/audit"
	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/fga"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/zitadel"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/saga"
)

// tenantRoleFromMemberRole maps a TenantMember's MemberRole to a tenantrole.Role
// (ADR-0093): owner to Owner, admin to Admin, member to Viewer.
func tenantRoleFromMemberRole(role gibsonv1alpha1.MemberRole) (tenantrole.Role, bool) {
	switch role {
	case gibsonv1alpha1.MemberRoleOwner:
		return tenantrole.Owner, true
	case gibsonv1alpha1.MemberRoleAdmin:
		return tenantrole.Admin, true
	case gibsonv1alpha1.MemberRoleMember:
		return tenantrole.Viewer, true
	default:
		return "", false
	}
}

// zitadelBackoff is the requeue delay when Zitadel is unavailable.
const zitadelBackoff = 30 * time.Second

// TenantMemberReconciler keeps the tenant role and the session tuples of a
// member whose account exists. It issues no invitation and sends no mail.
type TenantMemberReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder events.EventRecorder

	FGA     fga.Client
	Zitadel zitadel.Client
	// Roles is the tenant role Syncer (ADR-0093 decision 3): the one writer
	// of tenant-role tuples. syncZitadel calls Roles.Assign for a member
	// whose Zitadel user already exists; cleanup calls Roles.Revoke.
	Roles *tenantrole.Syncer

	// Audit writes the record of each identity, access or credential change
	// before the change (gibson#583). Required.
	Audit *audit.SagaEmitter
}

// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=tenantmembers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=tenantmembers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=tenantmembers/finalizers,verbs=update

func (r *TenantMemberReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx).WithValues("tenantmember", req.NamespacedName)

	var tm gibsonv1alpha1.TenantMember
	if err := r.Get(ctx, req.NamespacedName, &tm); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if r.Audit == nil {
		return ctrl.Result{}, fmt.Errorf("tenant member reconciler: %w", saga.ErrNoAudit)
	}

	if len(tm.OwnerReferences) == 0 {
		if ref, err := ResolveTenantOwnerRef(ctx, r.Client, tm.Namespace); err == nil && ref != nil {
			patch := client.MergeFrom(tm.DeepCopy())
			tm.OwnerReferences = []metav1.OwnerReference{*ref}
			if perr := r.Patch(ctx, &tm, patch); perr != nil {
				log.Info("ownerRef backfill failed; will retry", "err", perr)
				return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
			}
			log.Info("ownerRef backfilled", "tenant", ref.Name)
		}
	}

	// Deletion path: run finalizer cleanup.
	if !tm.DeletionTimestamp.IsZero() {
		if !controllerutil.ContainsFinalizer(&tm, gibsonv1alpha1.TenantMemberFinalizer) {
			return ctrl.Result{}, nil
		}
		if err := r.cleanup(ctx, &tm); err != nil {
			return ctrl.Result{RequeueAfter: 10 * time.Second}, err
		}
		controllerutil.RemoveFinalizer(&tm, gibsonv1alpha1.TenantMemberFinalizer)
		return ctrl.Result{}, r.Update(ctx, &tm)
	}

	// Ensure finalizer.
	if !controllerutil.ContainsFinalizer(&tm, gibsonv1alpha1.TenantMemberFinalizer) {
		controllerutil.AddFinalizer(&tm, gibsonv1alpha1.TenantMemberFinalizer)
		if err := r.Update(ctx, &tm); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// Propagate membership to Zitadel before phase-specific logic.
	if result, err := r.syncZitadel(ctx, &tm); err != nil || result.RequeueAfter > 0 {
		return result, err
	}

	// The operator issues no invitation and sends no mail. The daemon owns
	// every invitation and every onboarding email (gibson#626, gibson#520,
	// gibson#987): its AcceptInvitation creates the account, and each writer
	// of a TenantMember (ensureFoundingMember, bootstrap-tenant-owner) sets
	// spec.acceptedByUserId to an account that already exists. A member with
	// no account waits for the daemon.
	switch {
	case tm.Status.Phase == gibsonv1alpha1.TenantMemberPhaseActive:
		return ctrl.Result{}, nil
	case tm.Spec.AcceptedByUserID != "":
		return r.activateMember(ctx, &tm)
	}

	log.V(1).Info("no action", "phase", tm.Status.Phase)
	return ctrl.Result{}, nil
}

// activateMember makes a member whose account exists Active and seeds its
// session tuples.
func (r *TenantMemberReconciler) activateMember(ctx context.Context, tm *gibsonv1alpha1.TenantMember) (ctrl.Result, error) {
	ev := audit.ObjectEvent(audit.ActionMemberInvitationAccept, tm, map[string]string{"user_id": tm.Spec.AcceptedByUserID})
	if err := r.Audit.Change(ctx, ev, func() error {
		if r.FGA != nil {
			// The tenant role tuple is not written here. syncZitadel runs
			// before this branch on every reconcile. For a member with a
			// Zitadel user id and no grant, it called Roles.Assign, which
			// writes the Zitadel grant and copies it into FGA in one call
			// (ADR-0093). A member who already held a grant keeps it, and the
			// TenantRoleSyncReconciler copies it into FGA. The only writes
			// left here are the session tuples, which are not role tuples
			// and stay direct FGA writes.

			// Slice 2 of gibson#627: seed the active_session conditional tuple so
			// that ext-authz (Slice 3) can enforce the session-validity gate.
			// Written with revoked_at = epoch ("1970-01-01T00:00:00Z") meaning
			// "never revoked". RevokeUserSessions stamps revoked_at = now when a
			// session is explicitly revoked.
			//
			// Only human users (user: principal) receive an active_session tuple.
			// Machine principals (agent_principal / tool_principal / plugin_principal)
			// authenticate via mTLS + CG-JWTs and are not gated by active_session.
			if err := r.FGA.WriteConditional(ctx, fga.ConditionalTuple{
				User:          "user:" + tm.Spec.AcceptedByUserID,
				Relation:      "active_session",
				Object:        "tenant:" + tm.Spec.TenantRef.Name,
				ConditionName: "token_not_revoked",
				ConditionContext: map[string]any{
					"revoked_at": "1970-01-01T00:00:00Z",
				},
			}); err != nil {
				// Non-fatal: the role tuple was already written. Log loudly and
				// continue — the backfill Job will seed the active_session tuple
				// and enforcement (Slice 3) must not land before the backfill runs.
				log := logf.FromContext(ctx).WithValues("tenantmember", tm.Name)
				log.Error(err, "failed to write active_session FGA tuple (non-fatal; backfill will repair)",
					"user", tm.Spec.AcceptedByUserID,
					"tenant", tm.Spec.TenantRef.Name,
				)
			}

			// gibson#1244: also seed the USER-SCOPED active_session tuple
			// (user:<id>, active_session, user:<id>). This gates tenant-less
			// requests — the sign-in bootstrap window — which have no `type tenant`
			// object to check. Written alongside the per-tenant tuple by every
			// session writer and advanced by the same RevokeUserSessions path.
			// Idempotent: a member of several tenants resolves to one user-scoped
			// tuple regardless of how many per-tenant tuples exist.
			if err := r.FGA.WriteConditional(ctx, fga.ConditionalTuple{
				User:          "user:" + tm.Spec.AcceptedByUserID,
				Relation:      "active_session",
				Object:        "user:" + tm.Spec.AcceptedByUserID,
				ConditionName: "token_not_revoked",
				ConditionContext: map[string]any{
					"revoked_at": "1970-01-01T00:00:00Z",
				},
			}); err != nil {
				// Non-fatal, same rationale as the per-tenant tuple above.
				log := logf.FromContext(ctx).WithValues("tenantmember", tm.Name)
				log.Error(err, "failed to write user-scoped active_session FGA tuple (non-fatal; backfill will repair)",
					"user", tm.Spec.AcceptedByUserID,
				)
			}
		}

		return nil
	}); err != nil {
		return ctrl.Result{}, fmt.Errorf("record the invitation acceptance: %w", err)
	}

	tm.Status.Phase = gibsonv1alpha1.TenantMemberPhaseActive
	tm.Status.UserID = tm.Spec.AcceptedByUserID
	tm.Status.ObservedGeneration = tm.Generation
	return ctrl.Result{}, r.Status().Update(ctx, tm)
}

func (r *TenantMemberReconciler) cleanup(ctx context.Context, tm *gibsonv1alpha1.TenantMember) error {
	// Revoke the tenant role through the Syncer (ADR-0093): it deletes the
	// user's Zitadel grant, then copies the change into FGA in the same
	// call, so this replaces both the old FGA Delete and the Zitadel
	// RemoveMember call. Prefer the Zitadel-side id (what Assign granted
	// against); fall back to the FGA-side id for a member that never
	// resolved a Zitadel user.
	userID := tm.Status.ZitadelUserID
	if userID == "" {
		userID = tm.Status.UserID
	}
	if r.Roles != nil && userID != "" {
		orgID, deleting, err := r.tenantOrg(context.WithoutCancel(ctx), tm)
		if err != nil {
			// Zitadel unreachable — surface so the caller requeueues with backoff.
			return fmt.Errorf("cleanup: resolve zitadel org: %w", err)
		}
		// The org goes with the tenant, and every grant in it. A revoke on
		// a tenant that is leaving has nothing to keep consistent. No one
		// removes the Owner (ADR-0093): a revoke would drop the Zitadel
		// grant and then refuse the FGA copy, which leaves the two apart
		// and holds the finalizer for ever (gibson#1188). The Owner leaves
		// with the tenant, or through a transfer, never through this path.
		isOwner := tm.Spec.Role == gibsonv1alpha1.MemberRoleOwner
		if orgID != "" && !deleting && !isOwner {
			t := tenantrole.Tenant{ID: tm.Spec.TenantRef.Name, OrgID: orgID}
			ev := audit.ObjectEvent(audit.ActionMemberRoleRevoke, tm, map[string]string{"user_id": userID, "org_id": orgID})
			if err := r.Audit.Change(ctx, ev, func() error {
				if err := r.Roles.Revoke(tenantrole.WithCaller(ctx, "tenant-operator"), t, userID); err != nil {
					return fmt.Errorf("cleanup: revoke tenant role: %w", err)
				}
				return nil
			}); err != nil {
				return fmt.Errorf("record the member cleanup: %w", err)
			}
		}
	}
	return nil
}

// syncZitadel propagates the current TenantMember to Zitadel on create/update.
// It is idempotent: if status fields are already set the relevant branch is a
// no-op. Returns a non-zero RequeueAfter when Zitadel is temporarily
// unavailable.
func (r *TenantMemberReconciler) syncZitadel(ctx context.Context, tm *gibsonv1alpha1.TenantMember) (ctrl.Result, error) {
	if r.Zitadel == nil {
		return ctrl.Result{}, nil
	}

	// Already fully synced — nothing to do.
	if tm.Status.ZitadelMembershipID != "" {
		return ctrl.Result{}, nil
	}

	log := logf.FromContext(ctx).WithValues("tenantmember", tm.Name)

	// Self-signup (founding user): the Zitadel account was created by the
	// dashboard signup action before this TenantMember CR was applied.
	// Bootstrap ZitadelUserID from the spec so we call AddMember rather than
	// SendInvitation (which would create a duplicate account with a different
	// ID, causing the user's JWT to carry no org role).
	if tm.Spec.AcceptedByUserID != "" && tm.Status.ZitadelUserID == "" {
		tm.Status.ZitadelUserID = tm.Spec.AcceptedByUserID
		log.Info("syncZitadel: pre-accepted user; bootstrapping ZitadelUserID from spec.AcceptedByUserID", "userId", tm.Spec.AcceptedByUserID)
	}

	orgID, err := r.zitadelOrgID(ctx, tm)
	if err != nil {
		if errors.Is(err, clients.ErrUnreachable) {
			return ctrl.Result{RequeueAfter: zitadelBackoff}, nil
		}
		return ctrl.Result{}, err
	}
	if orgID == "" {
		// Parent Tenant not yet provisioned in Zitadel; requeue.
		return ctrl.Result{RequeueAfter: zitadelBackoff}, nil
	}

	// A member with no account waits for the daemon, which owns every
	// account and every invitation (gibson#626, gibson#987). The operator
	// never creates a user: on the first tenant it raced the first-admin
	// Job, which then found an Owner and sent no setup link (gibson#1188).
	if tm.Status.ZitadelUserID == "" {
		return ctrl.Result{}, nil
	}

	// The daemon writes every role change and every ownership transfer in
	// Zitadel, and it does not rewrite this record (ADR-0093). So the record
	// only fills a missing grant. A user who already holds one keeps it, and
	// the record's role, which can be out of date, assigns nothing. A record
	// from before gibson#1189 that names a transferred Owner then makes no
	// second Owner and does not retry (gibson#1190).
	held, err := r.holdsGrant(ctx, tm, orgID)
	if err != nil {
		return ctrl.Result{}, err
	}
	if held {
		log.Info("syncZitadel: the member already holds a tenant role; the record assigns nothing",
			"userId", tm.Status.ZitadelUserID)
		return r.recordMembership(ctx, tm, membershipKey(orgID, tm.Status.ZitadelUserID))
	}

	// The Zitadel user and the tenant role change under one audit record,
	// written first (gibson#583).
	var membershipID string
	ev := audit.ObjectEvent(audit.ActionMemberRoleAssign, tm, map[string]string{"role": string(tm.Spec.Role), "org_id": orgID})
	err = r.Audit.Change(ctx, ev, func() error {
		var aerr error
		membershipID, aerr = r.assignMembership(ctx, tm, orgID)
		return aerr
	})
	switch {
	case err == nil:
	case errors.Is(err, audit.ErrNotRecorded):
		return ctrl.Result{}, fmt.Errorf("record the Zitadel role sync: %w", err)
	case errors.Is(err, clients.ErrUnreachable):
		log.Info("syncZitadel: zitadel not ready; requeue", "err", err.Error())
		return ctrl.Result{RequeueAfter: zitadelBackoff}, nil
	case errors.Is(err, tenantrole.ErrOwnerConflict) && tm.Spec.Role == gibsonv1alpha1.MemberRoleOwner:
		// Only a founding owner gets a record, so a record that names Owner
		// on a tenant where another user holds Owner is stale: the daemon
		// moved ownership and then removed this user. The Syncer refused
		// before any write, so the record assigns nothing and stops
		// (gibson#1190).
		log.Info("syncZitadel: another user holds Owner; the stale Owner record assigns nothing",
			"userId", tm.Status.ZitadelUserID)
		return r.recordMembership(ctx, tm, membershipKey(orgID, tm.Status.ZitadelUserID))
	default:
		return ctrl.Result{}, fmt.Errorf("sync the Zitadel role of the member: %w", err)
	}
	return r.recordMembership(ctx, tm, membershipID)
}

// holdsGrant reports whether the member's Zitadel user already holds a role
// grant on the tenant. It reads Zitadel and writes nothing.
func (r *TenantMemberReconciler) holdsGrant(
	ctx context.Context, tm *gibsonv1alpha1.TenantMember, orgID string,
) (bool, error) {
	if r.Roles == nil {
		return false, errors.New("syncZitadel: role sync not configured")
	}
	t := tenantrole.Tenant{ID: tm.Spec.TenantRef.Name, OrgID: orgID}
	held, err := r.Roles.IsMember(ctx, t, tm.Status.ZitadelUserID)
	if err != nil {
		return false, fmt.Errorf("syncZitadel: read the grant of the member: %w", err)
	}
	return held, nil
}

// recordMembership writes the membership id to the status, which marks the
// record as synced.
func (r *TenantMemberReconciler) recordMembership(
	ctx context.Context, tm *gibsonv1alpha1.TenantMember, membershipID string,
) (ctrl.Result, error) {
	tm.Status.ZitadelMembershipID = membershipID
	if err := r.Status().Update(ctx, tm); err != nil {
		return ctrl.Result{}, fmt.Errorf("syncZitadel: status update: %w", err)
	}
	return ctrl.Result{}, nil
}

// membershipKey is the membership id "<org>/<user>".
func membershipKey(orgID, userID string) string {
	return orgID + "/" + userID
}

// assignMembership assigns the tenant role of a member that has a Zitadel
// user, through the Syncer (ADR-0093), which writes the Zitadel grant and
// copies it into FGA in the same call. It returns the membership id
// "<org>/<user>". hosted#203 deleted the org-member API write this path used
// to make: a tenant role IS the membership. The operator creates no user
// (gibson#1188): the daemon owns every account.
func (r *TenantMemberReconciler) assignMembership(ctx context.Context, tm *gibsonv1alpha1.TenantMember, orgID string) (string, error) {
	if r.Roles == nil {
		return "", errors.New("syncZitadel: role sync not configured")
	}
	role, ok := tenantRoleFromMemberRole(tm.Spec.Role)
	if !ok {
		return "", fmt.Errorf("syncZitadel: role %q has no tenant-role mapping", tm.Spec.Role)
	}
	userID := tm.Status.ZitadelUserID
	t := tenantrole.Tenant{ID: tm.Spec.TenantRef.Name, OrgID: orgID}
	if err := r.Roles.Assign(tenantrole.WithCaller(ctx, "tenant-operator"), t, userID, role); err != nil {
		return "", fmt.Errorf("syncZitadel: assign role: %w", err)
	}
	return membershipKey(orgID, userID), nil
}

// zitadelOrgID looks up the parent Tenant's Zitadel organization ID from its
// status. The TenantMember's TenantRef.Name identifies the cluster-scoped
// Tenant resource.
func (r *TenantMemberReconciler) zitadelOrgID(ctx context.Context, tm *gibsonv1alpha1.TenantMember) (string, error) {
	orgID, _, err := r.tenantOrg(ctx, tm)
	return orgID, err
}

// tenantOrg returns the Zitadel org of the parent Tenant and whether that
// Tenant is gone or on its way out. A missing Tenant reads as ("", true, nil).
func (r *TenantMemberReconciler) tenantOrg(
	ctx context.Context, tm *gibsonv1alpha1.TenantMember,
) (orgID string, deleting bool, err error) {
	var tenant gibsonv1alpha1.Tenant
	if err := r.Get(ctx, types.NamespacedName{Name: tm.Spec.TenantRef.Name}, &tenant); err != nil {
		if apierrors.IsNotFound(err) {
			return "", true, nil
		}
		return "", false, fmt.Errorf("get tenant %q: %w", tm.Spec.TenantRef.Name, err)
	}
	return tenant.Status.ZitadelOrgID, !tenant.DeletionTimestamp.IsZero(), nil
}

func (r *TenantMemberReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.Audit == nil {
		return fmt.Errorf("tenant member reconciler: %w", saga.ErrNoAudit)
	}
	if r.Recorder == nil {
		r.Recorder = mgr.GetEventRecorder("tenant-member-controller")
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&gibsonv1alpha1.TenantMember{}).
		Named("tenantmember").
		Complete(r)
}
