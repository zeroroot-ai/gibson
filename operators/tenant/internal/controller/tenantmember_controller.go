// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
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
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/mail"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/saga"
)

const invitationTTL = 7 * 24 * time.Hour

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

// TenantMemberReconciler owns invitation lifecycle and active membership
// state for a tenant.
type TenantMemberReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder events.EventRecorder

	FGA     fga.Client
	Mail    mail.Sender
	Zitadel zitadel.Client
	// Roles is the tenant role Syncer (ADR-0093 decision 3): the one writer
	// of tenant-role tuples. syncZitadel calls Roles.Assign for a member
	// whose Zitadel user already exists; cleanup calls Roles.Revoke.
	Roles *tenantrole.Syncer

	// BaseAcceptURL is the dashboard base URL for invitation accept links
	// (e.g. "https://app.zeroroot.ai").
	BaseAcceptURL string

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

	// Branch on phase + spec state.
	switch {
	case tm.Spec.AcceptedByUserID != "" && tm.Status.Phase == gibsonv1alpha1.TenantMemberPhaseInvited:
		return r.acceptInvitation(ctx, &tm)
	case tm.Status.Phase == gibsonv1alpha1.TenantMemberPhaseActive:
		// Already active. ResendRequestedAt bumps are a no-op once the
		// member is past invited (kept here as the documented behavior:
		// there is nothing to resend). Future work might surface the
		// resend-after-active case as an explicit Tenant condition.
		return ctrl.Result{}, nil
	case tm.Status.Phase == "" || tm.Status.Phase == gibsonv1alpha1.TenantMemberPhasePending:
		return r.issueInvitation(ctx, &tm)
	case tm.Status.Phase == gibsonv1alpha1.TenantMemberPhaseInvited:
		// Check expiry.
		if tm.Status.InvitationExpiresAt != nil && time.Now().After(tm.Status.InvitationExpiresAt.Time) {
			return r.expireInvitation(ctx, &tm)
		}
		if tm.Spec.ResendRequestedAt != nil && (tm.Status.LastResendAt == nil || tm.Spec.ResendRequestedAt.After(tm.Status.LastResendAt.Time)) {
			return r.resendInvitation(ctx, &tm)
		}
		// Nothing to do; requeue for expiry check.
		if tm.Status.InvitationExpiresAt != nil {
			remaining := time.Until(tm.Status.InvitationExpiresAt.Time)
			if remaining > 0 {
				return ctrl.Result{RequeueAfter: remaining}, nil
			}
		}
	}

	log.V(1).Info("no action", "phase", tm.Status.Phase)
	return ctrl.Result{}, nil
}

func (r *TenantMemberReconciler) issueInvitation(ctx context.Context, tm *gibsonv1alpha1.TenantMember) (ctrl.Result, error) {
	token, hash, err := generateInvitationToken()
	if err != nil {
		return ctrl.Result{}, err
	}
	expiresAt := time.Now().Add(invitationTTL)

	// Create Secret holding the plaintext token.
	secretName := fmt.Sprintf("invitation-%s", shortHash(hash))
	trueVal := true
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: tm.Namespace,
			Annotations: map[string]string{
				"gibson.zeroroot.ai/expires-at":   expiresAt.Format(time.RFC3339),
				"gibson.zeroroot.ai/tenantmember": tm.Name,
			},
			Labels: map[string]string{
				"gibson.zeroroot.ai/kind":       "invitation-token",
				"gibson.zeroroot.ai/managed-by": "tenant-operator",
			},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion:         gibsonv1alpha1.GroupVersion.String(),
				Kind:               "TenantMember",
				Name:               tm.Name,
				UID:                tm.UID,
				Controller:         &trueVal,
				BlockOwnerDeletion: &trueVal,
			}},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{"token": []byte(token)},
	}
	ev := audit.ObjectEvent(audit.ActionMemberInvitationIssue, tm, map[string]string{"secret": secretName})
	if err := r.Audit.Change(ctx, ev, func() error {
		if err := r.Create(ctx, secret); err != nil && !apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("create invitation secret: %w", err)
		}
		return nil
	}); err != nil {
		return ctrl.Result{}, fmt.Errorf("record the invitation: %w", err)
	}

	// Send email.
	if r.Mail != nil {
		acceptURL := fmt.Sprintf("%s/invite/%s", r.BaseAcceptURL, token)
		if err := r.Mail.SendInvitation(ctx, mail.InvitationMessage{
			To:           tm.Spec.Email,
			TenantName:   tm.Spec.TenantRef.Name,
			InviterEmail: inviterDisplay(tm),
			AcceptURL:    acceptURL,
			ExpiresAt:    expiresAt,
		}); err != nil {
			// Email failure is non-blocking: record but continue.
			// events.EventRecorder.Eventf signature: (regarding, related,
			// eventtype, reason, action, note, args...).
			r.Recorder.Eventf(tm, nil, corev1.EventTypeWarning, "EmailFailed", "EmailFailed", "%s", err.Error())
		}
	}

	now := metav1.Now()
	expMeta := metav1.NewTime(expiresAt)
	tm.Status.Phase = gibsonv1alpha1.TenantMemberPhaseInvited
	tm.Status.InvitationExpiresAt = &expMeta
	tm.Status.InvitationSecretRef = secretName
	tm.Status.LastResendAt = &now
	tm.Status.ObservedGeneration = tm.Generation

	if err := r.Status().Update(ctx, tm); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: invitationTTL}, nil
}

func (r *TenantMemberReconciler) resendInvitation(ctx context.Context, tm *gibsonv1alpha1.TenantMember) (ctrl.Result, error) {
	// Simpler: just resend email with the existing token (read from Secret).
	if tm.Status.InvitationSecretRef == "" {
		// No existing token; treat as new issuance.
		return r.issueInvitation(ctx, tm)
	}
	secret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: tm.Namespace, Name: tm.Status.InvitationSecretRef}, secret); err != nil {
		if apierrors.IsNotFound(err) {
			// Secret gone; re-issue.
			return r.issueInvitation(ctx, tm)
		}
		return ctrl.Result{}, err
	}
	token := string(secret.Data["token"])
	if r.Mail != nil {
		acceptURL := fmt.Sprintf("%s/invite/%s", r.BaseAcceptURL, token)
		_ = r.Mail.SendInvitation(ctx, mail.InvitationMessage{
			To:           tm.Spec.Email,
			TenantName:   tm.Spec.TenantRef.Name,
			InviterEmail: inviterDisplay(tm),
			AcceptURL:    acceptURL,
			ExpiresAt:    tm.Status.InvitationExpiresAt.Time,
		})
	}
	now := metav1.Now()
	tm.Status.LastResendAt = &now
	return ctrl.Result{}, r.Status().Update(ctx, tm)
}

func (r *TenantMemberReconciler) acceptInvitation(ctx context.Context, tm *gibsonv1alpha1.TenantMember) (ctrl.Result, error) {
	ev := audit.ObjectEvent(audit.ActionMemberInvitationAccept, tm, map[string]string{"user_id": tm.Spec.AcceptedByUserID})
	if err := r.Audit.Change(ctx, ev, func() error {
		if r.FGA != nil {
			// The tenant role tuple is no longer written here: syncZitadel runs
			// before this branch on every reconcile and, for a member with a
			// Zitadel user id, already called Roles.Assign — which writes the
			// Zitadel grant and copies it into FGA in one call (ADR-0093). The
			// only writes left here are the session tuples, which are not role
			// tuples and stay direct FGA writes.

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

		// Burn the invitation secret.
		if tm.Status.InvitationSecretRef != "" {
			secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: tm.Status.InvitationSecretRef, Namespace: tm.Namespace}}
			if err := r.Delete(ctx, secret); err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("delete the invitation secret: %w", err)
			}
		}
		return nil
	}); err != nil {
		return ctrl.Result{}, fmt.Errorf("record the invitation acceptance: %w", err)
	}

	tm.Status.Phase = gibsonv1alpha1.TenantMemberPhaseActive
	tm.Status.UserID = tm.Spec.AcceptedByUserID
	tm.Status.InvitationSecretRef = ""
	tm.Status.ObservedGeneration = tm.Generation
	return ctrl.Result{}, r.Status().Update(ctx, tm)
}

func (r *TenantMemberReconciler) expireInvitation(ctx context.Context, tm *gibsonv1alpha1.TenantMember) (ctrl.Result, error) {
	if tm.Status.InvitationSecretRef != "" {
		secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: tm.Status.InvitationSecretRef, Namespace: tm.Namespace}}
		ev := audit.ObjectEvent(audit.ActionMemberInvitationExpire, tm, map[string]string{"secret": secret.Name})
		if err := r.Audit.Change(ctx, ev, func() error {
			if err := r.Delete(ctx, secret); err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("delete invitation secret: %w", err)
			}
			return nil
		}); err != nil {
			return ctrl.Result{}, fmt.Errorf("record the invitation withdrawal: %w", err)
		}
	}
	tm.Status.Phase = gibsonv1alpha1.TenantMemberPhaseExpired
	tm.Status.InvitationSecretRef = ""
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
		orgID, err := r.zitadelOrgID(context.WithoutCancel(ctx), tm)
		if err != nil {
			// Zitadel unreachable — surface so the caller requeueues with backoff.
			return fmt.Errorf("cleanup: resolve zitadel org: %w", err)
		}
		if orgID != "" {
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

	// A member with no email and no Zitadel user has nothing to sync yet.
	if tm.Status.ZitadelUserID == "" && tm.Spec.Email == "" {
		return ctrl.Result{}, nil
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
	case errors.Is(err, clients.ErrUnreachable), errors.Is(err, tenantrole.ErrOwnerConflict):
		log.Info("syncZitadel: zitadel not ready; requeue", "err", err.Error())
		return ctrl.Result{RequeueAfter: zitadelBackoff}, nil
	default:
		return ctrl.Result{}, fmt.Errorf("sync the Zitadel role of the member: %w", err)
	}

	tm.Status.ZitadelMembershipID = membershipID
	if err := r.Status().Update(ctx, tm); err != nil {
		return ctrl.Result{}, fmt.Errorf("syncZitadel: status update: %w", err)
	}
	return ctrl.Result{}, nil
}

// assignMembership creates the Zitadel user of a member when it has none, then
// assigns the tenant role through the Syncer (ADR-0093), which writes the
// Zitadel grant and copies it into FGA in the same call. It returns the
// membership id "<org>/<user>".
//
// A member that already has a Zitadel user (self-signup, pre-accepted) gets
// only the role. A member with an email and no user gets a new Zitadel user:
// Zitadel's own unverified-email flow emails the invitee a way to set a
// credential. hosted#203 deleted the org-member API write this path used to
// make: a tenant role IS the membership.
func (r *TenantMemberReconciler) assignMembership(ctx context.Context, tm *gibsonv1alpha1.TenantMember, orgID string) (string, error) {
	if r.Roles == nil {
		return "", errors.New("syncZitadel: role sync not configured")
	}
	role, ok := tenantRoleFromMemberRole(tm.Spec.Role)
	if !ok {
		return "", fmt.Errorf("syncZitadel: role %q has no tenant-role mapping", tm.Spec.Role)
	}
	userID := tm.Status.ZitadelUserID
	if userID == "" {
		created, err := r.Zitadel.EnsureHumanUser(ctx, orgID, tm.Spec.Email)
		if err != nil {
			return "", fmt.Errorf("syncZitadel: ensure human user: %w", err)
		}
		userID = created
		tm.Status.ZitadelUserID = userID
	}
	t := tenantrole.Tenant{ID: tm.Spec.TenantRef.Name, OrgID: orgID}
	if err := r.Roles.Assign(tenantrole.WithCaller(ctx, "tenant-operator"), t, userID, role); err != nil {
		return "", fmt.Errorf("syncZitadel: assign role: %w", err)
	}
	return fmt.Sprintf("%s/%s", orgID, userID), nil
}

// zitadelOrgID looks up the parent Tenant's Zitadel organization ID from its
// status. The TenantMember's TenantRef.Name identifies the cluster-scoped
// Tenant resource.
func (r *TenantMemberReconciler) zitadelOrgID(ctx context.Context, tm *gibsonv1alpha1.TenantMember) (string, error) {
	var tenant gibsonv1alpha1.Tenant
	if err := r.Get(ctx, types.NamespacedName{Name: tm.Spec.TenantRef.Name}, &tenant); err != nil {
		if apierrors.IsNotFound(err) {
			return "", nil
		}
		return "", fmt.Errorf("get tenant %q: %w", tm.Spec.TenantRef.Name, err)
	}
	return tenant.Status.ZitadelOrgID, nil
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

func generateInvitationToken() (token, hash string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	token = hex.EncodeToString(buf)
	sum := sha256.Sum256([]byte(token))
	hash = hex.EncodeToString(sum[:])
	return token, hash, nil
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// inviterDisplay returns the value to render as the inviter in the
// outgoing invitation email. If the dashboard recorded the inviter's
// email on the CR, use it verbatim; otherwise fall back to a generic
// placeholder so the email never has a leading-whitespace artefact
// like " has invited you to join ...".
func inviterDisplay(tm *gibsonv1alpha1.TenantMember) string {
	if tm != nil && tm.Spec.InvitedByEmail != "" {
		return tm.Spec.InvitedByEmail
	}
	return "a Gibson admin"
}
