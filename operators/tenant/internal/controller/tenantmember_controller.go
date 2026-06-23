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

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/fga"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/zitadel"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/mail"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/provision"
)

const invitationTTL = 7 * 24 * time.Hour

// Zitadel project role keys minted by the post-install Job (task 2).
// Owner / admin / member are the canonical three; member is the default
// for any unrecognised value.
const (
	zitadelRoleKeyOwner  = "gibson.owner"
	zitadelRoleKeyAdmin  = "gibson.admin"
	zitadelRoleKeyMember = "gibson.member"
)

// zitadelRoleKey maps a MemberRole to the Zitadel project role key.
func zitadelRoleKey(role gibsonv1alpha1.MemberRole) string {
	switch role {
	case gibsonv1alpha1.MemberRoleOwner:
		return zitadelRoleKeyOwner
	case gibsonv1alpha1.MemberRoleAdmin:
		return zitadelRoleKeyAdmin
	case gibsonv1alpha1.MemberRoleMember:
		return zitadelRoleKeyMember
	default:
		return zitadelRoleKeyMember
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

	// BaseAcceptURL is the dashboard base URL for invitation accept links
	// (e.g. "https://app.zeroroot.ai").
	BaseAcceptURL string

	// StatusReporter mirrors the founding-owner member's readiness into the
	// daemon's tenant_status row (dashboard#855) once an owner-role member
	// reaches Active, so the dashboard's waitForMemberReady can read it from
	// the daemon instead of K8s (ADR-0023). Best-effort; nil = no-op (tests /
	// operator booted without a daemon client).
	StatusReporter TenantStatusReporter
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
		//
		// Re-report owner-member readiness (idempotent, daemon OR-preserves it):
		// covers a member that was already Active before the reporter was wired
		// or whose prior report was lost (dashboard#855).
		r.reportOwnerMemberReady(ctx, &tm)
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
	if err := r.Create(ctx, secret); err != nil && !apierrors.IsAlreadyExists(err) {
		return ctrl.Result{}, fmt.Errorf("create invitation secret: %w", err)
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
	tm.Status.InvitationTokenHash = hash
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
	if r.FGA != nil {
		if err := r.FGA.Write(ctx, []fga.Tuple{{
			User:     fmt.Sprintf("user:%s", tm.Spec.AcceptedByUserID),
			Relation: string(tm.Spec.Role),
			Object:   fmt.Sprintf("tenant:%s", tm.Spec.TenantRef.Name),
		}}); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Burn the invitation secret.
	if tm.Status.InvitationSecretRef != "" {
		secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: tm.Status.InvitationSecretRef, Namespace: tm.Namespace}}
		if err := r.Delete(ctx, secret); err != nil && !apierrors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
	}

	tm.Status.Phase = gibsonv1alpha1.TenantMemberPhaseActive
	tm.Status.UserID = tm.Spec.AcceptedByUserID
	tm.Status.InvitationSecretRef = ""
	tm.Status.InvitationTokenHash = ""
	tm.Status.ObservedGeneration = tm.Generation
	if err := r.Status().Update(ctx, tm); err != nil {
		return ctrl.Result{}, fmt.Errorf("set tenantmember active: %w", err)
	}
	r.reportOwnerMemberReady(ctx, tm)
	return ctrl.Result{}, nil
}

// reportOwnerMemberReady mirrors owner-member readiness into the daemon's
// tenant_status row when an owner-role member is Active (dashboard#855). It is a
// no-op for non-owner members and when no reporter is wired. It reads the live
// Tenant CR (the operator CAN read K8s; the daemon cannot — ADR-0023) so the
// upsert carries the full, accurate status alongside owner_member_ready=true,
// rather than clobbering phase/ready/zitadel/dataPlane with empty values.
// Best-effort: any failure logs and never fails the reconcile.
func (r *TenantMemberReconciler) reportOwnerMemberReady(ctx context.Context, tm *gibsonv1alpha1.TenantMember) {
	// owner-only domain gate (NOT a dep-nil guard): only the founding owner's
	// readiness feeds the daemon's tenant_status. StatusReporter is never nil in
	// a running operator (SetupWithManager defaults it to the noop).
	if tm.Spec.Role != gibsonv1alpha1.MemberRoleOwner {
		return
	}
	log := logf.FromContext(ctx).WithValues("tenantmember", tm.Name, "tenant", tm.Spec.TenantRef.Name)

	report := provision.TenantStatusReport{
		TenantID:         tm.Spec.TenantRef.Name,
		OwnerMemberReady: true,
	}
	// Enrich with the live Tenant CR status so the upsert does not regress
	// phase/ready/zitadel/dataPlane (the daemon overwrites those columns with
	// whatever this report carries; owner_member_ready alone is OR-preserved).
	var tenant gibsonv1alpha1.Tenant
	if err := r.Get(ctx, types.NamespacedName{Name: tm.Spec.TenantRef.Name}, &tenant); err == nil {
		report.Phase = string(tenant.Status.Phase)
		report.Ready = tenant.Status.Phase == gibsonv1alpha1.TenantPhaseReady
		report.ZitadelOrgID = tenant.Status.ZitadelOrgID
		report.DataPlaneReady = tenant.Status.DataPlane.Ready
	} else {
		log.Info("could not read Tenant CR to enrich owner-member-ready report; reporting readiness only", "err", err)
	}

	if err := r.StatusReporter.ReportTenantStatus(ctx, report); err != nil {
		log.Info("failed to mirror owner-member readiness to daemon (will retry next reconcile)", "err", err)
	}
}

func (r *TenantMemberReconciler) expireInvitation(ctx context.Context, tm *gibsonv1alpha1.TenantMember) (ctrl.Result, error) {
	if tm.Status.InvitationSecretRef != "" {
		secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: tm.Status.InvitationSecretRef, Namespace: tm.Namespace}}
		_ = r.Delete(ctx, secret)
	}
	tm.Status.Phase = gibsonv1alpha1.TenantMemberPhaseExpired
	tm.Status.InvitationSecretRef = ""
	return ctrl.Result{}, r.Status().Update(ctx, tm)
}

func (r *TenantMemberReconciler) cleanup(ctx context.Context, tm *gibsonv1alpha1.TenantMember) error {
	// Remove FGA tuple (active members). Best-effort: fgaMissing is
	// expected on retries (tuple already deleted) and other errors are
	// not actionable on the cleanup path — surface a real error class
	// + retry only when this becomes a saga step with its own status
	// condition.
	if r.FGA != nil && tm.Status.UserID != "" {
		_ = r.FGA.Delete(ctx, []fga.Tuple{{
			User:     fmt.Sprintf("user:%s", tm.Status.UserID),
			Relation: string(tm.Spec.Role),
			Object:   fmt.Sprintf("tenant:%s", tm.Spec.TenantRef.Name),
		}})
	}

	// Remove Zitadel membership if it was recorded.
	if r.Zitadel != nil && tm.Status.ZitadelMembershipID != "" && tm.Status.ZitadelUserID != "" {
		orgID, err := r.zitadelOrgID(context.WithoutCancel(ctx), tm)
		if err != nil {
			// Zitadel unreachable — surface so the caller requeueues with backoff.
			return fmt.Errorf("cleanup: resolve zitadel org: %w", err)
		}
		if orgID != "" {
			if err := r.Zitadel.RemoveMember(ctx, orgID, tm.Status.ZitadelUserID); err != nil {
				if !errors.Is(err, clients.ErrNotFound) {
					return fmt.Errorf("cleanup: remove zitadel member: %w", err)
				}
				// 404 — already gone; treat as success (idempotent).
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

	roles := []string{zitadelRoleKey(tm.Spec.Role)}

	var membershipID string

	if tm.Status.ZitadelUserID != "" {
		// User already exists in Zitadel — just add org membership.
		mid, merr := r.Zitadel.AddMember(ctx, orgID, tm.Status.ZitadelUserID, roles)
		if merr != nil {
			if errors.Is(merr, clients.ErrUnreachable) {
				return ctrl.Result{RequeueAfter: zitadelBackoff}, nil
			}
			if errors.Is(merr, clients.ErrAlreadyExists) {
				// Membership already exists — desired state reached; treat as success.
				log.Info("syncZitadel: membership already exists, treating as success", "orgID", orgID, "userID", tm.Status.ZitadelUserID)
				membershipID = fmt.Sprintf("%s/%s", orgID, tm.Status.ZitadelUserID)
			} else {
				return ctrl.Result{}, fmt.Errorf("syncZitadel: add member: %w", merr)
			}
		} else {
			membershipID = mid
		}
	} else if tm.Spec.Email != "" {
		// No Zitadel user yet — send an invitation which also creates the user
		// and grants the org membership.
		invitationID, ierr := r.Zitadel.SendInvitation(ctx, orgID, tm.Spec.Email, roles)
		if ierr != nil {
			if errors.Is(ierr, clients.ErrUnreachable) {
				return ctrl.Result{RequeueAfter: zitadelBackoff}, nil
			}
			return ctrl.Result{}, fmt.Errorf("syncZitadel: send invitation: %w", ierr)
		}
		// invitationID is the Zitadel user ID; persist both fields.
		tm.Status.ZitadelUserID = invitationID
		membershipID = fmt.Sprintf("%s/%s", orgID, invitationID)
	} else {
		// No email and no ZitadelUserID — nothing we can do yet.
		return ctrl.Result{}, nil
	}

	tm.Status.ZitadelMembershipID = membershipID
	if err := r.Status().Update(ctx, tm); err != nil {
		return ctrl.Result{}, fmt.Errorf("syncZitadel: status update: %w", err)
	}
	return ctrl.Result{}, nil
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
	if r.Recorder == nil {
		r.Recorder = mgr.GetEventRecorder("tenant-member-controller")
	}
	if r.StatusReporter == nil {
		r.StatusReporter = noopTenantStatusReporter{}
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
