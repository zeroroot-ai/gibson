// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	platformv1alpha1 "github.com/zeroroot-ai/gibson/operators/platform/api/v1alpha1"
	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/audit"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/identity"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/saga"
)

// identityResyncInterval re-reconciles a Ready TenantIdentity periodically so
// drift in the underlying Zitadel org (a deleted organization) is corrected
// without waiting for an external event. The identity.Provisioner is idempotent
// (it verifies the known org id and re-creates on drift), so a periodic re-run
// is cheap when everything is already in place.
const identityResyncInterval = 10 * time.Minute

// TenantOrgSeeder seeds the daemon's tenant -> Zitadel org mapping that
// ext-authz reads to find a signed-in person's tenant (ADR-0093 decision 4).
// Required: a nil OrgMapping fails a reconcile loud, the same as a nil
// Provisioner, rather than leaving a tenant Ready with no mapping ext-authz
// can resolve.
type TenantOrgSeeder interface {
	SetTenantZitadelOrg(ctx context.Context, tenantID, zitadelOrgID string) error
}

// TenantIdentityReconciler reconciles a TenantIdentity object. It is the
// declarative replacement for the imperative EnsureZitadelOrg / RemoveZitadelOrg
// saga steps: it composes the per-tenant Zitadel organization by delegating to
// the shared identity.Provisioner. That provisioner wraps the SAME zitadel.Client
// the Tenant saga uses today (and both call the same identity.EnsureOrg /
// identity.RemoveOrg core), so there is exactly one provisioning codepath
// (ADR-0027); this controller is a second, declarative caller of it, not a
// parallel reimplementation.
type TenantIdentityReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder events.EventRecorder

	// ZitadelURL is the in-cluster Zitadel address that each minted
	// OIDCClient names: the connect base of the operator's ZITADEL_URL
	// (ADR-0092). No custom resource holds it (gibson#665).
	ZitadelURL string

	// Provisioner is the shared identity pipeline. Always non-nil in production
	// (buildIdentityProvisioner in cmd/main.go always returns identity.New(...));
	// a nil here fails loud so a misconfigured operator crash-loops rather than
	// silently no-op'ing identity provisioning.
	Provisioner identity.Provisioner

	// OrgMapping seeds the daemon's tenant -> Zitadel org mapping that
	// ext-authz reads to find a signed-in person's tenant (ADR-0093 decision
	// 4). Required. TenantIdentity is Ready only once the mapping exists.
	OrgMapping TenantOrgSeeder

	// Audit writes the record of each Zitadel change before the change
	// (gibson#583). Required: SetupWithManager fails without it.
	Audit *audit.SagaEmitter
}

// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=tenantidentities,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=tenantidentities/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=tenantidentities/finalizers,verbs=update
// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=platformbootstraps,verbs=get;list;watch
// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=oidcclients,verbs=get;list;watch;create;update;patch;delete

// Reconcile drives a TenantIdentity toward its desired state. The flow:
//
//	delete path  → run the finalizer teardown (Deprovision), then drop the
//	               finalizer once the org is gone.
//	provision    → ensure finalizer, call Provisioner.Provision (idempotent +
//	               drift-correcting), then write org id/slug + per-component +
//	               aggregate status.
//
// Status is the ONLY persisted output of this controller. Following the known
// saga hazard (steps re-run every reconcile and only Status().Patch sticks),
// the controller never mutates spec; it writes desired observed state (including
// the provisioned org id/slug — the same values the saga writes to
// Tenant.Status) to the status subresource.
func (r *TenantIdentityReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx).WithValues("tenantidentity", req.NamespacedName)

	var ti gibsonv1alpha1.TenantIdentity
	if err := r.Get(ctx, req.NamespacedName, &ti); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if r.Provisioner == nil {
		// Fail loud: a nil provisioner means operator wiring passed nil
		// explicitly. Record the error in status and requeue with backoff.
		log.Error(clients.ErrInvalidInput, "identity provisioner unset (operator misconfigured)")
		return r.failIdentity(ctx, &ti, "identity provisioner unset (operator misconfigured)")
	}
	if r.OrgMapping == nil {
		// Fail loud, same as a nil Provisioner: without it a Ready tenant
		// would have no org mapping for ext-authz to resolve a person's
		// tenant from (ADR-0093 decision 4).
		log.Error(clients.ErrInvalidInput, "org mapping seeder unset (operator misconfigured)")
		return r.failIdentity(ctx, &ti, "org mapping seeder unset (operator misconfigured)")
	}

	if r.Audit == nil {
		// Fail loud, same as a nil Provisioner: no Zitadel change happens
		// without its audit record (gibson#583).
		log.Error(clients.ErrInvalidInput, "audit emitter unset (operator misconfigured)")
		return r.failIdentity(ctx, &ti, "audit emitter unset (operator misconfigured)")
	}

	// Deletion path: run teardown, then drop the finalizer.
	if !ti.DeletionTimestamp.IsZero() {
		return r.reconcileIdentityDelete(ctx, &ti)
	}

	// Ensure finalizer so teardown runs before the CR is GC'd.
	if !controllerutil.ContainsFinalizer(&ti, gibsonv1alpha1.TenantIdentityFinalizer) {
		controllerutil.AddFinalizer(&ti, gibsonv1alpha1.TenantIdentityFinalizer)
		if err := r.Update(ctx, &ti); err != nil {
			return ctrl.Result{}, err
		}
		log.Info("added finalizer")
		return ctrl.Result{Requeue: true}, nil
	}

	// Provision (idempotent + drift-correcting). On a steady-state drift-check
	// resync (already Ready for this generation) skip the Provisioning flip so
	// status stays Ready and status-patch self-triggering stops the churn.
	// First provision and spec changes (generation bump) still flip to
	// Provisioning → Ready correctly.
	alreadyReady := ti.Status.Phase == gibsonv1alpha1.TenantIdentityPhaseReady &&
		ti.Status.ObservedGeneration == ti.Generation
	if !alreadyReady {
		if err := r.markIdentityProvisioning(ctx, &ti); err != nil {
			return ctrl.Result{}, err
		}
	}

	// The Zitadel organization and the daemon org mapping change together,
	// under one audit record written first (gibson#583). A drift-check pass
	// (already Ready at this generation) writes no new record.
	var res identity.Result
	failedStage := ""
	change := func() error {
		var perr error
		res, perr = r.Provisioner.Provision(ctx, identity.Request{
			TenantID:    ti.Spec.TenantID,
			DisplayName: ti.Spec.DisplayName,
			KnownOrgID:  ti.Status.ZitadelOrgID,
		})
		if perr != nil {
			failedStage = "provision"
			return perr
		}
		// Seed the daemon's tenant -> Zitadel org mapping (ADR-0093 decision
		// 4). TenantIdentity is Ready only once this write succeeds. It runs
		// on every resync (identityResyncInterval), so a lost row is repaired
		// without a spec change.
		if perr = r.OrgMapping.SetTenantZitadelOrg(ctx, ti.Spec.TenantID, res.OrgID); perr != nil {
			failedStage = "org_mapping"
			return perr
		}
		return nil
	}
	var err error
	if alreadyReady {
		err = change()
	} else {
		err = r.Audit.Change(ctx, audit.ObjectEvent(audit.ActionIdentityProvision, &ti, map[string]string{
			"generation": strconv.FormatInt(ti.Generation, 10),
		}), change)
	}
	switch {
	case err == nil:
	case failedStage == "provision":
		log.Error(err, "identity provision failed", "tenant", ti.Spec.TenantID)
		r.emitIdentity(&ti, "Warning", "ProvisionFailed", err.Error())
		if _, ferr := r.failIdentity(ctx, &ti, err.Error()); ferr != nil {
			return ctrl.Result{}, ferr
		}
		// Return the provision error so controller-runtime backs off.
		return ctrl.Result{}, err
	case failedStage == "org_mapping":
		log.Error(err, "seed tenant org mapping failed", "tenant", ti.Spec.TenantID)
		r.emitIdentity(&ti, "Warning", "OrgMappingFailed", err.Error())
		if _, ferr := r.failIdentity(ctx, &ti, "seed tenant org mapping: "+err.Error()); ferr != nil {
			return ctrl.Result{}, ferr
		}
		// The raw error drives controller-runtime's backoff, and is already
		// logged and recorded on status, so it is returned unwrapped.
		return ctrl.Result{}, err
	default:
		// The audit record was not written, so nothing changed.
		log.Error(err, "identity audit record failed; nothing changed", "tenant", ti.Spec.TenantID)
		r.emitIdentity(&ti, "Warning", "AuditRecordFailed", err.Error())
		if _, ferr := r.failIdentity(ctx, &ti, "audit record: "+err.Error()); ferr != nil {
			return ctrl.Result{}, ferr
		}
		return ctrl.Result{}, err
	}

	// The declared OIDC clients (spec.oidcClients, gibson#597) are minted
	// through the platform-operator's OIDCClient kind, one child per entry,
	// once the org they belong to exists.
	oidcReady, err := r.reconcileOIDCClients(ctx, &ti)
	if err != nil {
		log.Error(err, "oidc clients failed", "tenant", ti.Spec.TenantID)
		r.emitIdentity(&ti, "Warning", "OIDCClientsFailed", err.Error())
		if _, ferr := r.failIdentity(ctx, &ti, "oidc clients: "+err.Error()); ferr != nil {
			return ctrl.Result{}, ferr
		}
		return ctrl.Result{}, err
	}

	r.markIdentityReady(ctx, &ti, res, oidcReady)
	if !oidcReady {
		log.V(1).Info("tenant identity waiting for oidc clients", "tenant", ti.Spec.TenantID)
		return ctrl.Result{RequeueAfter: oidcClientPollInterval}, nil
	}
	r.emitIdentity(&ti, "Normal", "Provisioned", "tenant identity is ready")
	log.V(1).Info("tenant identity ready", "tenant", ti.Spec.TenantID, "org", res.OrgID)

	return ctrl.Result{RequeueAfter: identityResyncInterval}, nil
}

// reconcileIdentityDelete tears down the per-tenant Zitadel org via the
// idempotent Deprovision path, then removes the finalizer. Deprovision is
// best-effort: a NotFound is treated as success (already gone) by the
// provisioner itself, and any other error keeps the finalizer so the controller
// retries with backoff.
func (r *TenantIdentityReconciler) reconcileIdentityDelete(ctx context.Context, ti *gibsonv1alpha1.TenantIdentity) (ctrl.Result, error) {
	log := logf.FromContext(ctx).WithValues("tenantidentity", ti.Name, "phase", "delete")

	if !controllerutil.ContainsFinalizer(ti, gibsonv1alpha1.TenantIdentityFinalizer) {
		return ctrl.Result{}, nil
	}

	base := ti.DeepCopy()
	ti.Status.Phase = gibsonv1alpha1.TenantIdentityPhaseDeprovisioning
	ti.Status.Ready = false
	_ = r.patchIdentityStatus(ctx, ti, base)

	if r.Provisioner != nil {
		ev := audit.ObjectEvent(audit.ActionIdentityDeprovision, ti, map[string]string{"zitadel_org_id": ti.Status.ZitadelOrgID})
		if err := r.Audit.Change(ctx, ev, func() error {
			if err := r.Provisioner.Deprovision(ctx, ti.Status.ZitadelOrgID); err != nil && !errors.Is(err, clients.ErrNotFound) {
				return err
			}
			return nil
		}); err != nil {
			log.Error(err, "identity deprovision failed; keeping finalizer for retry", "tenant", ti.Spec.TenantID)
			r.emitIdentity(ti, "Warning", "DeprovisionFailed", err.Error())
			return ctrl.Result{}, err
		}
	}

	patch := client.MergeFrom(ti.DeepCopy())
	if controllerutil.RemoveFinalizer(ti, gibsonv1alpha1.TenantIdentityFinalizer) {
		if err := r.Patch(ctx, ti, patch); err != nil {
			return ctrl.Result{}, err
		}
		log.Info("finalizer removed; tenant identity deprovisioned", "tenant", ti.Spec.TenantID)
	}
	return ctrl.Result{}, nil
}

// markIdentityProvisioning records the in-flight phase via Status().Patch. It
// returns an error only when the patch itself fails — callers that guard on
// alreadyReady propagate it so the reconcile retries rather than continuing
// with stale in-cluster state.
func (r *TenantIdentityReconciler) markIdentityProvisioning(ctx context.Context, ti *gibsonv1alpha1.TenantIdentity) error {
	base := ti.DeepCopy()
	ti.Status.Phase = gibsonv1alpha1.TenantIdentityPhaseProvisioning
	ti.Status.LastError = ""
	return r.patchIdentityStatus(ctx, ti, base)
}

// markIdentityReady records the ready state: org id/slug recorded, aggregate
// Ready true, every component ready, and the Ready condition flipped True. The
// org id/slug are written the SAME way the saga writes Tenant.Status, so
// downstream readers see identical data regardless of codepath.
func (r *TenantIdentityReconciler) markIdentityReady(ctx context.Context, ti *gibsonv1alpha1.TenantIdentity, res identity.Result, oidcReady bool) {
	base := ti.DeepCopy()
	ti.Status.ZitadelOrgID = res.OrgID
	ti.Status.ZitadelOrgSlug = res.Slug
	ti.Status.ObservedGeneration = ti.Generation
	ti.Status.Components = identityComponents(ti, oidcReady)
	if oidcReady {
		ti.Status.Phase = gibsonv1alpha1.TenantIdentityPhaseReady
		ti.Status.Ready = true
		ti.Status.LastError = ""
		setIdentityReadyCondition(ti, metav1.ConditionTrue, "Provisioned", "tenant identity is ready")
	} else {
		ti.Status.Phase = gibsonv1alpha1.TenantIdentityPhaseProvisioning
		ti.Status.Ready = false
		setIdentityReadyCondition(ti, metav1.ConditionFalse, "OIDCClientsPending", "declared oidc clients are not minted yet")
	}
	_ = r.patchIdentityStatus(ctx, ti, base)
}

// failIdentity records a failed reconcile in status without mutating spec.
func (r *TenantIdentityReconciler) failIdentity(ctx context.Context, ti *gibsonv1alpha1.TenantIdentity, msg string) (ctrl.Result, error) {
	base := ti.DeepCopy()
	ti.Status.Phase = gibsonv1alpha1.TenantIdentityPhaseFailed
	ti.Status.Ready = false
	ti.Status.LastError = msg
	setIdentityReadyCondition(ti, metav1.ConditionFalse, "ProvisionFailed", msg)
	_ = r.patchIdentityStatus(ctx, ti, base)
	return ctrl.Result{}, nil
}

// patchIdentityStatus persists status via a merge-patch off the captured base.
// Using Patch (not Update) avoids resourceVersion conflicts with the Tenant
// saga, which patches Tenant status concurrently. The error is returned so
// that callers which guard on observed phase (e.g. markIdentityProvisioning in
// the alreadyReady guard) can propagate it; callers that write terminal state
// (markIdentityReady, failIdentity) log and continue as before.
func (r *TenantIdentityReconciler) patchIdentityStatus(ctx context.Context, ti, base *gibsonv1alpha1.TenantIdentity) error {
	if err := r.Status().Patch(ctx, ti, client.MergeFrom(base)); err != nil {
		logf.FromContext(ctx).Error(err, "tenantidentity status patch failed", "tenant", ti.Spec.TenantID)
		return err
	}
	return nil
}

// emitIdentity records a Kubernetes event on the TenantIdentity. No-ops when the
// recorder is nil (tests).
func (r *TenantIdentityReconciler) emitIdentity(ti *gibsonv1alpha1.TenantIdentity, eventType, reason, msg string) {
	if r.Recorder == nil {
		return
	}
	r.Recorder.Eventf(ti, nil, eventType, reason, reason, "%s", msg)
}

// identityComponents returns the per-component conditions. The zitadel-org
// component always participates (the operator always provisions the org).
// The oidc-client component participates when the spec declares clients,
// and reads ready only once every declared OIDCClient child reports its
// Zitadel-side client exists (gibson#597).
func identityComponents(ti *gibsonv1alpha1.TenantIdentity, oidcReady bool) []gibsonv1alpha1.TenantIdentityComponentCondition {
	comps := []gibsonv1alpha1.TenantIdentityComponentCondition{{Name: "zitadel-org", State: "ready"}}
	if len(ti.Spec.OIDCClients) > 0 {
		state := "pending"
		if oidcReady {
			state = "ready"
		}
		comps = append(comps, gibsonv1alpha1.TenantIdentityComponentCondition{Name: "oidc-client", State: state})
	}
	return comps
}

// oidcClientPollInterval is how often a TenantIdentity waiting on its
// declared OIDC clients looks again.
const oidcClientPollInterval = 15 * time.Second

// reconcileOIDCClients mints one platform OIDCClient per declared entry in
// spec.oidcClients, owned by the TenantIdentity, with the Zitadel issuer,
// admin token and project copied from the cluster's PlatformBootstrap (the
// same source the platform-operator's own children use). An entry removed
// from the spec takes its child with it. It returns whether every declared
// client exists on the Zitadel side.
func (r *TenantIdentityReconciler) reconcileOIDCClients(ctx context.Context, ti *gibsonv1alpha1.TenantIdentity) (bool, error) {
	if len(ti.Spec.OIDCClients) == 0 {
		return true, r.pruneOIDCClients(ctx, ti, nil)
	}
	var boots platformv1alpha1.PlatformBootstrapList
	if err := r.List(ctx, &boots); err != nil {
		return false, fmt.Errorf("list PlatformBootstrap: %w", err)
	}
	if len(boots.Items) != 1 {
		return false, fmt.Errorf("spec.oidcClients needs exactly one PlatformBootstrap to copy the Zitadel issuer, admin token and project from; found %d", len(boots.Items))
	}
	pb := boots.Items[0]

	ready := true
	keep := make(map[string]struct{}, len(ti.Spec.OIDCClients))
	for _, entry := range ti.Spec.OIDCClients {
		name := oidcClientChildName(ti, entry)
		keep[name] = struct{}{}
		child := &platformv1alpha1.OIDCClient{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ti.Namespace}}
		if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, child, func() error {
			if err := controllerutil.SetControllerReference(ti, child, r.Scheme); err != nil {
				return fmt.Errorf("own OIDCClient %s: %w", name, err)
			}
			child.Spec = oidcClientSpecFor(ti, entry, pb, r.ZitadelURL)
			return nil
		}); err != nil {
			return false, fmt.Errorf("apply OIDCClient %s: %w", name, err)
		}
		var current platformv1alpha1.OIDCClient
		if err := r.Get(ctx, types.NamespacedName{Namespace: ti.Namespace, Name: name}, &current); err != nil {
			return false, fmt.Errorf("get OIDCClient %s: %w", name, err)
		}
		if !apimeta.IsStatusConditionTrue(current.Status.Conditions, platformv1alpha1.ConditionOIDCClientExists) {
			ready = false
		}
	}
	return ready, r.pruneOIDCClients(ctx, ti, keep)
}

// pruneOIDCClients deletes the OIDCClient children this TenantIdentity owns
// that no declared entry names any more.
func (r *TenantIdentityReconciler) pruneOIDCClients(ctx context.Context, ti *gibsonv1alpha1.TenantIdentity, keep map[string]struct{}) error {
	var owned platformv1alpha1.OIDCClientList
	if err := r.List(ctx, &owned, client.InNamespace(ti.Namespace)); err != nil {
		return fmt.Errorf("list OIDCClients: %w", err)
	}
	for i := range owned.Items {
		oc := &owned.Items[i]
		if !metav1.IsControlledBy(oc, ti) {
			continue
		}
		if _, ok := keep[oc.Name]; ok {
			continue
		}
		if err := r.Delete(ctx, oc); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete OIDCClient %s: %w", oc.Name, err)
		}
	}
	return nil
}

func oidcClientChildName(ti *gibsonv1alpha1.TenantIdentity, entry gibsonv1alpha1.TenantIdentityOIDCClient) string {
	return ti.Name + "-" + entry.Name
}

// oidcClientSpecFor is the OIDCClient the platform-operator mints for one
// declared entry: a web client when the entry has redirect URIs (the
// authorization-code flow), a service client otherwise, in the platform
// project every tenant org is granted (ADR-0093). The minted client secret
// lands in a Secret beside the TenantIdentity.
func oidcClientSpecFor(ti *gibsonv1alpha1.TenantIdentity, entry gibsonv1alpha1.TenantIdentityOIDCClient, pb platformv1alpha1.PlatformBootstrap, zitadelURL string) platformv1alpha1.OIDCClientSpec {
	spec := platformv1alpha1.OIDCClientSpec{
		ZitadelURL:      zitadelURL,
		AdminTokenRef:   pb.Spec.Zitadel.AdminTokenRef,
		ProjectRef:      platformv1alpha1.ProjectReference{Name: pb.Spec.Zitadel.Project.Name},
		ClientName:      ti.Spec.TenantID + "/" + entry.Name,
		ApplicationType: platformv1alpha1.OIDCAppTypeService,
		SecretRef:       platformv1alpha1.SecretKeyRef{Name: oidcClientChildName(ti, entry) + "-oidc", Namespace: ti.Namespace},
	}
	if len(entry.RedirectURIs) > 0 {
		spec.ApplicationType = platformv1alpha1.OIDCAppTypeWeb
		spec.RedirectURIs = append([]string(nil), entry.RedirectURIs...)
		spec.GrantTypes = []platformv1alpha1.OIDCGrantType{"AUTHORIZATION_CODE", "REFRESH_TOKEN"}
		spec.ResponseTypes = []platformv1alpha1.OIDCResponseType{"CODE"}
	}
	return spec
}

// setIdentityReadyCondition upserts the aggregate Ready condition.
func setIdentityReadyCondition(ti *gibsonv1alpha1.TenantIdentity, status metav1.ConditionStatus, reason, msg string) {
	cond := metav1.Condition{
		Type:               gibsonv1alpha1.ConditionTenantIdentityReady,
		Status:             status,
		Reason:             reason,
		Message:            msg,
		ObservedGeneration: ti.Generation,
		LastTransitionTime: metav1.Now(),
	}
	for i := range ti.Status.Conditions {
		if ti.Status.Conditions[i].Type == cond.Type {
			// Preserve LastTransitionTime when status is unchanged.
			if ti.Status.Conditions[i].Status == status {
				cond.LastTransitionTime = ti.Status.Conditions[i].LastTransitionTime
			}
			ti.Status.Conditions[i] = cond
			return
		}
	}
	ti.Status.Conditions = append(ti.Status.Conditions, cond)
}

// SetupWithManager registers the controller with the manager.
//
// GenerationChangedPredicate filters out status-only patch events: status
// writes do not bump metadata.generation, so they no longer re-trigger a
// reconcile. This stops the status-patch → re-trigger → markIdentityProvisioning
// churn that prevented the phase from ever settling on Ready (gibson#1140).
// Spec changes (generation bump), creates, and deletes still reconcile
// immediately; the 10-minute RequeueAfter handles drift-correction resyncs.
func (r *TenantIdentityReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.Audit == nil {
		return fmt.Errorf("tenant identity reconciler: %w", saga.ErrNoAudit)
	}
	if r.Recorder == nil {
		r.Recorder = mgr.GetEventRecorder("tenantidentity-controller")
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&gibsonv1alpha1.TenantIdentity{},
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Named("tenantidentity").
		Complete(r)
}
