// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package controller

import (
	"context"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/saga"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/saga/flows"
)

// AgentEnrollmentReconciler owns the lifecycle of external agent enrollments.
type AgentEnrollmentReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder events.EventRecorder

	Runner          *saga.Runner
	Deps            flows.EnrollmentDeps
	IssuanceSteps   []saga.Step
	RevocationSteps []saga.Step
}

// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=agentenrollments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=agentenrollments/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=agentenrollments/finalizers,verbs=update

func (r *AgentEnrollmentReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx).WithValues("agentenrollment", req.NamespacedName)

	var ae gibsonv1alpha1.AgentEnrollment
	if err := r.Get(ctx, req.NamespacedName, &ae); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Backfill missing ownerRef — converges pre-fix state and any CR that
	// slipped past the admission webhook. Safe to run on every reconcile;
	// no-op when ref is already present.
	if len(ae.OwnerReferences) == 0 {
		if ref, err := ResolveTenantOwnerRef(ctx, r.Client, ae.Namespace); err == nil && ref != nil {
			patch := client.MergeFrom(ae.DeepCopy())
			ae.OwnerReferences = []metav1.OwnerReference{*ref}
			if perr := r.Patch(ctx, &ae, patch); perr != nil {
				log.Info("ownerRef backfill failed; will retry", "err", perr)
				return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
			}
			log.Info("ownerRef backfilled", "tenant", ref.Name)
		}
	}

	// Explicit revocation via annotation (keep CR for forensics).
	if ae.Annotations[gibsonv1alpha1.RevokeAnnotation] == "true" && ae.Status.Phase != gibsonv1alpha1.AgentEnrollmentPhaseRevoked {
		result, err := r.Runner.Run(ctx, &ae, r.RevocationSteps, string(gibsonv1alpha1.AgentEnrollmentPhaseRevoked))
		_ = r.Status().Update(ctx, &ae)
		return result, err
	}

	// Deletion path.
	if !ae.DeletionTimestamp.IsZero() {
		if !controllerutil.ContainsFinalizer(&ae, gibsonv1alpha1.AgentEnrollmentFinalizer) {
			return ctrl.Result{}, nil
		}
		result, err := r.Runner.Run(ctx, &ae, r.RevocationSteps, string(gibsonv1alpha1.AgentEnrollmentPhaseTerminated))
		_ = r.Status().Update(ctx, &ae)
		if err != nil {
			return result, err
		}
		if result.RequeueAfter > 0 {
			return result, nil
		}
		controllerutil.RemoveFinalizer(&ae, gibsonv1alpha1.AgentEnrollmentFinalizer)
		return ctrl.Result{}, r.Update(ctx, &ae)
	}

	// Ensure finalizer.
	if !controllerutil.ContainsFinalizer(&ae, gibsonv1alpha1.AgentEnrollmentFinalizer) {
		controllerutil.AddFinalizer(&ae, gibsonv1alpha1.AgentEnrollmentFinalizer)
		if err := r.Update(ctx, &ae); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// Run FGA grant issuance saga for pending enrollments.
	if ae.Status.Phase == "" || ae.Status.Phase == gibsonv1alpha1.AgentEnrollmentPhasePending {
		result, err := r.Runner.Run(ctx, &ae, r.IssuanceSteps, string(gibsonv1alpha1.AgentEnrollmentPhaseActive))
		_ = r.Status().Update(ctx, &ae)
		return result, err
	}

	log.V(1).Info("reconciled", "phase", ae.Status.Phase)
	return ctrl.Result{RequeueAfter: time.Minute}, nil
}

func (r *AgentEnrollmentReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.Recorder == nil {
		r.Recorder = mgr.GetEventRecorder("agent-enrollment-controller")
	}
	if r.Runner == nil {
		r.Runner = saga.NewRunner(r.Client, r.Recorder, mgr.GetLogger())
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&gibsonv1alpha1.AgentEnrollment{}).
		Named("agentenrollment").
		Complete(r)
}
