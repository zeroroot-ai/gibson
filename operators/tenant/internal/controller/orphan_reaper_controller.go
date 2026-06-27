// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package controller

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	gibsonmetrics "github.com/zeroroot-ai/gibson/operators/tenant/internal/metrics"
)

// reaperAllowlist is the hardcoded set of finalizer keys the reaper is
// allowed to strip. Driven from config would be a foot-gun — a misconfigured
// values.yaml could broaden the blast radius.
var reaperAllowlist = map[string]struct{}{
	gibsonv1alpha1.AgentEnrollmentFinalizer: {},
	gibsonv1alpha1.TenantMemberFinalizer:    {},
}

// OrphanReaperReconciler watches Terminating `tenant-*` namespaces and, after
// a configurable grace period, strips allowlisted finalizers from child CRs
// that were orphaned when the saga was bypassed or the operator crashed
// mid-teardown.
type OrphanReaperReconciler struct {
	client.Client
	Recorder           events.EventRecorder
	GracePeriodSeconds int
	Enabled            bool
}

// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=agentenrollments;tenantmembers,verbs=get;list;watch;patch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch

// Reconcile implements the reaper. Reconciled key is a namespace.
func (r *OrphanReaperReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx).WithValues("component", "orphan-reaper", "namespace", req.Name)

	var ns corev1.Namespace
	if err := r.Get(ctx, types.NamespacedName{Name: req.Name}, &ns); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if ns.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}
	if !strings.HasPrefix(ns.Name, "tenant-") {
		return ctrl.Result{}, nil
	}

	grace := time.Duration(r.GracePeriodSeconds) * time.Second
	remaining := grace - time.Since(ns.DeletionTimestamp.Time)
	if remaining > 0 {
		return ctrl.Result{RequeueAfter: remaining}, nil
	}

	// If the parent Tenant still exists, saga is expected to complete; skip.
	tenantName := ns.Annotations[AnnotationOwnerTenantName]
	if tenantName == "" {
		tenantName = strings.TrimPrefix(ns.Name, "tenant-")
	}
	if tenantName != "" {
		var t gibsonv1alpha1.Tenant
		err := r.Get(ctx, types.NamespacedName{Name: tenantName}, &t)
		if err == nil {
			// Parent still exists — do not interfere with saga.
			return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
		}
		if !apierrors.IsNotFound(err) {
			return ctrl.Result{}, fmt.Errorf("get tenant %q: %w", tenantName, err)
		}
	}

	// Parent gone and grace expired — strip allowlisted finalizers.
	kinds := []struct {
		list client.ObjectList
		name string
	}{
		{&gibsonv1alpha1.AgentEnrollmentList{}, "AgentEnrollment"},
		{&gibsonv1alpha1.TenantMemberList{}, "TenantMember"},
	}

	for _, k := range kinds {
		if err := r.List(ctx, k.list, client.InNamespace(ns.Name)); err != nil {
			return ctrl.Result{}, fmt.Errorf("list %s in %s: %w", k.name, ns.Name, err)
		}
		items, err := meta.ExtractList(k.list)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("extract %s: %w", k.name, err)
		}
		for _, raw := range items {
			obj, ok := raw.(client.Object)
			if !ok {
				continue
			}
			if err := r.stripAllowlistedFinalizers(ctx, obj, k.name, &ns); err != nil {
				log.Info("strip finalizers failed; will retry", "kind", k.name, "name", obj.GetName(), "err", err)
			}
		}
	}

	return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
}

// stripAllowlistedFinalizers removes only finalizers whose key is in the
// hardcoded allowlist. Unknown finalizers trigger a warning event — they
// signal operator attention is needed, not brute force.
func (r *OrphanReaperReconciler) stripAllowlistedFinalizers(
	ctx context.Context, obj client.Object, kind string, ns *corev1.Namespace,
) error {
	existing := obj.GetFinalizers()
	if len(existing) == 0 {
		return nil
	}

	kept := make([]string, 0, len(existing))
	removed := make([]string, 0, len(existing))
	for _, f := range existing {
		if _, ok := reaperAllowlist[f]; ok {
			removed = append(removed, f)
			continue
		}
		kept = append(kept, f)
	}

	if len(removed) == 0 {
		// Everything is non-allowlisted — warn and do not strip.
		if len(existing) > 0 && r.Recorder != nil {
			// events.EventRecorder.Eventf signature: (regarding, related,
			// eventtype, reason, action, note, args...).
			r.Recorder.Eventf(ns, nil, corev1.EventTypeWarning, "OrphanFinalizerUnknown", "OrphanFinalizerUnknown",
				"unknown finalizer(s) %v on %s/%s blocking namespace termination; operator action required",
				existing, kind, obj.GetName())
		}
		return nil
	}

	patch := client.MergeFrom(obj.DeepCopyObject().(client.Object))
	obj.SetFinalizers(kept)
	if err := r.Patch(ctx, obj, patch); err != nil {
		return err
	}

	for _, f := range removed {
		gibsonmetrics.OrphanFinalizersStrippedTotal.WithLabelValues(kind, f).Inc()
		if r.Recorder != nil {
			// events.EventRecorder.Eventf signature: (regarding, related,
			// eventtype, reason, action, note, args...).
			r.Recorder.Eventf(ns, nil, corev1.EventTypeWarning, "OrphanFinalizerStripped", "OrphanFinalizerStripped",
				"stripped finalizer %s from %s/%s", f, kind, obj.GetName())
		}
	}
	return nil
}

// terminatingTenantNamespacePredicate accepts only namespace events where the
// namespace name begins with "tenant-". DeletionTimestamp is checked inside
// Reconcile (predicates are consulted for create/update/delete events; we
// want all of them for this resource).
func terminatingTenantNamespacePredicate() predicate.Predicate {
	return predicate.NewPredicateFuncs(func(obj client.Object) bool {
		return strings.HasPrefix(obj.GetName(), "tenant-")
	})
}

// SetupWithManager registers the controller — unless disabled.
func (r *OrphanReaperReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if !r.Enabled {
		return nil
	}
	if r.GracePeriodSeconds <= 0 {
		r.GracePeriodSeconds = 300
	}
	// Start the gauge sampler goroutine tied to the manager's context.
	if err := mgr.Add(sampleTickerRunnable{client: r.Client, grace: time.Duration(r.GracePeriodSeconds) * time.Second}); err != nil {
		return fmt.Errorf("add gauge sampler: %w", err)
	}
	return ctrl.NewControllerManagedBy(mgr).
		Named("orphan-reaper").
		For(&corev1.Namespace{},
			builder.WithPredicates(terminatingTenantNamespacePredicate()),
		).
		Complete(r)
}

// sampleTickerRunnable samples StuckTerminatingNamespaces gauge every 30s.
type sampleTickerRunnable struct {
	client client.Client
	grace  time.Duration
}

func (s sampleTickerRunnable) Start(ctx context.Context) error {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			s.sample(ctx)
		}
	}
}

func (s sampleTickerRunnable) sample(ctx context.Context) {
	var nsList corev1.NamespaceList
	if err := s.client.List(ctx, &nsList); err != nil {
		return
	}
	var stuck int
	now := time.Now()
	for _, ns := range nsList.Items {
		if ns.DeletionTimestamp.IsZero() {
			continue
		}
		if !strings.HasPrefix(ns.Name, "tenant-") {
			continue
		}
		if now.Sub(ns.DeletionTimestamp.Time) > s.grace {
			stuck++
		}
	}
	gibsonmetrics.StuckTerminatingNamespaces.Set(float64(stuck))
}

// discard unused import placeholder (event package is only for type hints in
// future predicates); kept to avoid goimports churn on next edit.
var _ = event.TypedCreateEvent[client.Object]{}
