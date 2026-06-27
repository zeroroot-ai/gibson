// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

// Package controller contains the tenant-operator reconcilers.
//
// This file implements the Neo4jUpgradeReconciler (spec
// per-tenant-data-plane-completion Task 30). It watches the
// tenant-neo4j-template ConfigMap for image tag changes and performs a
// sequential rolling upgrade of every tenant's Neo4j StatefulSet.
package controller

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
)

const (
	// neo4jUpgradeDefaultConcurrency is the number of tenants upgraded in
	// parallel when .Values.tenantNeo4j.upgradeConcurrency is unset.
	neo4jUpgradeDefaultConcurrency = 1

	// neo4jUpgradeMaxConcurrency is the hard upper bound accepted from config.
	neo4jUpgradeMaxConcurrency = 5

	// neo4jTemplateName is the ConfigMap watched for image-tag changes.
	neo4jTemplateName = "tenant-neo4j-template"

	// neo4jTemplateNS is the namespace where the ConfigMap lives.
	neo4jTemplateNS = "gibson"

	// annotationNeo4jCurrentImage is stored on the operator's own Namespace
	// (or any convenient object) to remember which image version was last
	// rolled. The controller compares the ConfigMap annotation against this
	// value to decide whether to trigger a rollout.
	annotationNeo4jCurrentImage = "gibson.zeroroot.ai/neo4j-current-image"
)

// Neo4jUpgradeProvisioner is the subset of neo4jProvisioner methods used by
// the upgrade controller. Defined as an interface for testability.
type Neo4jUpgradeProvisioner interface {
	// TargetNeo4jImage reads the current target image from the
	// tenant-neo4j-template ConfigMap annotation.
	TargetNeo4jImage(ctx context.Context) (string, error)

	// ReconcileNeo4jUpgrade upgrades a single tenant's StatefulSet to the
	// given image and waits for readiness.
	ReconcileNeo4jUpgrade(ctx context.Context, tenantID, targetImage string) error
}

// Neo4jUpgradeReconciler watches the tenant-neo4j-template ConfigMap and,
// when the ConfigMap's "gibson.zeroroot.ai/neo4j-image" annotation changes, iterates
// over all Tenant CRDs in name-sorted order and upgrades each tenant's Neo4j
// StatefulSet sequentially (or with limited concurrency).
//
// The concurrency limit is read from the UpgradeConcurrency field (default 1,
// max 5) so a kind cluster never gets all its Neo4j pods restarted at once.
type Neo4jUpgradeReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// Provisioner is the Neo4j upgrade implementation. Typically a
	// *dataplane.neo4jProvisioner. Required.
	Provisioner Neo4jUpgradeProvisioner

	// UpgradeConcurrency controls how many tenants are upgraded in parallel.
	// 0 or negative values are treated as 1; values > 5 are capped at 5.
	// Sourced from .Values.tenantNeo4j.upgradeConcurrency in the Helm chart.
	UpgradeConcurrency int

	// mu serialises concurrent reconcile calls so multiple ConfigMap update
	// events don't launch parallel upgrade loops.
	mu sync.Mutex
}

// kubebuilder:rbac markers — Spec secrets-blast-radius-reduction
// configmaps + statefulsets are NOT cluster-scope. The neo4j-upgrade
// controller watches the tenant-neo4j-template ConfigMap (release
// namespace, granted via the release-namespace Role) and StatefulSets
// in tenant namespaces (granted via the per-tenant Role written by
// NamespaceProvisioner). Cluster-scope markers for these resources
// have been removed; access is granted at the appropriate scope by the
// chart's release-namespace-rbac.yaml + the runtime per-tenant Role.
// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=tenants,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=tenants/status,verbs=get;update;patch

// Reconcile is triggered whenever the tenant-neo4j-template ConfigMap is
// created or updated. It reads the target image from the ConfigMap annotation,
// compares against the last-applied image stored in the ConfigMap's own
// annotation, and performs a rolling upgrade of all tenants if there is a
// difference.
func (r *Neo4jUpgradeReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx).WithValues("controller", "neo4j-upgrade")

	// Only handle the template ConfigMap. The watch predicate should already
	// filter, but guard defensively.
	if req.Name != neo4jTemplateName || req.Namespace != neo4jTemplateNS {
		return ctrl.Result{}, nil
	}

	targetImage, err := r.Provisioner.TargetNeo4jImage(ctx)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("neo4j upgrade: read target image: %w", err)
	}
	if targetImage == "" {
		log.Info("tenant-neo4j-template ConfigMap has no gibson.zeroroot.ai/neo4j-image annotation; skipping upgrade")
		return ctrl.Result{}, nil
	}

	// Read the last-applied image tag from a well-known annotation on the
	// ConfigMap itself (written back by this controller after each upgrade).
	var cm corev1.ConfigMap
	if err := r.Get(ctx, req.NamespacedName, &cm); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	lastApplied := cm.Annotations[annotationNeo4jCurrentImage]
	if lastApplied == targetImage {
		log.V(1).Info("all tenants already at target image; no upgrade needed", "image", targetImage)
		return ctrl.Result{}, nil
	}

	log.Info("neo4j image change detected; starting rolling upgrade",
		"from", lastApplied, "to", targetImage)

	// Serialise against concurrent reconcile calls (e.g. multiple rapid
	// updates to the ConfigMap).
	if !r.mu.TryLock() {
		log.Info("upgrade loop already in progress; requeuing")
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}
	defer r.mu.Unlock()

	if err := r.runRollingUpgrade(ctx, targetImage); err != nil {
		return ctrl.Result{RequeueAfter: 30 * time.Second}, err
	}

	// Record the applied image on the ConfigMap annotation so the next
	// reconcile can skip.
	patch := client.MergeFrom(cm.DeepCopy())
	if cm.Annotations == nil {
		cm.Annotations = map[string]string{}
	}
	cm.Annotations[annotationNeo4jCurrentImage] = targetImage
	if patchErr := r.Patch(ctx, &cm, patch); patchErr != nil {
		log.Error(patchErr, "failed to update current-image annotation on ConfigMap")
	}

	log.Info("rolling upgrade complete", "image", targetImage)
	return ctrl.Result{}, nil
}

// runRollingUpgrade lists all Tenant CRDs, sorts them by name for
// determinism, and upgrades them concurrently up to the configured limit.
func (r *Neo4jUpgradeReconciler) runRollingUpgrade(ctx context.Context, targetImage string) error {
	log := logf.FromContext(ctx)

	var tenantList gibsonv1alpha1.TenantList
	if err := r.List(ctx, &tenantList); err != nil {
		return fmt.Errorf("neo4j upgrade: list tenants: %w", err)
	}

	// Sort by name for deterministic rollout order.
	tenants := make([]gibsonv1alpha1.Tenant, len(tenantList.Items))
	copy(tenants, tenantList.Items)
	sort.Slice(tenants, func(i, j int) bool {
		return tenants[i].Name < tenants[j].Name
	})

	concurrency := r.concurrencyLimit()
	log.Info("rolling upgrade parameters",
		"tenantCount", len(tenants),
		"concurrency", concurrency,
		"targetImage", targetImage)

	// Channel-based worker pool. Each tenant is dispatched to the pool;
	// workers process tenants sequentially within each worker slot.
	work := make(chan gibsonv1alpha1.Tenant, len(tenants))
	for _, t := range tenants {
		work <- t
	}
	close(work)

	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		errors []error
	)

	for range concurrency {
		wg.Go(func() {
			for t := range work {
				if err := r.upgradeOneTenant(ctx, t, targetImage); err != nil {
					mu.Lock()
					errors = append(errors, err)
					mu.Unlock()
				}
			}
		})
	}
	wg.Wait()

	if len(errors) > 0 {
		return fmt.Errorf("neo4j rolling upgrade: %d tenant(s) failed: %v", len(errors), errors[0])
	}
	return nil
}

// upgradeOneTenant sets the Neo4jUpgrading condition on the Tenant CRD,
// delegates to the provisioner's ReconcileNeo4jUpgrade, and then clears the
// condition.
func (r *Neo4jUpgradeReconciler) upgradeOneTenant(ctx context.Context, t gibsonv1alpha1.Tenant, targetImage string) error {
	log := logf.FromContext(ctx).WithValues("tenant", t.Name, "targetImage", targetImage)
	log.Info("upgrading tenant neo4j")

	// Mark upgrading.
	if err := r.setUpgradingCondition(ctx, &t, true, ""); err != nil {
		log.Error(err, "failed to set Neo4jUpgrading condition (continuing)")
	}

	upgradeErr := r.Provisioner.ReconcileNeo4jUpgrade(ctx, t.Name, targetImage)

	// Clear the condition regardless of outcome; record failure reason.
	reason := "UpgradeComplete"
	if upgradeErr != nil {
		reason = "UpgradeFailed"
		log.Error(upgradeErr, "tenant neo4j upgrade failed")
	}
	if err := r.setUpgradingCondition(ctx, &t, false, reason); err != nil {
		log.Error(err, "failed to clear Neo4jUpgrading condition")
	}

	return upgradeErr
}

// setUpgradingCondition writes the Neo4jUpgrading condition on the Tenant CR.
// upgrading=true → condition Status=True; false → condition Status=False.
func (r *Neo4jUpgradeReconciler) setUpgradingCondition(ctx context.Context, t *gibsonv1alpha1.Tenant, upgrading bool, reason string) error {
	// Re-fetch to get the latest ResourceVersion before patching status.
	var latest gibsonv1alpha1.Tenant
	if err := r.Get(ctx, client.ObjectKeyFromObject(t), &latest); err != nil {
		return err
	}

	status := metav1.ConditionFalse
	msg := "Neo4j StatefulSet is at the target image version"
	if upgrading {
		status = metav1.ConditionTrue
		msg = "Rolling upgrade of Neo4j StatefulSet in progress"
		reason = "Upgrading"
	}
	if reason == "" {
		reason = "Unknown"
	}

	meta.SetStatusCondition(&latest.Status.Conditions, metav1.Condition{
		Type:               gibsonv1alpha1.ConditionNeo4jUpgrading,
		Status:             status,
		ObservedGeneration: latest.Generation,
		LastTransitionTime: metav1.Now(),
		Reason:             reason,
		Message:            msg,
	})
	return r.Status().Update(ctx, &latest)
}

// concurrencyLimit returns the validated concurrency value.
func (r *Neo4jUpgradeReconciler) concurrencyLimit() int {
	c := r.UpgradeConcurrency
	if c <= 0 {
		c = neo4jUpgradeDefaultConcurrency
	}
	if c > neo4jUpgradeMaxConcurrency {
		c = neo4jUpgradeMaxConcurrency
	}
	return c
}

// SetupWithManager registers the reconciler with the manager. It watches the
// tenant-neo4j-template ConfigMap using a name-filtered predicate so only
// changes to that specific object trigger reconciliation.
func (r *Neo4jUpgradeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Predicate: only fire for the specific ConfigMap we care about.
	nameFilter := predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return e.Object.GetName() == neo4jTemplateName &&
				e.Object.GetNamespace() == neo4jTemplateNS
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			return e.ObjectNew.GetName() == neo4jTemplateName &&
				e.ObjectNew.GetNamespace() == neo4jTemplateNS
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return false // deletion of the template is a chart concern, not an upgrade
		},
		GenericFunc: func(e event.GenericEvent) bool {
			return false
		},
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.ConfigMap{}, builder.WithPredicates(nameFilter)).
		Named("neo4j-upgrade").
		Complete(r)
}

// The Neo4jUpgradeProvisioner interface is satisfied by any concrete dataplane
// provisioner that exports TargetNeo4jImage and ReconcileNeo4jUpgrade.
// cmd/main.go constructs a *dataplane.Neo4jProvisioner (exported wrapper) and
// passes it directly since it satisfies the interface.
