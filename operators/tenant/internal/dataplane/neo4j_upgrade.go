// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package dataplane

import (
	"context"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tenantns "github.com/zeroroot-ai/gibson/operators/tenant/internal/tenant"
)

const (
	// neo4jUpgradeReadyTimeout is the maximum time to wait for a StatefulSet
	// to reach readyReplicas == replicas after an image update.
	neo4jUpgradeReadyTimeout = 10 * time.Minute

	// neo4jUpgradePollInterval is how frequently readiness is polled during upgrade.
	neo4jUpgradePollInterval = 5 * time.Second
)

// TargetNeo4jImage reads the current target Neo4j image tag from the
// tenant-neo4j-template ConfigMap. Returns an empty string when the ConfigMap
// is absent (no upgrade needed — operator is running pre-chart-22 bootstrap).
//
// The ConfigMap is expected to carry the annotation
// "gibson.zeroroot.ai/neo4j-image" set by Helm chart Task 22 so the upgrade
// controller can detect a version bump without parsing the full template YAML.
func (n *Neo4jProvisioner) TargetNeo4jImage(ctx context.Context) (string, error) {
	var cm corev1.ConfigMap
	if err := n.cfg.K8sClient.Get(ctx, types.NamespacedName{
		Name:      neo4jTemplateConfigMapName,
		Namespace: neo4jTemplateNamespace,
	}, &cm); err != nil {
		// ConfigMap absent — no target version available yet.
		return "", client.IgnoreNotFound(err)
	}
	// Prefer the annotation; fall back to the label for compat.
	img := cm.Annotations["gibson.zeroroot.ai/neo4j-image"]
	if img == "" {
		img = cm.Labels["gibson.zeroroot.ai/neo4j-image"]
	}
	return img, nil
}

// ReconcileNeo4jUpgrade upgrades a single tenant's Neo4j StatefulSet to the
// targetImage. It is idempotent: if the StatefulSet already runs targetImage
// the method returns immediately. After patching the image, it polls for
// readyReplicas == spec.replicas with a 10-minute timeout.
//
// Called by the NeoJ4UpgradeController (Task 30) once per tenant during a
// rolling upgrade triggered by a tenant-neo4j-template ConfigMap change.
func (n *Neo4jProvisioner) ReconcileNeo4jUpgrade(ctx context.Context, tenantID, targetImage string) error {
	if targetImage == "" {
		return nil
	}
	names, err := tenantNames(tenantID)
	if err != nil {
		return fmt.Errorf("neo4j upgrade: sanitize tenantID %q: %w", tenantID, err)
	}

	// Resolve the per-tenant namespace where the Neo4j StatefulSet lives.
	// Provision() creates resources in tenant.Status.Namespace (the per-
	// tenant Role grants verbs there); the upgrade path must target the
	// same namespace.
	tenantNS, nsErr := tenantns.NamespaceFor(ctx, n.cfg.K8sClient, tenantID)
	if nsErr != nil {
		return fmt.Errorf("neo4j upgrade: resolve namespace: %w", nsErr)
	}

	stsName := names.Neo4jStatefulSet()
	var sts appsv1.StatefulSet
	if err := n.cfg.K8sClient.Get(ctx, types.NamespacedName{Name: stsName, Namespace: tenantNS}, &sts); err != nil {
		return client.IgnoreNotFound(err)
	}

	// Find the neo4j container and check if the image already matches.
	containerIdx := -1
	for i, c := range sts.Spec.Template.Spec.Containers {
		if c.Name == "neo4j" {
			containerIdx = i
			break
		}
	}
	if containerIdx == -1 {
		return fmt.Errorf("neo4j upgrade: StatefulSet %q has no container named \"neo4j\"", stsName)
	}
	if sts.Spec.Template.Spec.Containers[containerIdx].Image == targetImage {
		// Already up-to-date; nothing to do.
		return nil
	}

	// Patch the container image.
	patch := client.MergeFrom(sts.DeepCopy())
	sts.Spec.Template.Spec.Containers[containerIdx].Image = targetImage
	if err := n.cfg.K8sClient.Patch(ctx, &sts, patch); err != nil {
		return fmt.Errorf("neo4j upgrade: patch StatefulSet %q: %w", stsName, err)
	}

	// Wait until the rolling update completes (readyReplicas reaches the
	// desired replica count).
	replicas := int32(1)
	if sts.Spec.Replicas != nil {
		replicas = *sts.Spec.Replicas
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, neo4jUpgradeReadyTimeout)
	defer cancel()

	return wait.PollUntilContextTimeout(timeoutCtx, neo4jUpgradePollInterval, neo4jUpgradeReadyTimeout, true,
		func(ctx context.Context) (bool, error) {
			var current appsv1.StatefulSet
			if err := n.cfg.K8sClient.Get(ctx,
				types.NamespacedName{Name: stsName, Namespace: tenantNS}, &current); err != nil {
				return false, err
			}
			return current.Status.ReadyReplicas >= replicas &&
				current.Status.CurrentRevision == current.Status.UpdateRevision, nil
		},
	)
}
