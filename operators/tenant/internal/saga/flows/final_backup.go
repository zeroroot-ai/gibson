// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package flows

// This file implements the FinalNeo4jBackup step for the tenant teardown
// saga (spec per-tenant-data-plane-completion Task 32).
//
// The step emits a Velero Backup CR named "tenant-<id>-final-<timestamp>"
// annotated with final-backup-before-delete: "true" and a 90-day retention
// label. It polls the Backup until phase == Completed (timeout 30 min).
// On Backup failure or timeout, the step returns an error so the saga
// aborts deprovisioning and retries — data is never deleted if the
// backup has not succeeded.

import (
	"context"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/saga"
)

const (
	// FinalBackupDefaultTimeout is how long the saga step waits for the
	// Velero Backup to reach phase Completed.
	FinalBackupDefaultTimeout = 30 * time.Minute

	// finalBackupPollInterval is the polling frequency while waiting for
	// the Velero Backup phase transition.
	finalBackupPollInterval = 15 * time.Second

	// finalBackupRetentionDays is the gibson.zeroroot.ai/retention-days
	// label value stamped on the final-backup CR.
	finalBackupRetentionDays = "90"

	// veleroNamespace is the namespace where Velero is deployed.
	veleroNamespace = "velero"

	// finalBackupAnnotationKey is the annotation stamped on every Velero
	// Backup CR this saga step creates. The teardown reconciler reads it
	// back to identify "do not delete data plane until this Backup
	// completes" CRs.
	finalBackupAnnotationKey = "final-backup-before-delete"

	// annotationTrueValue is the stringly-typed "true" used wherever
	// Kubernetes annotations represent a boolean flag.
	annotationTrueValue = "true"
)

// veleroBackupGVR is the GroupVersionResource for Velero Backup objects.
var veleroBackupGVR = schema.GroupVersionResource{
	Group:    "velero.io",
	Version:  "v1",
	Resource: "backups",
}

// FinalBackupDeps carries the dependencies needed by the final-backup step.
type FinalBackupDeps struct {
	// K8sClient is the controller-runtime client. Required.
	K8sClient client.Client

	// Namespace is the namespace where Velero Backup CRs are created.
	// Defaults to "velero" when empty.
	Namespace string

	// Timeout overrides FinalBackupDefaultTimeout when non-zero.
	Timeout time.Duration

	// VeleroEnabled controls whether the step runs. When false (no Velero
	// install detected) the step is a no-op so the teardown saga still
	// completes on clusters without Velero.
	VeleroEnabled bool
}

// finalBackupStep creates a Velero Backup CR for the tenant and waits for
// it to reach Completed phase before returning.
type finalBackupStep struct {
	saga.StepBase
	deps FinalBackupDeps
}

func newFinalBackupStep(deps FinalBackupDeps) *finalBackupStep {
	return &finalBackupStep{
		StepBase: saga.StepBase{
			N: "FinalNeo4jBackup",
			C: "FinalNeo4jBackupComplete",
			// No Req — this is the first step in TeardownSteps; it must
			// complete before any data-plane teardown runs.
			Caps:  []saga.ClientCapability{saga.CapabilityKubernetes},
			Owner: "platform-neo4j",
			// Velero Backup polling timeout is FinalBackupDefaultTimeout
			// (30 minutes). Most healthy tenants complete in well under
			// a minute, but the SLA tracks the worst-case window the
			// step is willing to wait for.
			P99: FinalBackupDefaultTimeout,
		},
		deps: deps,
	}
}

func (s *finalBackupStep) Provision(ctx context.Context, obj saga.ConditionedObject, _ *saga.Deps) (bool, error) {
	t, err := tenantOf(obj)
	if err != nil {
		return false, err
	}

	if s.deps.K8sClient == nil || !s.deps.VeleroEnabled {
		// No Velero install — skip gracefully so non-Velero deployments
		// (local dev kind without Velero) can still tear down tenants.
		return true, nil
	}

	ns := s.deps.Namespace
	if ns == "" {
		ns = veleroNamespace
	}
	timeout := s.deps.Timeout
	if timeout <= 0 {
		timeout = FinalBackupDefaultTimeout
	}

	// --- Idempotency check ---
	existing, err := findCompletedFinalBackup(ctx, s.deps.K8sClient, ns, t.Name)
	if err != nil {
		return false, fmt.Errorf("finalBackupStep: check existing backup: %w", err)
	}
	if existing != "" {
		return true, nil
	}

	// --- Create Backup CR ---
	backupName := fmt.Sprintf("tenant-%s-final-%d", t.Name, metav1.Now().Unix())
	backup := buildVeleroBackup(backupName, ns, t.Name)

	if createErr := s.deps.K8sClient.Create(ctx, backup); createErr != nil {
		if !errors.IsAlreadyExists(createErr) {
			return false, fmt.Errorf("finalBackupStep: create Backup %q: %w", backupName, createErr)
		}
	}

	// --- Poll until Completed or timeout ---
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if err := wait.PollUntilContextTimeout(timeoutCtx, finalBackupPollInterval, timeout, true,
		func(ctx context.Context) (bool, error) {
			phase, err := getBackupPhase(ctx, s.deps.K8sClient, ns, backupName)
			if err != nil {
				if errors.IsNotFound(err) {
					return false, nil
				}
				return false, err
			}
			switch phase {
			case "Completed":
				return true, nil
			case "Failed", "PartiallyFailed":
				return false, fmt.Errorf("finalBackupStep: Velero Backup %q entered phase %q", backupName, phase)
			}
			return false, nil
		},
	); err != nil {
		return false, fmt.Errorf("finalBackupStep: waiting for Backup %q: %w", backupName, err)
	}

	return true, nil
}

// buildVeleroBackup constructs an unstructured Velero Backup CR with the
// 90-day retention label and final-backup annotation.
func buildVeleroBackup(name, namespace, tenantID string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "velero.io",
		Version: "v1",
		Kind:    "Backup",
	})
	u.SetName(name)
	u.SetNamespace(namespace)
	u.SetAnnotations(map[string]string{
		finalBackupAnnotationKey:    annotationTrueValue,
		"gibson.zeroroot.ai/tenant": tenantID,
	})
	u.SetLabels(map[string]string{
		"gibson.zeroroot.ai/retention-days": finalBackupRetentionDays,
		"gibson.zeroroot.ai/tenant":         tenantID,
		"gibson.zeroroot.ai/backup-type":    "final",
	})

	_ = unstructured.SetNestedMap(u.Object, map[string]any{
		"includedNamespaces": []any{"*"},
		"labelSelector": map[string]any{
			"matchLabels": map[string]any{
				"gibson.zeroroot.ai/tenant": tenantID,
			},
		},
		"storageLocation": "default",
		"ttl":             fmt.Sprintf("%dh", 90*24),
	}, "spec")

	return u
}

// findCompletedFinalBackup returns the name of the first Velero Backup
// that has both the "final-backup-before-delete: true" annotation and
// status.phase == "Completed" for the given tenant.
func findCompletedFinalBackup(ctx context.Context, c client.Client, namespace, tenantID string) (string, error) {
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "velero.io",
		Version: "v1",
		Kind:    "BackupList",
	})
	if err := c.List(ctx, list,
		client.InNamespace(namespace),
		client.MatchingLabels{
			"gibson.zeroroot.ai/tenant":      tenantID,
			"gibson.zeroroot.ai/backup-type": "final",
		},
	); err != nil {
		if isCRDNotFound(err) {
			return "", nil
		}
		return "", err
	}

	for _, item := range list.Items {
		ann := item.GetAnnotations()
		if ann[finalBackupAnnotationKey] != annotationTrueValue {
			continue
		}
		phase, _, _ := unstructured.NestedString(item.Object, "status", "phase")
		if phase == "Completed" {
			return item.GetName(), nil
		}
	}
	return "", nil
}

// getBackupPhase returns the Velero Backup's status.phase value.
func getBackupPhase(ctx context.Context, c client.Client, namespace, name string) (string, error) {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "velero.io",
		Version: "v1",
		Kind:    "Backup",
	})
	if err := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, u); err != nil {
		return "", err
	}
	phase, _, _ := unstructured.NestedString(u.Object, "status", "phase")
	return phase, nil
}

// ExportedFinalBackupStep is the exported shim used by package-external
// tests to exercise the step in isolation.
func ExportedFinalBackupStep(deps FinalBackupDeps) saga.Step {
	return newFinalBackupStep(deps)
}

// ExportedBuildVeleroBackup is the exported test shim for buildVeleroBackup.
func ExportedBuildVeleroBackup(name, namespace, tenantID string) *unstructured.Unstructured {
	return buildVeleroBackup(name, namespace, tenantID)
}

// isCRDNotFound returns true when the error indicates the Velero Backup
// CRD has not been installed.
func isCRDNotFound(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return contains(msg, "no kind is registered") ||
		contains(msg, "no matches for kind") ||
		contains(msg, "the server could not find the requested resource")
}

// contains is a simple substring check.
func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}())
}

// keep veleroBackupGVR referenced (used by older code paths and tests).
var _ = veleroBackupGVR

// Tenant ConditionedObject conformance check.
var _ saga.ConditionedObject = (*gibsonv1alpha1.Tenant)(nil)
