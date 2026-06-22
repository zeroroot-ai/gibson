/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package flows_test

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/saga/flows"
)

// veleroBackupGVK is the GroupVersionKind used for Velero Backup objects in tests.
var veleroBackupGVK = schema.GroupVersionKind{
	Group:   "velero.io",
	Version: "v1",
	Kind:    "Backup",
}

// buildTestScheme returns a scheme that includes the Velero Backup GVK as an
// unstructured type so the fake client can handle Backup objects.
func buildTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := gibsonv1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("add gibson scheme: %v", err)
	}
	return s
}

// newFakeTenant returns a minimal Tenant CR for use in tests.
func newFakeTenant(name string) *gibsonv1alpha1.Tenant {
	return &gibsonv1alpha1.Tenant{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: gibsonv1alpha1.TenantSpec{
			DisplayName: name,
			Owner:       "owner@example.com",
			Tier:        gibsonv1alpha1.TenantPlanTeam,
		},
	}
}

// TestFinalBackupStep_VeleroDisabled verifies that when VeleroEnabled is
// false, the step returns (done=true, nil) without attempting any API calls.
func TestFinalBackupStep_VeleroDisabled(t *testing.T) {
	scheme := buildTestScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()

	deps := flows.FinalBackupDeps{
		K8sClient:     c,
		Namespace:     "velero",
		VeleroEnabled: false,
		Timeout:       5 * time.Second,
	}

	tenant := newFakeTenant("tenant-alpha")
	step := flows.ExportedFinalBackupStep(deps)

	done, err := step.Provision(context.Background(), tenant, nil)
	if err != nil {
		t.Fatalf("expected no error when Velero disabled, got: %v", err)
	}
	if !done {
		t.Fatal("expected done=true when Velero disabled")
	}
}

// TestFinalBackupStep_NilK8sClient verifies that a nil K8sClient is treated
// as "Velero not available" and returns done=true without panicking.
func TestFinalBackupStep_NilK8sClient(t *testing.T) {
	deps := flows.FinalBackupDeps{
		K8sClient:     nil,
		VeleroEnabled: true,
	}
	tenant := newFakeTenant("tenant-beta")
	step := flows.ExportedFinalBackupStep(deps)

	done, err := step.Provision(context.Background(), tenant, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !done {
		t.Fatal("expected done=true when K8sClient is nil")
	}
}

// TestFinalBackupStep_IdempotentCompletedBackup verifies that when a Completed
// final-backup Backup CR already exists, the step returns done=true without
// creating another Backup.
func TestFinalBackupStep_IdempotentCompletedBackup(t *testing.T) {
	scheme := buildTestScheme(t)

	// Pre-create a Completed Backup so the idempotency check fires.
	existingBackup := &unstructured.Unstructured{}
	existingBackup.SetGroupVersionKind(veleroBackupGVK)
	existingBackup.SetName("tenant-gamma-final-1234567890")
	existingBackup.SetNamespace("velero")
	existingBackup.SetAnnotations(map[string]string{
		"final-backup-before-delete": "true",
	})
	existingBackup.SetLabels(map[string]string{
		"gibson.zeroroot.ai/tenant":      "gamma",
		"gibson.zeroroot.ai/backup-type": "final",
	})
	_ = unstructured.SetNestedField(existingBackup.Object, "Completed", "status", "phase")

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(existingBackup).
		Build()

	deps := flows.FinalBackupDeps{
		K8sClient:     c,
		Namespace:     "velero",
		VeleroEnabled: true,
		Timeout:       5 * time.Second,
	}

	tenant := newFakeTenant("gamma")
	step := flows.ExportedFinalBackupStep(deps)

	done, err := step.Provision(context.Background(), tenant, nil)
	if err != nil {
		t.Fatalf("expected no error on idempotent check, got: %v", err)
	}
	if !done {
		t.Fatal("expected done=true when completed backup exists")
	}

	// Verify no additional Backup was created.
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(schema.GroupVersionKind{
		Group: "velero.io", Version: "v1", Kind: "BackupList",
	})
	_ = c.List(context.Background(), list, client.InNamespace("velero"))
	if len(list.Items) != 1 {
		t.Errorf("expected 1 Backup (no new creation), got %d", len(list.Items))
	}
}

// TestFinalBackupStep_CreatesBackupWithCorrectFields verifies that the step
// creates a Backup CR with the correct annotations/labels when a
// pre-completed final backup already exists (idempotent path). The backing
// store for Velero Backup status phase is pre-populated to simulate Velero
// having completed the backup before polling begins.
func TestFinalBackupStep_CreatesBackupWithCorrectFields(t *testing.T) {
	scheme := buildTestScheme(t)

	// Pre-seed a Completed Backup so the idempotency check fires and
	// the step returns done=true without needing to poll.
	existingBackup := &unstructured.Unstructured{}
	existingBackup.SetGroupVersionKind(veleroBackupGVK)
	existingBackup.SetName("tenant-delta-final-111")
	existingBackup.SetNamespace("velero")
	existingBackup.SetAnnotations(map[string]string{
		"final-backup-before-delete": "true",
		"gibson.zeroroot.ai/tenant":  "delta",
	})
	existingBackup.SetLabels(map[string]string{
		"gibson.zeroroot.ai/tenant":         "delta",
		"gibson.zeroroot.ai/backup-type":    "final",
		"gibson.zeroroot.ai/retention-days": "90",
	})
	_ = unstructured.SetNestedField(existingBackup.Object, "Completed", "status", "phase")

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(existingBackup).
		Build()

	deps := flows.FinalBackupDeps{
		K8sClient:     c,
		Namespace:     "velero",
		VeleroEnabled: true,
		Timeout:       5 * time.Second,
	}

	tenant := newFakeTenant("delta")
	step := flows.ExportedFinalBackupStep(deps)
	done, err := step.Provision(context.Background(), tenant, nil)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if !done {
		t.Fatal("expected done=true when completed backup exists")
	}

	// Verify the pre-existing Backup has the correct fields.
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(schema.GroupVersionKind{
		Group: "velero.io", Version: "v1", Kind: "BackupList",
	})
	_ = c.List(context.Background(), list, client.InNamespace("velero"))
	if len(list.Items) == 0 {
		t.Fatal("expected at least one Backup CR to exist")
	}
	b := list.Items[0]
	if b.GetAnnotations()["final-backup-before-delete"] != "true" {
		t.Error("missing final-backup-before-delete annotation")
	}
	if b.GetLabels()["gibson.zeroroot.ai/retention-days"] != "90" {
		t.Errorf("expected retention-days=90, got %q", b.GetLabels()["gibson.zeroroot.ai/retention-days"])
	}
	if b.GetLabels()["gibson.zeroroot.ai/tenant"] != "delta" {
		t.Errorf("expected tenant label=delta, got %q", b.GetLabels()["gibson.zeroroot.ai/tenant"])
	}
}

// TestBuildVeleroBackup_Fields exercises the buildVeleroBackup helper
// (exported for test) to validate the structure of the generated CR.
func TestBuildVeleroBackup_Fields(t *testing.T) {
	b := flows.ExportedBuildVeleroBackup("my-backup", "velero", "epsilon")

	if b.GetName() != "my-backup" {
		t.Errorf("expected name my-backup, got %q", b.GetName())
	}
	if b.GetNamespace() != "velero" {
		t.Errorf("expected namespace velero, got %q", b.GetNamespace())
	}
	if b.GetAnnotations()["final-backup-before-delete"] != "true" {
		t.Error("missing final-backup-before-delete annotation")
	}
	if b.GetLabels()["gibson.zeroroot.ai/retention-days"] != "90" {
		t.Errorf("expected retention-days=90, got %q", b.GetLabels()["gibson.zeroroot.ai/retention-days"])
	}
	// Verify the Velero spec includes the TTL for 90 days.
	ttl, _, _ := unstructured.NestedString(b.Object, "spec", "ttl")
	if ttl != "2160h" {
		t.Errorf("expected TTL 2160h, got %q", ttl)
	}
}
