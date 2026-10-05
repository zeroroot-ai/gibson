// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package finalbackup

import (
	"context"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/prometheus/client_golang/prometheus/testutil"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/metrics"
)

const (
	testVeleroNS = "backup-system"
	testTenant   = "acme"
	testUID      = "3b1f6a52-0c58-4d4b-9a59-0d7f3a5d7c11"
)

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatalf("add core scheme: %v", err)
	}
	if err := gibsonv1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("add gibson scheme: %v", err)
	}
	return s
}

func tenantFixture() *gibsonv1alpha1.Tenant {
	return &gibsonv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: testTenant, UID: types.UID(testUID)}}
}

func tenantNamespace() *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: TenantNamespace(testTenant)}}
}

// backupWithPhase is a Backup as Velero leaves it, with the given phase and
// age.
func backupWithPhase(phase string, age time.Duration) *unstructured.Unstructured {
	b := Build(BackupName(tenantFixture()), testVeleroNS, tenantFixture())
	b.SetCreationTimestamp(metav1.NewTime(time.Now().Add(-age)))
	if phase != "" {
		_ = unstructured.SetNestedField(b.Object, phase, "status", "phase")
	}
	return b
}

func newTaker(t *testing.T, c client.Client) *Taker {
	t.Helper()
	taker, err := New(c, testVeleroNS)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return taker
}

func getBackup(t *testing.T, c client.Client) (*unstructured.Unstructured, error) {
	t.Helper()
	b := &unstructured.Unstructured{}
	b.SetGroupVersionKind(backupGVK)
	err := c.Get(context.Background(), client.ObjectKey{Namespace: testVeleroNS, Name: BackupName(tenantFixture())}, b)
	return b, err
}

func TestNew_RequiresBothArguments(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).Build()
	if _, err := New(nil, testVeleroNS); err == nil {
		t.Error("New accepted a nil client")
	}
	if _, err := New(c, ""); err == nil {
		t.Error("New accepted an empty Velero namespace")
	}
}

// The first pass creates the Backup and reports that the flow must wait.
func TestEnsure_CreatesTheBackupAndWaits(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(tenantNamespace()).Build()
	done, err := newTaker(t, c).Ensure(context.Background(), tenantFixture())
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if done {
		t.Fatal("Ensure reported done before a backup completed")
	}
	b, err := getBackup(t, c)
	if err != nil {
		t.Fatalf("the Backup was not created: %v", err)
	}
	if got := b.GetLabels()[LabelTenant]; got != testTenant {
		t.Errorf("label %s = %q, want %q", LabelTenant, got, testTenant)
	}
	if got := b.GetLabels()[LabelBackupType]; got != BackupTypeFinal {
		t.Errorf("label %s = %q, want %q", LabelBackupType, got, BackupTypeFinal)
	}
	if got := b.GetAnnotations()[AnnotationTenantUID]; got != testUID {
		t.Errorf("annotation %s = %q, want %q", AnnotationTenantUID, got, testUID)
	}
	ttl, _, _ := unstructured.NestedString(b.Object, "spec", "ttl")
	if ttl != "720h0m0s" {
		t.Errorf("spec.ttl = %q, want 720h0m0s (30 days)", ttl)
	}
	d, err := time.ParseDuration(ttl)
	if err != nil || d != 30*24*time.Hour {
		t.Errorf("spec.ttl parses to %v (%v), want 30 days", d, err)
	}
	nss, _, _ := unstructured.NestedStringSlice(b.Object, "spec", "includedNamespaces")
	if len(nss) != 1 || nss[0] != "tenant-"+testTenant {
		t.Errorf("spec.includedNamespaces = %v, want the tenant namespace only", nss)
	}
	fs, _, _ := unstructured.NestedBool(b.Object, "spec", "defaultVolumesToFsBackup")
	if !fs {
		t.Error("spec.defaultVolumesToFsBackup is not true, so the backup holds no volume data")
	}
}

// A second pass does not create a second backup.
func TestEnsure_OneBackupForEachDelete(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(tenantNamespace()).Build()
	taker := newTaker(t, c)
	for i := 0; i < 3; i++ {
		if done, err := taker.Ensure(context.Background(), tenantFixture()); err != nil || done {
			t.Fatalf("pass %d: done=%v err=%v, want waiting", i, done, err)
		}
	}
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(backupGVK.GroupVersion().WithKind("BackupList"))
	if err := c.List(context.Background(), list); err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("%d backups exist after three passes, want 1", len(list.Items))
	}
}

// Case 1 of the issue: the backup is complete, so the flow goes on.
func TestEnsure_BackupComplete(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).
		WithObjects(tenantNamespace(), backupWithPhase("Completed", time.Minute)).Build()
	done, err := newTaker(t, c).Ensure(context.Background(), tenantFixture())
	if err != nil || !done {
		t.Fatalf("done=%v err=%v, want done with no error", done, err)
	}
}

// Case 2 of the issue: the backup failed, so the flow stops with an error.
func TestEnsure_BackupFailed(t *testing.T) {
	for _, phase := range []string{"Failed", "PartiallyFailed", "FailedValidation"} {
		t.Run(phase, func(t *testing.T) {
			before := testutil.ToFloat64(metrics.FinalBackupFailures.WithLabelValues("backup_failed"))
			c := fake.NewClientBuilder().WithScheme(testScheme(t)).
				WithObjects(tenantNamespace(), backupWithPhase(phase, time.Minute)).Build()
			done, err := newTaker(t, c).Ensure(context.Background(), tenantFixture())
			if done {
				t.Fatal("Ensure reported done for a failed backup")
			}
			if !errors.Is(err, ErrBackupFailed) {
				t.Fatalf("err = %v, want ErrBackupFailed", err)
			}
			after := testutil.ToFloat64(metrics.FinalBackupFailures.WithLabelValues("backup_failed"))
			if after != before+1 {
				t.Errorf("the failure counter moved by %v, want 1", after-before)
			}
		})
	}
}

// Case 3 of the issue: Velero is not reachable. The API server has no Backup
// kind, or it gives an error. Neither is a reason to go on.
func TestEnsure_VeleroNotReachable(t *testing.T) {
	noKind := &meta.NoKindMatchError{GroupKind: backupGVK.GroupKind(), SearchedVersions: []string{"v1"}}
	cases := map[string]interceptor.Funcs{
		"read fails with no such kind": {
			Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object,
				opts ...client.GetOption) error {
				if obj.GetObjectKind().GroupVersionKind() == backupGVK {
					return noKind
				}
				return c.Get(ctx, key, obj, opts...)
			},
		},
		"create fails": {
			Create: func(context.Context, client.WithWatch, client.Object, ...client.CreateOption) error {
				return errors.New("the API server is not reachable")
			},
		},
	}
	for name, funcs := range cases {
		t.Run(name, func(t *testing.T) {
			c := fake.NewClientBuilder().WithScheme(testScheme(t)).
				WithObjects(tenantNamespace()).WithInterceptorFuncs(funcs).Build()
			done, err := newTaker(t, c).Ensure(context.Background(), tenantFixture())
			if done || err == nil {
				t.Fatalf("done=%v err=%v, want an error and not done", done, err)
			}
		})
	}
}

// A backup that runs is not an error until the time limit.
func TestEnsure_UnfinishedBackup(t *testing.T) {
	for _, phase := range []string{"", "New", "InProgress", "Finalizing"} {
		c := fake.NewClientBuilder().WithScheme(testScheme(t)).
			WithObjects(tenantNamespace(), backupWithPhase(phase, time.Minute)).Build()
		if done, err := newTaker(t, c).Ensure(context.Background(), tenantFixture()); done || err != nil {
			t.Errorf("phase %q after one minute: done=%v err=%v, want waiting", phase, done, err)
		}
	}
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).
		WithObjects(tenantNamespace(), backupWithPhase("InProgress", Timeout+time.Minute)).Build()
	done, err := newTaker(t, c).Ensure(context.Background(), tenantFixture())
	if done || !errors.Is(err, ErrBackupFailed) {
		t.Fatalf("after the time limit: done=%v err=%v, want ErrBackupFailed", done, err)
	}
}

// With no tenant namespace, no data exists. With a namespace in deletion, an
// earlier pass already passed the gate. Neither creates a backup.
func TestEnsure_NothingToBackUp(t *testing.T) {
	now := metav1.Now()
	terminating := tenantNamespace()
	terminating.DeletionTimestamp = &now
	terminating.Finalizers = []string{"kubernetes"}
	cases := map[string][]client.Object{
		"no namespace":          nil,
		"namespace in deletion": {terminating},
	}
	for name, objs := range cases {
		t.Run(name, func(t *testing.T) {
			c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(objs...).Build()
			done, err := newTaker(t, c).Ensure(context.Background(), tenantFixture())
			if err != nil || !done {
				t.Fatalf("done=%v err=%v, want done", done, err)
			}
			if _, gErr := getBackup(t, c); gErr == nil {
				t.Error("a backup was created although no data exists")
			}
		})
	}
}

func TestEnsure_RefusesATenantWithNoUID(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(tenantNamespace()).Build()
	tenant := tenantFixture()
	tenant.UID = ""
	if done, err := newTaker(t, c).Ensure(context.Background(), tenant); done || err == nil {
		t.Fatalf("done=%v err=%v, want an error", done, err)
	}
}
