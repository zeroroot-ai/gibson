// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package finalbackup

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/zeroroot-ai/gibson/operators/internal/audit"
	"github.com/zeroroot-ai/gibson/operators/internal/audit/audittest"
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

// testTemplate is the backup template of the shipped Schedule, in the shape
// the chart renders (helm/gibson-velero templates/schedule.yaml).
func testTemplate() map[string]any {
	return map[string]any{
		"includedNamespaces":               []any{"gibson", "tenant-*"},
		"includedNamespaceScopedResources": []any{"*"},
		"excludedNamespaceScopedResources": []any{
			"secrets", "*.generators.external-secrets.io", "*.helm.cattle.io", "*.k3s.cattle.io",
			"ciliumendpoints.cilium.io",
		},
		"includedClusterScopedResources": []any{"tenants.gibson.zeroroot.ai"},
		"defaultVolumesToFsBackup":       true,
		"storageLocation":                "default",
		"ttl":                            "4320h0m0s",
		"hooks": map[string]any{"resources": []any{map[string]any{
			"name": "tenant-neo4j-checkpoint",
		}}},
	}
}

// scheduleFixture is the Schedule the chart ships in the Velero namespace.
func scheduleFixture() *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(scheduleGVK)
	u.SetNamespace(testVeleroNS)
	u.SetName(ScheduleName)
	u.Object["spec"] = map[string]any{"schedule": "0 * * * *", "template": testTemplate()}
	return u
}

// backupWithPhase is a Backup as Velero leaves it, with the given phase and
// age.
func backupWithPhase(phase string, age time.Duration) *unstructured.Unstructured {
	b := Build(BackupName(tenantFixture()), testVeleroNS, tenantFixture(), testTemplate())
	b.SetCreationTimestamp(metav1.NewTime(time.Now().Add(-age)))
	if phase != "" {
		_ = unstructured.SetNestedField(b.Object, phase, "status", "phase")
	}
	return b
}

func newTaker(t *testing.T, c client.Client) *Taker {
	t.Helper()
	return newTakerWithSink(t, c, &audittest.Sink{})
}

func newTakerWithSink(t *testing.T, c client.Client, sink *audittest.Sink) *Taker {
	t.Helper()
	taker, err := New(c, testVeleroNS, sink.Emitter(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return taker
}

// getBackup returns the last backup of the test tenant, or false when it does
// not exist.
func getBackup(t *testing.T, c client.Client) (*unstructured.Unstructured, bool) {
	t.Helper()
	b := &unstructured.Unstructured{}
	b.SetGroupVersionKind(backupGVK)
	err := c.Get(context.Background(), client.ObjectKey{Namespace: testVeleroNS, Name: BackupName(tenantFixture())}, b)
	if apierrors.IsNotFound(err) {
		return nil, false
	}
	if err != nil {
		t.Fatalf("get the Backup: %v", err)
	}
	return b, true
}

func TestNew_RequiresEachArgument(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).Build()
	em := (&audittest.Sink{}).Emitter(t)
	if _, err := New(nil, testVeleroNS, em); err == nil {
		t.Error("New accepted a nil client")
	}
	if _, err := New(c, "", em); err == nil {
		t.Error("New accepted an empty Velero namespace")
	}
	if _, err := New(c, testVeleroNS, nil); !errors.Is(err, audit.ErrNoSink) {
		t.Errorf("New with no audit emitter = %v, want ErrNoSink", err)
	}
}

// The audit record of the backup is written before the Backup exists
// (gibson#583).
func TestEnsure_RecordsBeforeTheBackup(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(tenantNamespace(), scheduleFixture()).Build()
	existedAtRecord := true
	sink := &audittest.Sink{OnEmit: func(audit.Event) { _, existedAtRecord = getBackup(t, c) }}
	if _, err := newTakerWithSink(t, c, sink).Ensure(context.Background(), tenantFixture()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if existedAtRecord {
		t.Error("the Backup existed when its audit record was written")
	}
	got := sink.Events()
	if len(got) != 1 || got[0].Action != audit.ActionLastBackup || got[0].TenantID != tenantFixture().Name ||
		got[0].TargetType != "tenant" || got[0].TargetID != tenantFixture().Name || got[0].Result != "" {
		t.Fatalf("records = %+v", got)
	}
	if _, ok := getBackup(t, c); !ok {
		t.Fatal("no Backup after the record")
	}
}

// With no audit record there is no Backup, and the delete flow stops.
func TestEnsure_NoRecordNoBackup(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(tenantNamespace(), scheduleFixture()).Build()
	sink := &audittest.Sink{Err: errors.New("daemon down")}
	done, err := newTakerWithSink(t, c, sink).Ensure(context.Background(), tenantFixture())
	if done || err == nil {
		t.Fatalf("done=%v err=%v, want an error and not done", done, err)
	}
	if _, ok := getBackup(t, c); ok {
		t.Fatal("a Backup was created with no audit record")
	}
}

// A create that fails after its record gets a second record with the reason.
func TestEnsure_FailedCreateIsRecorded(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(tenantNamespace(), scheduleFixture()).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(context.Context, client.WithWatch, client.Object, ...client.CreateOption) error {
				return errors.New("the API server is not reachable")
			},
		}).Build()
	sink := &audittest.Sink{}
	if _, err := newTakerWithSink(t, c, sink).Ensure(context.Background(), tenantFixture()); err == nil {
		t.Fatal("Ensure returned no error for a failed create")
	}
	got := sink.Events()
	if len(got) != 2 || got[0].Result != "" || got[1].Result != audit.ResultFailure || got[1].Reason == "" {
		t.Fatalf("records = %+v, want the record and then the failure", got)
	}
}

// The first pass creates the Backup and reports that the flow must wait.
func TestEnsure_CreatesTheBackupAndWaits(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(tenantNamespace(), scheduleFixture()).Build()
	done, err := newTaker(t, c).Ensure(context.Background(), tenantFixture())
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if done {
		t.Fatal("Ensure reported done before a backup completed")
	}
	b, found := getBackup(t, c)
	if !found {
		t.Fatal("the Backup was not created")
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
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(tenantNamespace(), scheduleFixture()).Build()
	taker := newTaker(t, c)
	for i := range 3 {
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
		WithObjects(tenantNamespace(), scheduleFixture(), backupWithPhase("Completed", time.Minute)).Build()
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
				WithObjects(tenantNamespace(), scheduleFixture(), backupWithPhase(phase, time.Minute)).Build()
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
				WithObjects(tenantNamespace(), scheduleFixture()).WithInterceptorFuncs(funcs).Build()
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
			WithObjects(tenantNamespace(), scheduleFixture(), backupWithPhase(phase, time.Minute)).Build()
		if done, err := newTaker(t, c).Ensure(context.Background(), tenantFixture()); done || err != nil {
			t.Errorf("phase %q after one minute: done=%v err=%v, want waiting", phase, done, err)
		}
	}
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).
		WithObjects(tenantNamespace(), scheduleFixture(), backupWithPhase("InProgress", Timeout+time.Minute)).Build()
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
			if _, found := getBackup(t, c); found {
				t.Error("a backup was created although no data exists")
			}
		})
	}
}

func TestEnsure_RefusesATenantWithNoUID(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(tenantNamespace(), scheduleFixture()).Build()
	tenant := tenantFixture()
	tenant.UID = ""
	if done, err := newTaker(t, c).Ensure(context.Background(), tenant); done || err == nil {
		t.Fatalf("done=%v err=%v, want an error", done, err)
	}
}

// The last backup is the template of the shipped Schedule with only the
// namespace and the retention changed (C67, gibson#1177). The exact
// comparison fails when the build drops or changes any field of the
// template: an exclusion, a hook, the volume rule or the storage location.
func TestBuild_IsTheScheduleTemplate(t *testing.T) {
	template := testTemplate()
	b := Build(BackupName(tenantFixture()), testVeleroNS, tenantFixture(), template)
	want := testTemplate()
	want["includedNamespaces"] = []any{"tenant-" + testTenant}
	want["ttl"] = "720h0m0s"
	if !reflect.DeepEqual(b.Object["spec"], want) {
		t.Errorf("spec = %v\nwant   %v", b.Object["spec"], want)
	}
	// The build does not write into the template it was given.
	if !reflect.DeepEqual(template, testTemplate()) {
		t.Error("Build changed the template of the Schedule")
	}
}

// An exclusion that the Schedule gains later reaches the last backup with no
// change in the operator: the one list is the Schedule.
func TestBuild_KeepsAnExclusionTheTemplateAdds(t *testing.T) {
	template := testTemplate()
	template["excludedNamespaceScopedResources"] = append(
		template["excludedNamespaceScopedResources"].([]any), "new.kind.example.io")
	b := Build(BackupName(tenantFixture()), testVeleroNS, tenantFixture(), template)
	got, _, _ := unstructured.NestedStringSlice(b.Object, "spec", "excludedNamespaceScopedResources")
	if !slices.Contains(got, "new.kind.example.io") || !slices.Contains(got, "ciliumendpoints.cilium.io") {
		t.Errorf("excludedNamespaceScopedResources = %v, want each exclusion of the template", got)
	}
}

// With no Schedule, or a Schedule with no template, no Backup is created and
// the delete flow stops: a backup without the exclusions ends PartiallyFailed.
func TestEnsure_NoScheduleNoBackup(t *testing.T) {
	empty := scheduleFixture()
	empty.Object["spec"] = map[string]any{"schedule": "0 * * * *"}
	for name, objs := range map[string][]client.Object{
		"no Schedule":           {tenantNamespace()},
		"Schedule, no template": {tenantNamespace(), empty},
	} {
		c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(objs...).Build()
		done, err := newTaker(t, c).Ensure(context.Background(), tenantFixture())
		if done || err == nil {
			t.Errorf("%s: done=%v err=%v, want an error and not done", name, done, err)
		}
		if _, found := getBackup(t, c); found {
			t.Errorf("%s: a Backup was created with no Schedule template", name)
		}
	}
}

// attempt is attempt n of the test tenant, as Velero leaves it: the given
// phase, created age ago, and ended ended ago (no completion time when
// ended is zero).
func attempt(n int, phase string, age, ended time.Duration) *unstructured.Unstructured {
	b := Build(AttemptName(tenantFixture(), n), testVeleroNS, tenantFixture(), testTemplate())
	b.SetCreationTimestamp(metav1.NewTime(time.Now().Add(-age)))
	if phase != "" {
		_ = unstructured.SetNestedField(b.Object, phase, "status", "phase")
	}
	if ended != 0 {
		_ = unstructured.SetNestedField(b.Object, time.Now().Add(-ended).UTC().Format(time.RFC3339),
			"status", "completionTimestamp")
	}
	return b
}

func attemptExists(t *testing.T, c client.Client, n int) bool {
	t.Helper()
	b := &unstructured.Unstructured{}
	b.SetGroupVersionKind(backupGVK)
	err := c.Get(context.Background(), client.ObjectKey{Namespace: testVeleroNS, Name: AttemptName(tenantFixture(), n)}, b)
	if apierrors.IsNotFound(err) {
		return false
	}
	if err != nil {
		t.Fatalf("get attempt %d: %v", n, err)
	}
	return true
}

// The first attempt keeps the name that a backup had before attempts
// existed, so a failed backup of an older operator is attempt 1.
func TestAttemptName_FirstAttemptIsTheOldName(t *testing.T) {
	if got, want := AttemptName(tenantFixture(), 1), "tenant-final-"+testUID; got != want {
		t.Fatalf("attempt 1 = %q, want %q", got, want)
	}
	if got, want := AttemptName(tenantFixture(), 2), "tenant-final-"+testUID+"-2"; got != want {
		t.Fatalf("attempt 2 = %q, want %q", got, want)
	}
	if BackupName(tenantFixture()) != AttemptName(tenantFixture(), 1) {
		t.Fatal("BackupName is not attempt 1")
	}
}

// hosted#23: a failed last backup kept the delete, and the CPU of the tenant,
// for ever. RetryDelay after the failure, the next pass takes attempt 2.
func TestEnsure_FailedAttemptIsTakenAgainAfterTheDelay(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(tenantNamespace(), scheduleFixture(),
		attempt(1, "PartiallyFailed", RetryDelay+2*time.Minute, RetryDelay+time.Minute)).Build()
	done, err := newTaker(t, c).Ensure(context.Background(), tenantFixture())
	if done || err != nil {
		t.Fatalf("done=%v err=%v, want a new attempt and waiting", done, err)
	}
	if !attemptExists(t, c, 2) {
		t.Fatal("no attempt 2 after the delay")
	}
}

// Inside the delay, the failure is an error and no attempt is taken. The
// delay starts when Velero ended the backup, not when it was created.
func TestEnsure_FailedAttemptWaitsForTheDelay(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(tenantNamespace(), scheduleFixture(),
		attempt(1, "PartiallyFailed", 2*RetryDelay, time.Minute)).Build()
	done, err := newTaker(t, c).Ensure(context.Background(), tenantFixture())
	if done || !errors.Is(err, ErrBackupFailed) {
		t.Fatalf("done=%v err=%v, want ErrBackupFailed and not done", done, err)
	}
	if attemptExists(t, c, 2) {
		t.Fatal("attempt 2 started inside the delay")
	}
}

// A later attempt that completed lets the delete go on, whatever came before.
func TestEnsure_LaterAttemptComplete(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(tenantNamespace(), scheduleFixture(),
		attempt(1, "PartiallyFailed", time.Hour, time.Hour), attempt(2, "Completed", time.Minute, time.Minute)).Build()
	done, err := newTaker(t, c).Ensure(context.Background(), tenantFixture())
	if !done || err != nil {
		t.Fatalf("done=%v err=%v, want done", done, err)
	}
}

// The newest attempt decides: a Completed attempt 1 does not hide a running
// attempt 2, and a failed attempt 1 does not hide a running attempt 2.
func TestEnsure_TheNewestAttemptDecides(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(tenantNamespace(), scheduleFixture(),
		attempt(1, "Failed", time.Hour, time.Hour), attempt(2, "InProgress", time.Minute, 0)).Build()
	done, err := newTaker(t, c).Ensure(context.Background(), tenantFixture())
	if done || err != nil {
		t.Fatalf("done=%v err=%v, want waiting on attempt 2", done, err)
	}
	if attemptExists(t, c, 3) {
		t.Fatal("attempt 3 started while attempt 2 runs")
	}
}

// After MaxAttempts failed attempts, no attempt is taken, and the delete
// stops for a person.
func TestEnsure_NoAttemptAfterTheLast(t *testing.T) {
	objs := []client.Object{tenantNamespace(), scheduleFixture()}
	for n := 1; n <= MaxAttempts; n++ {
		objs = append(objs, attempt(n, "PartiallyFailed", 3*RetryDelay, 2*RetryDelay))
	}
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(objs...).Build()
	done, err := newTaker(t, c).Ensure(context.Background(), tenantFixture())
	if done || !errors.Is(err, ErrBackupFailed) {
		t.Fatalf("done=%v err=%v, want ErrBackupFailed", done, err)
	}
	if attemptExists(t, c, MaxAttempts+1) {
		t.Fatal("an attempt past MaxAttempts started")
	}
}

// A backup that does not finish in time is a failed attempt too, so it does
// not hold the delete for ever either.
func TestEnsure_UnfinishedAttemptIsTakenAgain(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(tenantNamespace(), scheduleFixture(),
		attempt(1, "InProgress", Timeout+RetryDelay+time.Minute, 0)).Build()
	done, err := newTaker(t, c).Ensure(context.Background(), tenantFixture())
	if done || err != nil {
		t.Fatalf("done=%v err=%v, want a new attempt and waiting", done, err)
	}
	if !attemptExists(t, c, 2) {
		t.Fatal("no attempt 2 after the time limit and the delay")
	}
}
