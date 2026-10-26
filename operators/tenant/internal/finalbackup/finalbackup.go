// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package finalbackup takes the last Velero backup of a tenant before the
// tenant delete flow removes anything (ADR-0075).
//
// The tenant reconciler calls Ensure at the start of each delete pass, before
// it deletes a child resource. Ensure never blocks: it creates the Backup on
// the first pass and reads its phase on each later pass. The delete flow goes
// on only after the phase of one attempt is Completed. A failed backup, a
// backup that does not finish in time, and a Velero API that does not answer
// are all errors, so the flow removes nothing.
//
// A failed attempt is not the end. RetryDelay after it, Ensure takes a new
// attempt, up to MaxAttempts. Before, the only way on was a person who
// deleted the failed Backup object, so each failed delete kept the workloads
// and the volumes of the tenant for ever (hosted#23: the staging node ran out
// of CPU on the Neo4j pods of three such tenants).
//
// Ensure writes the audit record of the backup before it creates the Backup,
// and creates nothing when the record cannot be written (gibson#583).
//
// No switch turns the backup off.
package finalbackup

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/zeroroot-ai/gibson/operators/internal/audit"
	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/metrics"
)

const (
	// RetentionDays is the life of the last backup. Velero deletes the
	// backup and its data after this time.
	RetentionDays = 30

	// Timeout is the longest time that a backup can stay unfinished before
	// Ensure reports an error.
	Timeout = 30 * time.Minute

	// LabelTenant holds the tenant name.
	LabelTenant = "gibson.zeroroot.ai/tenant"
	// LabelBackupType marks the last backup of a tenant delete. The purge
	// script selects a backup by this label and LabelTenant, never by a part
	// of its name.
	LabelBackupType = "gibson.zeroroot.ai/backup-type"
	// BackupTypeFinal is the value of LabelBackupType.
	BackupTypeFinal = "final"
	// LabelRetentionDays states the life of the backup in days.
	LabelRetentionDays = "gibson.zeroroot.ai/retention-days"
	// AnnotationTenantUID holds the UID of the Tenant object, so a backup of
	// a deleted tenant is distinct from the backup of a later tenant with
	// the same name.
	AnnotationTenantUID = "gibson.zeroroot.ai/tenant-uid"

	phaseCompleted = "Completed"

	// MaxAttempts is the number of backups that a delete takes before it
	// stops for a person.
	MaxAttempts = 5

	// RetryDelay is the time from a failed attempt to the next one. It gives
	// Velero and the tenant workloads time to recover: a pre-hook fails on a
	// Neo4j pod that has no node yet.
	RetryDelay = 15 * time.Minute
)

// failedPhases are the Velero phases from which a backup never becomes
// Completed.
var failedPhases = map[string]bool{
	"Failed":           true,
	"PartiallyFailed":  true,
	"FailedValidation": true,
}

var (
	backupGVK   = schema.GroupVersionKind{Group: "velero.io", Version: "v1", Kind: "Backup"}
	scheduleGVK = schema.GroupVersionKind{Group: "velero.io", Version: "v1", Kind: "Schedule"}
)

// ScheduleName is the Schedule that the chart ships in the Velero namespace
// (charts helm/gibson-velero, platform-hourly). The last backup of a tenant is
// built from its template, so the last backup and the hourly backups exclude
// the same kinds from one list: secrets, the ESO generators, the k3s kinds and
// CiliumEndpoints (C67, gibson#1177). The chart grants the operator get on
// this one Schedule by name.
const ScheduleName = "platform-hourly"

// ErrBackupFailed reports a last backup that Velero did not complete. Ensure
// takes a new attempt RetryDelay later, up to MaxAttempts. After the last
// attempt, a person reads the Backup objects of the tenant, and deletes the
// failed ones to start a new set of attempts.
var ErrBackupFailed = errors.New("the last backup of the tenant did not complete")

// Taker takes the last backup of a tenant.
type Taker struct {
	client    client.Client
	namespace string
	audit     *audit.SagaEmitter
	now       func() time.Time
}

// New returns a Taker that writes Backup objects into veleroNamespace and
// the audit record of each backup through auditEmitter. Each argument is
// required.
func New(c client.Client, veleroNamespace string, auditEmitter *audit.SagaEmitter) (*Taker, error) {
	if c == nil {
		return nil, errors.New("finalbackup: the Kubernetes client is required")
	}
	if veleroNamespace == "" {
		return nil, errors.New("finalbackup: the Velero namespace is required")
	}
	if auditEmitter == nil {
		return nil, fmt.Errorf("finalbackup: %w", audit.ErrNoSink)
	}
	return &Taker{client: c, namespace: veleroNamespace, audit: auditEmitter, now: time.Now}, nil
}

// BackupName returns the name of the first attempt of the last backup of a
// tenant. The name comes from the UID of the Tenant object, so each delete
// has its own backups.
func BackupName(tenant *gibsonv1alpha1.Tenant) string {
	return AttemptName(tenant, 1)
}

// AttemptName returns the name of attempt n (1 to MaxAttempts) of the last
// backup of a tenant. The first attempt has no suffix, so a backup written
// before attempts existed is attempt 1.
func AttemptName(tenant *gibsonv1alpha1.Tenant, n int) string {
	if n <= 1 {
		return "tenant-final-" + string(tenant.UID)
	}
	return "tenant-final-" + string(tenant.UID) + "-" + strconv.Itoa(n)
}

// TenantNamespace returns the namespace that holds the workloads and the
// volumes of a tenant.
func TenantNamespace(tenantName string) string {
	return "tenant-" + tenantName
}

// Ensure reports true when the delete flow can go on.
//
//   - The tenant namespace does not exist, or it is already in deletion: true.
//     No data exists that a backup could hold, or a delete pass that came
//     earlier already passed this gate.
//   - No backup exists: Ensure creates attempt 1 and reports false.
//   - The newest attempt is Completed: true.
//   - The newest attempt is not finished: false, and a failure after Timeout.
//   - The newest attempt failed: an error. RetryDelay after the failure,
//     Ensure creates the next attempt and reports false. After MaxAttempts
//     failed attempts it creates none.
//   - The Velero API gave an error: an error.
func (t *Taker) Ensure(ctx context.Context, tenant *gibsonv1alpha1.Tenant) (bool, error) {
	if tenant.UID == "" {
		return false, errors.New("finalbackup: the tenant has no UID")
	}
	nsName := TenantNamespace(tenant.Name)
	var ns corev1.Namespace
	switch err := t.client.Get(ctx, client.ObjectKey{Name: nsName}, &ns); {
	case apierrors.IsNotFound(err):
		return true, nil
	case err != nil:
		return false, t.fail("read_namespace", fmt.Errorf("finalbackup: read namespace %q: %w", nsName, err))
	}
	if !ns.DeletionTimestamp.IsZero() {
		return true, nil
	}

	n, backup, err := t.newestAttempt(ctx, tenant)
	if err != nil {
		return false, err
	}
	if backup == nil {
		return false, t.create(ctx, AttemptName(tenant, 1), tenant)
	}
	name := backup.GetName()

	phase, _, _ := unstructured.NestedString(backup.Object, "status", "phase")
	if phase == phaseCompleted {
		return true, nil
	}
	var failedAt time.Time
	switch created := backup.GetCreationTimestamp(); {
	case failedPhases[phase]:
		failedAt = completionTime(backup)
	case created.IsZero():
		return false, nil
	case t.now().Sub(created.Time) > Timeout:
		failedAt = created.Add(Timeout)
	default:
		return false, nil
	}
	failure := fmt.Errorf("%w: attempt %d of %d, Backup %s/%s, has the phase %q",
		ErrBackupFailed, n, MaxAttempts, t.namespace, name, phase)
	if n >= MaxAttempts {
		return false, t.fail("backup_failed", fmt.Errorf("%w; no attempt is left", failure))
	}
	if next := failedAt.Add(RetryDelay); t.now().Before(next) {
		return false, t.fail("backup_failed",
			fmt.Errorf("%w; attempt %d starts at %s", failure, n+1, next.UTC().Format(time.RFC3339)))
	}
	return false, t.create(ctx, AttemptName(tenant, n+1), tenant)
}

// newestAttempt returns the attempt with the highest number that exists, and
// its number. With no attempt it returns 0 and nil.
func (t *Taker) newestAttempt(ctx context.Context, tenant *gibsonv1alpha1.Tenant) (int, *unstructured.Unstructured, error) {
	for n := MaxAttempts; n >= 1; n-- {
		name := AttemptName(tenant, n)
		backup := &unstructured.Unstructured{}
		backup.SetGroupVersionKind(backupGVK)
		err := t.client.Get(ctx, client.ObjectKey{Namespace: t.namespace, Name: name}, backup)
		switch {
		case err == nil:
			return n, backup, nil
		case !apierrors.IsNotFound(err):
			return 0, nil, t.fail("read", fmt.Errorf("finalbackup: read Backup %s/%s: %w", t.namespace, name, err))
		}
	}
	return 0, nil, nil
}

// completionTime is the time at which Velero ended a backup, or its creation
// time when Velero wrote none.
func completionTime(backup *unstructured.Unstructured) time.Time {
	if v, found, _ := unstructured.NestedString(backup.Object, "status", "completionTimestamp"); found {
		if at, err := time.Parse(time.RFC3339, v); err == nil {
			return at
		}
	}
	return backup.GetCreationTimestamp().Time
}

// create writes the audit record of the backup, then creates the Backup.
// With no record, it creates nothing. A failed create gets a second record.
func (t *Taker) create(ctx context.Context, name string, tenant *gibsonv1alpha1.Tenant) error {
	ev := audit.ObjectEvent(audit.ActionLastBackup, tenant, map[string]string{
		"backup":           t.namespace + "/" + name,
		"tenant_namespace": TenantNamespace(tenant.Name),
		"tenant_uid":       string(tenant.UID),
	})
	template, err := t.scheduleTemplate(ctx)
	if err != nil {
		return t.fail("read_schedule", err)
	}
	backup := Build(name, t.namespace, tenant, template)
	created := false
	err = t.audit.Change(ctx, ev, func() error {
		created = true
		if cErr := t.client.Create(ctx, backup); cErr != nil {
			return fmt.Errorf("finalbackup: create Backup %s/%s: %w", t.namespace, name, cErr)
		}
		return nil
	})
	switch {
	case err == nil:
		return nil
	case !created:
		return t.fail("audit", fmt.Errorf("finalbackup: Backup %s/%s not created: %w", t.namespace, name, err))
	default:
		return t.fail("create", err)
	}
}

// scheduleTemplate reads the backup template of the shipped Schedule. With
// no Schedule or no template there is no last backup, so the delete flow
// stops: a backup without the exclusions of the Schedule ends
// PartiallyFailed and holds kinds that a restore cannot create.
func (t *Taker) scheduleTemplate(ctx context.Context) (map[string]any, error) {
	sched := &unstructured.Unstructured{}
	sched.SetGroupVersionKind(scheduleGVK)
	if err := t.client.Get(ctx, client.ObjectKey{Namespace: t.namespace, Name: ScheduleName}, sched); err != nil {
		return nil, fmt.Errorf("finalbackup: read Schedule %s/%s, the template of the last backup: %w",
			t.namespace, ScheduleName, err)
	}
	template, found, err := unstructured.NestedMap(sched.Object, "spec", "template")
	if err != nil {
		return nil, fmt.Errorf("finalbackup: Schedule %s/%s: read spec.template: %w", t.namespace, ScheduleName, err)
	}
	if !found || len(template) == 0 {
		return nil, fmt.Errorf("finalbackup: Schedule %s/%s has no spec.template", t.namespace, ScheduleName)
	}
	return template, nil
}

// fail counts one failure and returns err unchanged.
func (t *Taker) fail(reason string, err error) error {
	metrics.FinalBackupFailures.WithLabelValues(reason).Inc()
	return err
}

// Build returns the Backup object for the last backup of a tenant: the
// template of the shipped Schedule, with the tenant namespace as the only
// included namespace and the retention of the last backup. Every other field
// of the template stays as it is, so each exclusion, hook and volume rule of
// the hourly backups holds for the last backup too.
func Build(name, veleroNamespace string, tenant *gibsonv1alpha1.Tenant, template map[string]any) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(backupGVK)
	u.SetName(name)
	u.SetNamespace(veleroNamespace)
	u.SetLabels(map[string]string{
		LabelTenant:        tenant.Name,
		LabelBackupType:    BackupTypeFinal,
		LabelRetentionDays: strconv.Itoa(RetentionDays),
	})
	u.SetAnnotations(map[string]string{
		AnnotationTenantUID: string(tenant.UID),
	})
	spec := runtime.DeepCopyJSON(template)
	spec["includedNamespaces"] = []any{TenantNamespace(tenant.Name)}
	spec["ttl"] = fmt.Sprintf("%dh0m0s", RetentionDays*24)
	u.Object["spec"] = spec
	return u
}
