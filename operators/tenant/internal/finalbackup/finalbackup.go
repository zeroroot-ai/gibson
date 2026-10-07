// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package finalbackup takes the last Velero backup of a tenant before the
// tenant delete flow removes anything (ADR-0075).
//
// The tenant reconciler calls Ensure at the start of each delete pass, before
// it deletes a child resource. Ensure never blocks: it creates the Backup on
// the first pass and reads its phase on each later pass. The delete flow goes
// on only after the phase is Completed. A failed backup, a backup that does
// not finish in time, and a Velero API that does not answer are all errors,
// so the flow removes nothing.
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
)

// failedPhases are the Velero phases from which a backup never becomes
// Completed.
var failedPhases = map[string]bool{
	"Failed":           true,
	"PartiallyFailed":  true,
	"FailedValidation": true,
}

var backupGVK = schema.GroupVersionKind{Group: "velero.io", Version: "v1", Kind: "Backup"}

// ErrBackupFailed reports a last backup that Velero did not complete. To try
// again, an operator deletes the failed Backup object. The next delete pass
// then creates a new one.
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

// BackupName returns the name of the last backup of a tenant. The name comes
// from the UID of the Tenant object, so each delete has exactly one backup.
func BackupName(tenant *gibsonv1alpha1.Tenant) string {
	return "tenant-final-" + string(tenant.UID)
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
//   - No backup exists: Ensure creates it and reports false.
//   - The backup is Completed: true.
//   - The backup is not finished: false, or an error after Timeout.
//   - The backup failed, or the Velero API gave an error: an error.
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

	name := BackupName(tenant)
	backup := &unstructured.Unstructured{}
	backup.SetGroupVersionKind(backupGVK)
	err := t.client.Get(ctx, client.ObjectKey{Namespace: t.namespace, Name: name}, backup)
	if apierrors.IsNotFound(err) {
		return false, t.create(ctx, name, tenant)
	}
	if err != nil {
		return false, t.fail("read", fmt.Errorf("finalbackup: read Backup %s/%s: %w", t.namespace, name, err))
	}

	phase, _, _ := unstructured.NestedString(backup.Object, "status", "phase")
	switch {
	case phase == phaseCompleted:
		return true, nil
	case failedPhases[phase]:
		return false, t.fail("backup_failed",
			fmt.Errorf("%w: Backup %s/%s has the phase %q", ErrBackupFailed, t.namespace, name, phase))
	}
	created := backup.GetCreationTimestamp()
	if created.IsZero() {
		return false, nil
	}
	if age := t.now().Sub(created.Time); age > Timeout {
		return false, t.fail("timeout",
			fmt.Errorf("%w: Backup %s/%s has the phase %q after %s",
				ErrBackupFailed, t.namespace, name, phase, age.Round(time.Second)))
	}
	return false, nil
}

// create writes the audit record of the backup, then creates the Backup.
// With no record, it creates nothing. A failed create gets a second record.
func (t *Taker) create(ctx context.Context, name string, tenant *gibsonv1alpha1.Tenant) error {
	ev := audit.ObjectEvent(audit.ActionLastBackup, tenant, map[string]string{
		"backup":           t.namespace + "/" + name,
		"tenant_namespace": TenantNamespace(tenant.Name),
		"tenant_uid":       string(tenant.UID),
	})
	created := false
	err := t.audit.Change(ctx, ev, func() error {
		created = true
		if cErr := t.client.Create(ctx, Build(name, t.namespace, tenant)); cErr != nil {
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

// fail counts one failure and returns err unchanged.
func (t *Taker) fail(reason string, err error) error {
	metrics.FinalBackupFailures.WithLabelValues(reason).Inc()
	return err
}

// Build returns the Backup object for the last backup of a tenant. The backup
// holds each object of the tenant namespace and the files of each pod volume
// in it.
func Build(name, veleroNamespace string, tenant *gibsonv1alpha1.Tenant) *unstructured.Unstructured {
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
	_ = unstructured.SetNestedMap(u.Object, map[string]any{
		"includedNamespaces":       []any{TenantNamespace(tenant.Name)},
		"defaultVolumesToFsBackup": true,
		"storageLocation":          "default",
		"ttl":                      fmt.Sprintf("%dh0m0s", RetentionDays*24),
	}, "spec")
	return u
}
