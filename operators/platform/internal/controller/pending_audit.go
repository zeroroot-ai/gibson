// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strconv"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/zeroroot-ai/sdk/auth"

	"github.com/zeroroot-ai/gibson/operators/internal/audit"
	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/platform/api/v1alpha1"
)

// The platform operator runs before the daemon exists: it makes the Zitadel
// project, the FGA store and the OIDC clients the daemon starts on. A change
// of this operator therefore never waits for its audit record, or the install
// deadlocks. The operator makes the change, keeps the record pending in the
// status of the changed resource, sends it when the daemon answers, and then
// removes it (gibson#583).

// flushTimeout bounds one attempt to send the pending records, so a daemon
// that does not exist yet holds a reconcile for a bounded time.
const flushTimeout = 3 * time.Second

// pendingRequeue is how soon a resource with pending records is visited again
// to send them.
const pendingRequeue = 30 * time.Second

// errNoAuditEmitter reports a reconciler built with no audit emitter.
var errNoAuditEmitter = errors.New("platform operator: the audit emitter is required (gibson#583)")

// pendingRecord returns the pending form of a change to obj. Platform
// resources belong to the system tenant.
func pendingRecord(action string, obj client.Object, result, reason string, fields map[string]string) gibsonv1alpha1.PendingAuditRecord {
	ev := audit.ObjectEvent(action, obj, fields)
	return gibsonv1alpha1.PendingAuditRecord{
		Action:     ev.Action,
		TargetType: ev.TargetType,
		TargetID:   ev.TargetID,
		Result:     result,
		Reason:     reason,
		Fields:     ev.Fields,
		Count:      1,
		FirstAt:    metav1.Now(),
	}
}

// maxPending bounds the pending list of one resource.
const maxPending = 64

// keepPending adds rec to the pending list. A record equal to one already
// pending (the same change, tried again by a later pass while the daemon is
// down) is not added again, so the list stays small and a pass that changes
// nothing new leaves the status as it was. When the list is full, each
// further record raises the count of one overflow record.
func keepPending(list *[]gibsonv1alpha1.PendingAuditRecord, rec gibsonv1alpha1.PendingAuditRecord) {
	for i := range *list {
		p := &(*list)[i]
		if p.Action == rec.Action && p.TargetType == rec.TargetType && p.TargetID == rec.TargetID &&
			p.Result == rec.Result && p.Reason == rec.Reason && maps.Equal(p.Fields, rec.Fields) {
			return
		}
	}
	if n := len(*list); n > 0 && (*list)[n-1].Fields["overflow"] == "true" {
		(*list)[n-1].Count += rec.Count
		return
	}
	if len(*list) >= maxPending-1 {
		*list = append(*list, gibsonv1alpha1.PendingAuditRecord{
			Action: rec.Action, TargetType: rec.TargetType, TargetID: rec.TargetID,
			Fields: map[string]string{"overflow": "true"}, Count: rec.Count, FirstAt: rec.FirstAt,
		})
		return
	}
	*list = append(*list, rec)
}

// flushPending sends the pending records in order and removes each one the
// daemon accepts. It stops at the first refusal and keeps the rest. It
// returns the error of that refusal, which only delays the records.
func flushPending(ctx context.Context, em *audit.SagaEmitter, list *[]gibsonv1alpha1.PendingAuditRecord) error {
	_, err := flushPendingSent(ctx, em, list)
	return err
}

// flushPendingSent is flushPending that also returns the records that the
// daemon accepted. A status write that loses a conflict uses them, so it does
// not bring back a record that this pass already sent.
func flushPendingSent(ctx context.Context, em *audit.SagaEmitter, list *[]gibsonv1alpha1.PendingAuditRecord) ([]gibsonv1alpha1.PendingAuditRecord, error) {
	if len(*list) == 0 {
		return nil, nil
	}
	fctx, cancel := context.WithTimeout(ctx, flushTimeout)
	defer cancel()
	sent := 0
	var err error
	for _, rec := range *list {
		ev := eventOf(rec)
		if rec.Result == audit.ResultFailure {
			err = em.RecordFailure(fctx, ev, errors.New(rec.Reason))
		} else {
			err = em.Record(fctx, ev)
		}
		if err != nil {
			break
		}
		sent++
	}
	accepted := append([]gibsonv1alpha1.PendingAuditRecord(nil), (*list)[:sent]...)
	*list = append([]gibsonv1alpha1.PendingAuditRecord(nil), (*list)[sent:]...)
	if len(*list) == 0 {
		*list = nil
	}
	if err != nil {
		return accepted, fmt.Errorf("send the pending audit records: %w", err)
	}
	return accepted, nil
}

// samePending reports whether two pending records stand for the same change.
func samePending(a, b gibsonv1alpha1.PendingAuditRecord) bool {
	return a.Action == b.Action && a.TargetType == b.TargetType && a.TargetID == b.TargetID &&
		a.Result == b.Result && a.Reason == b.Reason && maps.Equal(a.Fields, b.Fields)
}

func containsPending(list []gibsonv1alpha1.PendingAuditRecord, rec gibsonv1alpha1.PendingAuditRecord) bool {
	for _, p := range list {
		if samePending(p, rec) {
			return true
		}
	}
	return false
}

// mergePending is the pending list that a status write keeps after it lost a
// conflict. It holds every record of this pass (desired), and every record
// that another writer added in the meantime (fresh), for example the delete
// record of an OIDC client. It drops a record that this pass already sent
// (flushed), so a sent record does not come back.
func mergePending(desired, fresh, flushed []gibsonv1alpha1.PendingAuditRecord) []gibsonv1alpha1.PendingAuditRecord {
	merged := append([]gibsonv1alpha1.PendingAuditRecord(nil), desired...)
	for _, f := range fresh {
		if !containsPending(merged, f) && !containsPending(flushed, f) {
			merged = append(merged, f)
		}
	}
	return merged
}

// recordBefore keeps the pending record of a change and writes the status
// that holds it, before the change. When the status is not written, it
// returns an error and the caller makes no change: no admin removal, user
// delete or role reset exists without its record (gibson#676). The record
// still waits for the daemon, because the platform operator runs before the
// daemon exists.
func (r *PlatformBootstrapReconciler) recordBefore(ctx context.Context, pb *gibsonv1alpha1.PlatformBootstrap, rec gibsonv1alpha1.PendingAuditRecord) error {
	keepPending(&pb.Status.PendingAuditRecords, rec)
	if err := r.statusUpdate(ctx, pb); err != nil {
		return fmt.Errorf("keep the audit record before the change: %w", err)
	}
	return nil
}

// eventOf is the audit record of a pending record. The record carries when
// the change happened, because the daemon writes it later.
func eventOf(rec gibsonv1alpha1.PendingAuditRecord) audit.Event {
	fields := make(map[string]string, len(rec.Fields)+2)
	maps.Copy(fields, rec.Fields)
	fields["changed_at"] = rec.FirstAt.UTC().Format(time.RFC3339)
	if rec.Count > 1 {
		fields["count"] = strconv.Itoa(int(rec.Count))
	}
	return audit.Event{
		Action:     rec.Action,
		TenantID:   auth.SystemTenantString,
		TargetType: rec.TargetType,
		TargetID:   rec.TargetID,
		Result:     rec.Result,
		Reason:     rec.Reason,
		Fields:     fields,
	}
}
