// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/zeroroot-ai/gibson/operators/internal/audit"
	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/platform/api/v1alpha1"
)

// A delete that finds no daemon for pendingDeleteGrace must still not lose its
// audit records. The status that held them goes with the deleted object, so the
// records move to a ConfigMap in the operator namespace. PendingAuditFlusher
// sends them when the daemon returns and then deletes the ConfigMap. The
// operator log is the last copy only in a teardown of the whole platform, where
// no daemon will return (logTeardown).

// pendingAuditLabel marks the ConfigMaps that hold pending audit records.
const pendingAuditLabel = "platform-operator.gibson.zeroroot.ai/pending-audit"

// durableActions are the actions that a delete of this operator can leave in a
// ConfigMap. The flusher refuses a record with any other action.
var durableActions = map[string]bool{
	audit.ActionOIDCClientApply:   true,
	audit.ActionOIDCClientDelete:  true,
	audit.ActionPlatformBootstrap: true,
}

// pendingAuditKey is the data key that holds the records, as JSON.
const pendingAuditKey = "records"

// durableFlushInterval is how often PendingAuditFlusher looks for ConfigMaps.
const durableFlushInterval = 30 * time.Second

// saveDurable keeps recs in a ConfigMap in the operator namespace. The name
// comes from the content, so a retry of the same records writes the same
// object.
func saveDurable(ctx context.Context, c client.Client, recs []gibsonv1alpha1.PendingAuditRecord) error {
	if len(recs) == 0 {
		return nil
	}
	raw, err := json.Marshal(recs)
	if err != nil {
		return fmt.Errorf("encode the pending audit records: %w", err)
	}
	// The name comes from the records without their first-seen time, so a
	// retry of the same delete, which stamps a new time, writes the same
	// object and not a second one.
	norm := make([]gibsonv1alpha1.PendingAuditRecord, len(recs))
	copy(norm, recs)
	for i := range norm {
		norm[i].FirstAt = metav1.Time{}
	}
	nameRaw, err := json.Marshal(norm)
	if err != nil {
		return fmt.Errorf("encode the pending audit records: %w", err)
	}
	sum := sha256.Sum256(nameRaw)
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gibson-pending-audit-" + hex.EncodeToString(sum[:])[:16],
			Namespace: defaultChildNamespace,
			Labels:    map[string]string{pendingAuditLabel: "true"},
		},
		Data: map[string]string{pendingAuditKey: string(raw)},
	}
	if err := c.Create(ctx, cm); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("keep the pending audit records in a ConfigMap: %w", err)
	}
	return nil
}

// parentInTeardown reports whether the PlatformBootstrap that owns oc is
// deleting or gone. That is a teardown of the whole platform: no daemon will
// return to take the records.
func parentInTeardown(ctx context.Context, c client.Client, oc *gibsonv1alpha1.OIDCClient) bool {
	for _, ref := range oc.GetOwnerReferences() {
		if ref.Kind != "PlatformBootstrap" {
			continue
		}
		var pb gibsonv1alpha1.PlatformBootstrap
		err := c.Get(ctx, client.ObjectKey{Name: ref.Name}, &pb)
		return apierrors.IsNotFound(err) || (err == nil && !pb.DeletionTimestamp.IsZero())
	}
	return false
}

// logTeardown writes the records of a platform teardown to the operator log.
// It is the last copy, and it says so.
func logTeardown(ctx context.Context, recs []gibsonv1alpha1.PendingAuditRecord) {
	logger := log.FromContext(ctx)
	for _, rec := range recs {
		logger.Error(errors.New("audit record not delivered"),
			"platform teardown: no daemon will return, and no ConfigMap holds the record; this log line is the last copy",
			"action", rec.Action, "target", rec.TargetID, "result", rec.Result, "reason", rec.Reason,
			"fields", rec.Fields, "first_at", rec.FirstAt.UTC().Format(time.RFC3339))
	}
}

// PendingAuditFlusher sends the pending audit records that a delete moved to
// ConfigMaps, and deletes each ConfigMap when the daemon has the records.
type PendingAuditFlusher struct {
	Client   client.Client
	Audit    *audit.SagaEmitter
	Interval time.Duration
}

// NeedLeaderElection makes one replica run the loop.
func (f *PendingAuditFlusher) NeedLeaderElection() bool { return true }

// SetupWithManager adds the loop to the manager.
func (f *PendingAuditFlusher) SetupWithManager(mgr manager.Manager) error {
	if f.Audit == nil {
		return errNoAuditEmitter
	}
	if f.Client == nil {
		f.Client = mgr.GetClient()
	}
	if err := mgr.Add(f); err != nil {
		return fmt.Errorf("add the pending audit flusher to the manager: %w", err)
	}
	return nil
}

// Start runs the loop until ctx ends.
func (f *PendingAuditFlusher) Start(ctx context.Context) error {
	interval := f.Interval
	if interval <= 0 {
		interval = durableFlushInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := f.FlushOnce(ctx); err != nil {
				log.FromContext(ctx).Error(err, "pending audit ConfigMaps stay; the daemon did not accept them")
			}
		}
	}
}

// FlushOnce sends the records of each pending ConfigMap. A ConfigMap whose
// records are all accepted is deleted. A partly accepted one keeps the rest.
// Delivery is at least once: when the update after a send fails, the next
// pass sends the same records again.
func (f *PendingAuditFlusher) FlushOnce(ctx context.Context) error {
	var cms corev1.ConfigMapList
	if err := f.Client.List(ctx, &cms, client.InNamespace(defaultChildNamespace),
		client.MatchingLabels{pendingAuditLabel: "true"}); err != nil {
		return fmt.Errorf("list the pending audit ConfigMaps: %w", err)
	}
	var first error
	for i := range cms.Items {
		if err := f.flushOne(ctx, &cms.Items[i]); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (f *PendingAuditFlusher) flushOne(ctx context.Context, cm *corev1.ConfigMap) error {
	var recs []gibsonv1alpha1.PendingAuditRecord
	if err := json.Unmarshal([]byte(cm.Data[pendingAuditKey]), &recs); err != nil {
		return fmt.Errorf("decode the pending audit ConfigMap %s: %w", cm.Name, err)
	}
	// The flusher sends only the records that this operator writes for a
	// delete. A ConfigMap with any other record is not sent and is left for a
	// person to read.
	for _, rec := range recs {
		if !durableActions[rec.Action] {
			return fmt.Errorf("the pending audit ConfigMap %s holds a record with the action %q, which the operator does not write for a delete", cm.Name, rec.Action)
		}
	}
	ferr := flushPending(ctx, f.Audit, &recs)
	if len(recs) == 0 {
		if err := f.Client.Delete(ctx, cm); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete the pending audit ConfigMap %s: %w", cm.Name, err)
		}
		return nil
	}
	raw, err := json.Marshal(recs)
	if err != nil {
		return fmt.Errorf("encode the pending audit records: %w", err)
	}
	cm.Data[pendingAuditKey] = string(raw)
	if err := f.Client.Update(ctx, cm); err != nil {
		return fmt.Errorf("update the pending audit ConfigMap %s: %w", cm.Name, err)
	}
	return ferr
}
