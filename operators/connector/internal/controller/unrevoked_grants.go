// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	connectorv1alpha1 "github.com/zeroroot-ai/gibson/operators/connector/api/v1alpha1"
)

// An unrevoked grant record is the durable record of a connector grant that
// the finalizer could not revoke before revokeDeadline. The finalizer
// releases so that a delete never wedges, and it first writes this record: a
// ConfigMap in the tenant namespace. The UnrevokedGrantsRunnable reads each
// record, asks the daemon to revoke the grant again, and deletes the record
// when the revoke succeeds. The gauge UnrevokedGrants counts the records, so
// an alert can name a grant that stays live. A log line is not a record.
const (
	labelUnrevokedGrant           = "gibson.zeroroot.ai/unrevoked-grant"
	unrevokedGrantKeyTenant       = "tenant"
	unrevokedGrantKeyConnector    = "connector"
	unrevokedGrantKeyReleasedAt   = "released-at"
	defaultUnrevokedGrantInterval = 5 * time.Minute
)

// UnrevokedGrants is the number of unrevoked grant records after the last
// pass of the retry loop.
var UnrevokedGrants = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "gibson_connector_unrevoked_grants",
	Help: "Connector grants that the finalizer could not revoke and that the retry loop has not revoked yet.",
})

func init() {
	metrics.Registry.MustRegister(UnrevokedGrants)
}

// unrevokedGrantName is the name of the record of the connector instance
// name.
func unrevokedGrantName(instance string) string {
	return "connector-unrevoked-" + instance
}

// recordUnrevokedGrant writes the record of the grant of ci. An existing
// record is kept as it is.
func recordUnrevokedGrant(
	ctx context.Context, c client.Client, ci *connectorv1alpha1.ConnectorInstance,
	tenant, connector string, now time.Time,
) error {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      unrevokedGrantName(ci.Name),
			Namespace: ci.Namespace,
			Labels: map[string]string{
				labelManagedBy:      connectorOperatorManagedBy,
				labelUnrevokedGrant: "true",
			},
		},
		Data: map[string]string{
			unrevokedGrantKeyTenant:     tenant,
			unrevokedGrantKeyConnector:  connector,
			unrevokedGrantKeyReleasedAt: now.UTC().Format(time.RFC3339),
		},
	}
	if err := c.Create(ctx, cm); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("record the unrevoked grant of %s/%s: %w", tenant, connector, err)
	}
	return nil
}

// UnrevokedGrantsRunnable retries the revoke of each recorded grant.
type UnrevokedGrantsRunnable struct {
	Client   client.Client
	Revoker  GrantRevoker
	Interval time.Duration
}

// NeedLeaderElection runs the loop on the leader only.
func (r *UnrevokedGrantsRunnable) NeedLeaderElection() bool { return true }

// SetupWithManager adds the loop to the manager.
func (r *UnrevokedGrantsRunnable) SetupWithManager(mgr manager.Manager) error {
	if r.Revoker == nil {
		return errors.New("unrevoked grants: Revoker is nil")
	}
	if r.Client == nil {
		r.Client = mgr.GetClient()
	}
	if err := mgr.Add(r); err != nil {
		return fmt.Errorf("unrevoked grants: add the loop to the manager: %w", err)
	}
	return nil
}

// Start runs one pass at once and one pass for each interval.
func (r *UnrevokedGrantsRunnable) Start(ctx context.Context) error {
	interval := r.Interval
	if interval <= 0 {
		interval = defaultUnrevokedGrantInterval
	}
	logger := log.FromContext(ctx).WithName("unrevoked-grants")
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if err := r.retry(ctx); err != nil {
			logger.Error(err, "unrevoked grants pass failed; retrying next tick")
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// retry asks the daemon to revoke each recorded grant and deletes the record
// of each grant that it revoked. A record whose connector instance exists
// again is deleted with no revoke: the grant of that record was replaced by
// the grant of the new instance, and a revoke now would revoke the new one.
func (r *UnrevokedGrantsRunnable) retry(ctx context.Context) error {
	logger := log.FromContext(ctx).WithName("unrevoked-grants")
	var records corev1.ConfigMapList
	if err := r.Client.List(ctx, &records, client.MatchingLabels{labelUnrevokedGrant: "true"}); err != nil {
		return fmt.Errorf("list the unrevoked grant records: %w", err)
	}
	left := 0
	for i := range records.Items {
		rec := &records.Items[i]
		tenant, connector := rec.Data[unrevokedGrantKeyTenant], rec.Data[unrevokedGrantKeyConnector]
		replaced, err := r.instanceExists(ctx, rec)
		if err != nil {
			return err
		}
		if !replaced {
			if err := r.Revoker.Revoke(ctx, tenant, connector); err != nil {
				logger.Error(err, "the grant is still live", "tenant", tenant, "connector", connector,
					"released_at", rec.Data[unrevokedGrantKeyReleasedAt])
				left++
				continue
			}
		}
		if err := r.Client.Delete(ctx, rec); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete the record %s/%s: %w", rec.Namespace, rec.Name, err)
		}
	}
	UnrevokedGrants.Set(float64(left))
	return nil
}

// instanceExists reports whether a connector instance of the record exists
// and is not being deleted.
func (r *UnrevokedGrantsRunnable) instanceExists(ctx context.Context, rec *corev1.ConfigMap) (bool, error) {
	var instances connectorv1alpha1.ConnectorInstanceList
	if err := r.Client.List(ctx, &instances, client.InNamespace(rec.Namespace)); err != nil {
		return false, fmt.Errorf("list the connector instances of %s: %w", rec.Namespace, err)
	}
	for i := range instances.Items {
		ci := &instances.Items[i]
		if unrevokedGrantName(ci.Name) == rec.Name && ci.DeletionTimestamp.IsZero() {
			return true, nil
		}
	}
	return false, nil
}
