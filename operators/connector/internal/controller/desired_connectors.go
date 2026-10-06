// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	connectorv1alpha1 "github.com/zeroroot-ai/gibson/operators/connector/api/v1alpha1"
)

// The desired connectors loop (gibson#662).
//
// A tenant enables a connector through the daemon. The daemon records the
// wish in its table and makes no Kubernetes call (ADR-0023). This loop pulls
// the wishes, makes one ConnectorInstance for each (tenant, connector) pair in
// the namespace tenant-<tenant>, deletes each ConnectorInstance that no tenant
// wants any more, and reports the state of each one back to the daemon. The
// ConnectorInstance controller then does the ToolHive work, as before.

const (
	defaultDesiredConnectorsInterval = 30 * time.Second

	labelManagedBy   = "app.kubernetes.io/managed-by"
	labelPartOf      = "app.kubernetes.io/part-of"
	labelConnectorID = "gibson.zeroroot.ai/connector"

	// connectorOperatorManagedBy marks a ConnectorInstance that this loop
	// made. The loop deletes only a ConnectorInstance with this label.
	connectorOperatorManagedBy = "gibson-connector-operator"

	// legacyConnectorServiceManagedBy marks a ConnectorInstance that the
	// daemon wrote before it kept the desired state. The loop adopts each one
	// once: it asks the daemon to record it, then puts its own label on it.
	// The daemon writes no ConnectorInstance any more, so no new object gets
	// this label.
	legacyConnectorServiceManagedBy = "gibson-connector-service"

	connectorTenantNamespacePrefix = "tenant-"
)

// DesiredConnectorsDaemon is the slice of the daemon client this loop needs.
type DesiredConnectorsDaemon interface {
	ListDesiredConnectors(ctx context.Context) ([]*daemonoperatorv1.DesiredConnector, error)
	ReportConnectorStatus(ctx context.Context, req *daemonoperatorv1.ReportConnectorStatusRequest) error
	AdoptConnector(ctx context.Context, tenantID, connector string) error
	ConnectorCredential(
		ctx context.Context, req *daemonoperatorv1.GetConnectorCredentialRequest,
	) (*daemonoperatorv1.GetConnectorCredentialResponse, error)
}

// DesiredConnectorsRunnable converges the ConnectorInstances to the
// connectors that the tenants enabled.
type DesiredConnectorsRunnable struct {
	Client   client.Client
	Daemon   DesiredConnectorsDaemon
	Interval time.Duration
}

// NeedLeaderElection makes one replica run the loop.
func (r *DesiredConnectorsRunnable) NeedLeaderElection() bool { return true }

// SetupWithManager checks the inputs and adds the loop to the manager.
func (r *DesiredConnectorsRunnable) SetupWithManager(mgr manager.Manager) error {
	if r.Daemon == nil {
		return errors.New("desired connectors: Daemon client is nil")
	}
	if r.Client == nil {
		r.Client = mgr.GetClient()
	}
	if err := mgr.Add(r); err != nil {
		return fmt.Errorf("desired connectors: add the loop to the manager: %w", err)
	}
	return nil
}

// Start runs the loop until ctx ends.
func (r *DesiredConnectorsRunnable) Start(ctx context.Context) error {
	interval := r.Interval
	if interval <= 0 {
		interval = defaultDesiredConnectorsInterval
	}
	logger := log.FromContext(ctx).WithName("desired-connectors")
	logger.Info("starting the desired connectors loop", "interval", interval.String())
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if err := r.converge(ctx); err != nil {
			logger.Error(err, "desired connectors pass failed; retrying next tick")
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// pairKey is the (tenant, connector) key of a ConnectorInstance.
func pairKey(tenant, connector string) string { return tenant + "/" + connector }

// tenantOf returns the tenant of a ConnectorInstance from its namespace.
func tenantOf(ci *connectorv1alpha1.ConnectorInstance) (string, bool) {
	tenant, ok := strings.CutPrefix(ci.Namespace, connectorTenantNamespacePrefix)
	return tenant, ok && tenant != ""
}

// converge runs one pass: adopt, then make what is wanted, report its state,
// and delete what is no longer wanted.
func (r *DesiredConnectorsRunnable) converge(ctx context.Context) error {
	logger := log.FromContext(ctx).WithName("desired-connectors")

	var all connectorv1alpha1.ConnectorInstanceList
	if err := r.Client.List(ctx, &all); err != nil {
		return fmt.Errorf("list ConnectorInstances: %w", err)
	}
	// Adopt first, so a ConnectorInstance from before the table is in the
	// desired set of this same pass and is never deleted.
	for i := range all.Items {
		if err := r.adopt(ctx, &all.Items[i]); err != nil {
			return err
		}
	}

	desired, err := r.Daemon.ListDesiredConnectors(ctx)
	if err != nil {
		return fmt.Errorf("list desired connectors: %w", err)
	}
	wanted := make(map[string]struct{}, len(desired))
	for _, d := range desired {
		wanted[pairKey(d.GetTenantId(), d.GetConnectorId())] = struct{}{}
		report := &daemonoperatorv1.ReportConnectorStatusRequest{
			TenantId: d.GetTenantId(), ConnectorId: d.GetConnectorId(),
		}
		ci, ensureErr := r.ensure(ctx, d)
		if ensureErr != nil {
			logger.Error(ensureErr, "connector failed", "tenant", d.GetTenantId(), "connector", d.GetConnectorId())
			report.Phase = string(connectorv1alpha1.ConnectorInstancePhaseFailed)
			report.LastError = ensureErr.Error()
		} else {
			if cerr := r.syncCredential(ctx, d.GetTenantId(), ci); cerr != nil {
				// The error names the Secret, never a value.
				logger.Error(cerr, "connector credential failed", "tenant", d.GetTenantId(), "connector", d.GetConnectorId())
			}
			report.Phase = string(ci.Status.Phase)
			if report.Phase == "" {
				report.Phase = string(connectorv1alpha1.ConnectorInstancePhasePending)
			}
			report.DiscoveredTools = ci.Status.DiscoveredTools
			report.LastError = ci.Status.LastError
		}
		if rerr := r.Daemon.ReportConnectorStatus(ctx, report); rerr != nil {
			logger.Error(rerr, "report connector status failed", "tenant", d.GetTenantId(), "connector", d.GetConnectorId())
		}
	}
	return r.prune(ctx, all.Items, wanted)
}

// adopt records a ConnectorInstance that the daemon wrote before the table
// existed, then marks it as an object of this loop.
func (r *DesiredConnectorsRunnable) adopt(ctx context.Context, ci *connectorv1alpha1.ConnectorInstance) error {
	if ci.Labels[labelManagedBy] != legacyConnectorServiceManagedBy {
		return nil
	}
	tenant, ok := tenantOf(ci)
	if !ok {
		return nil
	}
	// A connector that left the catalog is not adopted. The loop still puts
	// its label on the object, so the prune of this pass deletes it.
	if err := r.Daemon.AdoptConnector(ctx, tenant, ci.Name); err != nil && status.Code(err) != codes.NotFound {
		return fmt.Errorf("adopt ConnectorInstance %s/%s: %w", ci.Namespace, ci.Name, err)
	}
	ci.Labels[labelManagedBy] = connectorOperatorManagedBy
	if err := r.Client.Update(ctx, ci); err != nil {
		return fmt.Errorf("label adopted ConnectorInstance %s/%s: %w", ci.Namespace, ci.Name, err)
	}
	return nil
}

// desiredSpec is the ConnectorInstance spec of a desired connector. It is the
// spec that componentcatalog.ConnectorEntry.BuildConnectorInstance writes.
func desiredSpec(d *daemonoperatorv1.DesiredConnector) connectorv1alpha1.ConnectorInstanceSpec {
	return connectorv1alpha1.ConnectorInstanceSpec{
		Connector:   d.GetConnectorId(),
		Shape:       connectorv1alpha1.ConnectorShape(d.GetShape()),
		Image:       d.GetImage(),
		Endpoint:    d.GetEndpoint(),
		Transport:   connectorv1alpha1.ConnectorTransport(d.GetTransport()),
		Runtime:     connectorv1alpha1.ConnectorRuntimePod,
		EgressAllow: d.GetEgressAllow(),
		Auth:        connectorv1alpha1.ConnectorAuthKind(d.GetAuth()),
	}
}

// ensure makes the ConnectorInstance of one desired connector, or brings the
// fields of the catalog entry up to date on the one that exists. The fields
// that the catalog does not set (the credential refs) stay as they are.
func (r *DesiredConnectorsRunnable) ensure(
	ctx context.Context, d *daemonoperatorv1.DesiredConnector,
) (*connectorv1alpha1.ConnectorInstance, error) {
	// A tenant namespace that does not exist fails the create below, and the
	// loop reports the connector as Failed with that error.
	ns := connectorTenantNamespacePrefix + d.GetTenantId()
	want := desiredSpec(d)
	ci := &connectorv1alpha1.ConnectorInstance{}
	err := r.Client.Get(ctx, client.ObjectKey{Namespace: ns, Name: d.GetConnectorId()}, ci)
	switch {
	case apierrors.IsNotFound(err):
		ci = &connectorv1alpha1.ConnectorInstance{
			ObjectMeta: metav1.ObjectMeta{
				Name: d.GetConnectorId(), Namespace: ns,
				Labels: map[string]string{
					labelConnectorID: d.GetConnectorId(),
					labelManagedBy:   connectorOperatorManagedBy,
					labelPartOf:      "gibson",
				},
			},
			Spec: want,
		}
		if cerr := r.Client.Create(ctx, ci); cerr != nil {
			return nil, fmt.Errorf("create ConnectorInstance %s/%s: %w", ns, d.GetConnectorId(), cerr)
		}
		return ci, nil
	case err != nil:
		return nil, fmt.Errorf("get ConnectorInstance %s/%s: %w", ns, d.GetConnectorId(), err)
	}
	if ci.Labels[labelManagedBy] != connectorOperatorManagedBy {
		return nil, fmt.Errorf("ConnectorInstance %s/%s exists and is not managed by %s",
			ns, ci.Name, connectorOperatorManagedBy)
	}
	want.Credentials = ci.Spec.Credentials
	if !reflect.DeepEqual(ci.Spec, want) {
		ci.Spec = want
		if uerr := r.Client.Update(ctx, ci); uerr != nil {
			return nil, fmt.Errorf("update ConnectorInstance %s/%s: %w", ns, ci.Name, uerr)
		}
	}
	return ci, nil
}

// prune deletes each ConnectorInstance of this loop that no tenant wants. It
// never touches a ConnectorInstance without the label of this loop.
func (r *DesiredConnectorsRunnable) prune(
	ctx context.Context, items []connectorv1alpha1.ConnectorInstance, wanted map[string]struct{},
) error {
	var failures []error
	for i := range items {
		ci := &items[i]
		if ci.Labels[labelManagedBy] != connectorOperatorManagedBy || !ci.DeletionTimestamp.IsZero() {
			continue
		}
		tenant, ok := tenantOf(ci)
		if !ok {
			continue
		}
		if _, keep := wanted[pairKey(tenant, ci.Name)]; keep {
			continue
		}
		if err := r.Client.Delete(ctx, ci); err != nil && !apierrors.IsNotFound(err) {
			failures = append(failures, fmt.Errorf("delete ConnectorInstance %s/%s: %w", ci.Namespace, ci.Name, err))
		}
	}
	return errors.Join(failures...)
}

// needsCredential reports whether a connector has a connector-cred Secret: an
// OAuth or a static token, or a declared credential.
func needsCredential(ci *connectorv1alpha1.ConnectorInstance) bool {
	return ci.Spec.Auth == connectorv1alpha1.ConnectorAuthOAuth ||
		ci.Spec.Auth == connectorv1alpha1.ConnectorAuthSecret ||
		len(ci.Spec.Credentials) > 0
}

// syncCredential writes the connector-cred Secret of one ConnectorInstance
// from the daemon (gibson#663), or deletes it when the daemon says that the
// token is past its expiry. The Secret has an ownerReference to the
// ConnectorInstance, so Kubernetes deletes it with the connector. The whole
// data set is replaced, so a withdrawn token or a removed ref leaves.
func (r *DesiredConnectorsRunnable) syncCredential(
	ctx context.Context, tenant string, ci *connectorv1alpha1.ConnectorInstance,
) error {
	if !needsCredential(ci) {
		return nil
	}
	req := &daemonoperatorv1.GetConnectorCredentialRequest{TenantId: tenant, ConnectorId: ci.Spec.Connector}
	for _, ref := range ci.Spec.Credentials {
		req.Credentials = append(req.Credentials, &daemonoperatorv1.ConnectorCredentialRef{
			Key: ref.Key, Property: ref.Property, TargetEnv: ref.EnvName(),
		})
	}
	resp, err := r.Daemon.ConnectorCredential(ctx, req)
	if err != nil {
		return fmt.Errorf("read the credential of %s/%s: %w", ci.Namespace, ci.Name, err)
	}
	name := credentialSecretName(ci.Name)
	if resp.GetWithdraw() {
		sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ci.Namespace}}
		if derr := r.Client.Delete(ctx, sec); derr != nil && !apierrors.IsNotFound(derr) {
			return fmt.Errorf("withdraw Secret %s/%s: %w", ci.Namespace, name, derr)
		}
		return nil
	}
	if len(resp.GetData()) == 0 {
		return nil // nothing minted and nothing declared
	}
	sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ci.Namespace}}
	owner := metav1.OwnerReference{
		APIVersion: connectorv1alpha1.GroupVersion.String(),
		Kind:       "ConnectorInstance",
		Name:       ci.Name,
		UID:        ci.UID,
	}
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, sec, func() error {
		sec.Type = corev1.SecretTypeOpaque
		sec.Data = resp.GetData()
		sec.OwnerReferences = []metav1.OwnerReference{owner}
		return nil
	}); err != nil {
		return fmt.Errorf("apply Secret %s/%s: %w", ci.Namespace, name, err)
	}
	return nil
}
