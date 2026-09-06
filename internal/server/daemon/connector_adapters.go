// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"fmt"

	apiruntime "k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"google.golang.org/grpc"

	discoverysvc "github.com/zeroroot-ai/gibson/internal/server/api/discovery"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	connectorv1alpha1 "github.com/zeroroot-ai/gibson/operators/connector/api/v1alpha1"
)

// registerConnector registers gibson.tenant.v1.ConnectorService on srv. The
// service writes ConnectorInstance CRs into tenant namespaces with a narrow
// controller-runtime client; the connector-operator reconciles them (ADR-0014).
//
// The client uses the in-cluster (or KUBECONFIG) config and a scheme carrying
// the ConnectorInstance types. When no cluster config is reachable — a unit
// test, a detached daemon — the service is not registered rather than served
// with a nil client; a caller then gets Unimplemented, which is the honest
// answer for a daemon that cannot reach the API server.
func (d *daemonImpl) registerConnector(ctx context.Context, srv *grpc.Server) {
	kube, err := d.connectorKubeClient()
	if err != nil {
		d.logger.Warn(ctx, "ConnectorService: no kube client; not registering", "error", err)
		return
	}
	// The platform catalog gate (ADR-0067) needs the authorizer. Without one
	// the service is not registered — Unimplemented, never a fail-open
	// catalog.
	if d.authorizer == nil {
		d.logger.Warn(ctx, "ConnectorService: no authorizer; not registering")
		return
	}
	tenantv1.RegisterConnectorServiceServer(srv, api.NewConnectorService(kube, d.authorizer))
	d.logger.Info(ctx, "ConnectorService registered (ADR-0014)")
}

// connectorInstanceLister adapts the narrow ConnectorInstance kube client to
// discovery.ConnectorLister (ADR-0067): the tenant's enabled connectors are
// its ConnectorInstance CR names (the catalog ids).
type connectorInstanceLister struct{ kube client.Client }

func (l *connectorInstanceLister) ListEnabledConnectors(ctx context.Context, tenant string) ([]string, error) {
	var list connectorv1alpha1.ConnectorInstanceList
	if err := l.kube.List(ctx, &list, client.InNamespace("tenant-"+tenant)); err != nil {
		return nil, fmt.Errorf("list connector instances: %w", err)
	}
	ids := make([]string, 0, len(list.Items))
	for i := range list.Items {
		ids = append(ids, list.Items[i].Name)
	}
	return ids, nil
}

// connectorLister returns the discovery ConnectorLister, or nil when the
// daemon has no kube client — ListConnectors then fails closed.
func (d *daemonImpl) connectorLister(ctx context.Context) discoverysvc.ConnectorLister {
	kube, err := d.connectorKubeClient()
	if err != nil {
		d.logger.Warn(ctx, "connector discovery: no kube client; ListConnectors unavailable", "error", err)
		return nil
	}
	return &connectorInstanceLister{kube: kube}
}

// connectorKubeClient returns the narrow ConnectorInstance controller-runtime
// client, building it once and caching it on the daemon. Both registerConnector
// (writes ConnectorInstance CRs) and registerConnectorAuth (lists them to drive
// the OAuth token freshener, ADR-0065) share it. The client is built lazily and
// does no API-server round trip here. A test may pre-set d.connectorKube (e.g.
// with the controller-runtime fake client) to inject a lister without a cluster.
func (d *daemonImpl) connectorKubeClient() (client.Client, error) {
	if d.connectorKube != nil {
		return d.connectorKube, nil
	}
	cfg, err := ctrl.GetConfig()
	if err != nil {
		return nil, fmt.Errorf("connector kube config: %w", err)
	}
	kube, err := newConnectorKubeClient(cfg)
	if err != nil {
		return nil, err
	}
	d.connectorKube = kube
	return kube, nil
}

// newConnectorKubeClient builds the narrow controller-runtime client the
// ConnectorService writes ConnectorInstance CRs with. The scheme carries the
// core Kubernetes types and the ConnectorInstance API; the client is built
// lazily, so no API-server round trip happens here.
func newConnectorKubeClient(cfg *rest.Config) (client.Client, error) {
	scheme := apiruntime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("connector kube scheme: %w", err)
	}
	if err := connectorv1alpha1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("connector CRD scheme: %w", err)
	}
	kube, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return nil, fmt.Errorf("connector kube client: %w", err)
	}
	return kube, nil
}
