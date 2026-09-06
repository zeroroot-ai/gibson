// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package reconciler

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	connectorv1alpha1 "github.com/zeroroot-ai/gibson/operators/connector/api/v1alpha1"
	"github.com/zeroroot-ai/sdk/auth"
)

// tenantNamespacePrefix is the fixed prefix of a per-tenant namespace
// (tenant-<id>), the same convention the ConnectorService writes CRs into
// (owner_ref.go). ConnectorInstances live only in tenant namespaces, so the
// prefix is how a listed CR's tenant is recovered.
const tenantNamespacePrefix = "tenant-"

// ConnectorInstanceLister lists ConnectorInstance CRs. It is the one capability
// the ConnectorInstance-backed catalog source needs; a controller-runtime
// client.Client satisfies it, and the controller-runtime fake client satisfies
// it in tests — no live cluster, no Postgres. Narrowed to List so the source
// declares exactly what it reads and nothing more.
type ConnectorInstanceLister interface {
	List(ctx context.Context, list ctrlclient.ObjectList, opts ...ctrlclient.ListOption) error
}

// ConnectorInstanceCatalogSource derives the desired per-tenant connector set
// from ConnectorInstance CRs (the ToolHive path, group gibson.zeroroot.ai,
// ADR-0014), NOT from connector_manifest-row presence. Each ConnectorInstance
// is one connector enabled for one tenant; its namespace is tenant-<id> and
// Spec.Connector is the grant key. An oauth connector carries a vendor token
// the freshener keeps warm; a secret connector carries a customer-supplied
// static credential (ADR-0015). Both are published to the connector-cred
// Secret by the materializer, so both are in the set the token loop walks. A
// connector with auth none has nothing to publish and is skipped.
//
// This severs the connector-OAuth refresh path from the legacy connector
// runtime removed in ADR-0065: the freshener no longer depends on
// connector_manifest-row presence, so the legacy runtime could be removed
// (gibson#1524) without connector OAuth going dark. Satisfies CatalogSource.
type ConnectorInstanceCatalogSource struct {
	Lister ConnectorInstanceLister
	Logger *slog.Logger
}

// carriesVendorCredential reports whether a connector of this auth kind has a
// credential in the tenant store for the materializer to publish: an OAuth
// access token (oauth) or a customer-supplied static credential (secret).
func carriesVendorCredential(kind connectorv1alpha1.ConnectorAuthKind) bool {
	return kind == connectorv1alpha1.ConnectorAuthOAuth || kind == connectorv1alpha1.ConnectorAuthSecret
}

// DesiredConnectors lists every ConnectorInstance across tenant namespaces and
// returns the oauth- and secret-auth ones as (tenant, connector) pairs. A list
// failure fails the whole pass — the token reconciler then skips the tick and
// retries, never acting on a partial set. A ConnectorInstance outside a tenant
// namespace, or with a malformed tenant id, is data corruption rather than a
// transient read failure, so it is skipped, not fatal.
func (s *ConnectorInstanceCatalogSource) DesiredConnectors(ctx context.Context) ([]ConnectorSandbox, error) {
	logger := s.Logger
	if logger == nil {
		logger = slog.Default()
	}

	var list connectorv1alpha1.ConnectorInstanceList
	if err := s.Lister.List(ctx, &list); err != nil {
		return nil, fmt.Errorf("connector instance catalog source: list ConnectorInstances: %w", err)
	}

	desired := make([]ConnectorSandbox, 0, len(list.Items))
	for i := range list.Items {
		ci := &list.Items[i]
		if !carriesVendorCredential(ci.Spec.Auth) {
			continue
		}
		ns := ci.GetNamespace()
		if !strings.HasPrefix(ns, tenantNamespacePrefix) {
			logger.Warn("connector instance catalog source: skipping ConnectorInstance outside a tenant namespace",
				"namespace", ns, "name", ci.GetName())
			continue
		}
		tenantID := strings.TrimPrefix(ns, tenantNamespacePrefix)
		tid, err := auth.NewTenantID(tenantID)
		if err != nil {
			logger.Warn("connector instance catalog source: skipping malformed tenant namespace",
				"namespace", ns, "err", err)
			continue
		}
		connector := ci.Spec.Connector
		if connector == "" {
			connector = ci.GetName() // BuildConnectorInstance sets Name == Spec.Connector
		}
		desired = append(desired, ConnectorSandbox{
			Tenant:    tid,
			Connector: connector,
			// The CR identity the materializer needs for the connector-cred
			// Secret's ownerReference (ADR-0015). Name and UID come straight
			// from the listed CR; the namespace is the tenant namespace above.
			Namespace:    ns,
			InstanceName: ci.GetName(),
			InstanceUID:  ci.GetUID(),
		})
	}
	return desired, nil
}
