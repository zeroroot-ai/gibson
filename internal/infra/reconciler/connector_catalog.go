// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package reconciler

import (
	"context"

	"k8s.io/apimachinery/pkg/types"

	"github.com/zeroroot-ai/sdk/auth"
)

// ConnectorSandbox is one (tenant, connector) the connector-token freshener
// keeps a vendor access token warm for, because the tenant has the connector
// enabled. It also carries the identity of the backing ConnectorInstance CR, so
// the materializer can write the connector-cred Secret with an ownerReference
// the Kubernetes garbage collector follows on connector delete (ADR-0015).
//
// The name is historical: connectors now run on ToolHive behind a
// ConnectorInstance CR (ADR-0014), not as per-tenant setec sandboxes.
type ConnectorSandbox struct {
	Tenant    auth.TenantID
	Connector string // bare component name, e.g. "connector-gitlab"

	// Namespace is the tenant namespace (tenant-<id>) the ConnectorInstance CR
	// lives in. The materialized Secret is written here, beside the CR.
	Namespace string
	// InstanceName is the ConnectorInstance CR name. It names the Secret
	// (<InstanceName>-connector-cred) and the ownerReference target, matching
	// the connector-operator's credentialSecretName(ci.Name).
	InstanceName string
	// InstanceUID is the ConnectorInstance CR UID, required on the Secret's
	// ownerReference so Kubernetes garbage-collects the Secret with the CR.
	InstanceUID types.UID
}

// CatalogSource enumerates the connectors each tenant has enabled — the
// desired set the connector-token freshener walks. The production source is
// ConnectorInstanceCatalogSource, which derives the set from ConnectorInstance
// CRs (the ToolHive path, ADR-0014).
type CatalogSource interface {
	DesiredConnectors(ctx context.Context) ([]ConnectorSandbox, error)
}
