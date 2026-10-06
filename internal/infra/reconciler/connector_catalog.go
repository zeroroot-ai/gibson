// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package reconciler

import (
	"context"

	"github.com/zeroroot-ai/sdk/auth"
)

// ConnectorSandbox is one (tenant, connector) the connector-token freshener
// keeps a vendor access token warm for, because the tenant has the connector
// enabled and it uses OAuth.
//
// The name is historical: connectors now run on ToolHive behind a
// ConnectorInstance CR (ADR-0114), not as per-tenant setec sandboxes.
type ConnectorSandbox struct {
	Tenant    auth.TenantID
	Connector string // the catalog id, e.g. "gitlab"
}

// CatalogSource enumerates the connectors each tenant has enabled — the
// desired set the connector-token freshener walks. The daemon reads it from
// the table of tenant connectors (gibson#662).
type CatalogSource interface {
	DesiredConnectors(ctx context.Context) ([]ConnectorSandbox, error)
}
