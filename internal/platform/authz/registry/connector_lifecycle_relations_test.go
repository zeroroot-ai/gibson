// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package registry_test

// connector_lifecycle_relations_test.go pins the connector lifecycle deny
// contract (ADR-0067, gibson#1547).
//
// The registry IS the deny contract: ext-authz runs the FGA Check each entry
// names (see rpc_authz_deny_test.go). The model's tenant hierarchy is
// admin ⊆ writer ⊆ member, so an entry with relation "admin" denies a plain
// member and allows an admin, and an "admin" holder still passes "member"
// entries. Pinning the relation per RPC therefore pins exactly who may call.
//
// Contract: mutating lifecycle and grant RPCs are admin-only. Enable creates
// a ToolHive workload and an outbound OAuth surface, and it is what puts the
// connector into the tenant catalog, so no per-connector relation can gate
// it. Read RPCs stay member. Keyed by RPC name, never by registry position.

import (
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/authz/registry"
)

func TestConnectorLifecycleRelations(t *testing.T) {
	want := map[string]string{
		"/gibson.tenant.v1.ConnectorService/EnableConnector":  "admin",
		"/gibson.tenant.v1.ConnectorService/DisableConnector": "admin",
		"/gibson.tenant.v1.ConnectorService/ListCatalog":      "member",
		"/gibson.tenant.v1.ConnectorService/ListConnectors":   "member",

		"/gibson.tenant.v1.ConnectorAuthService/StartConnectorAuthorization":    "admin",
		"/gibson.tenant.v1.ConnectorAuthService/CompleteConnectorAuthorization": "admin",
		"/gibson.tenant.v1.ConnectorAuthService/RevokeConnectorGrant":           "admin",
		"/gibson.tenant.v1.ConnectorAuthService/GetConnectorAuthStatus":         "member",
	}

	for rpc, relation := range want {
		entry, ok := registry.Registry[rpc]
		if !ok {
			t.Errorf("%s: missing from the generated registry", rpc)
			continue
		}
		if entry.Relation != relation {
			t.Errorf("%s: relation = %q, want %q (ADR-0067: mutating connector RPCs are admin-only)",
				rpc, entry.Relation, relation)
		}
		if entry.ObjectType != "tenant" {
			t.Errorf("%s: object_type = %q, want %q", rpc, entry.ObjectType, "tenant")
		}
	}
}
