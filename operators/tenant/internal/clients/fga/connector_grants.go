// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package fga

import (
	"context"
	"errors"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
)

// Connector component grants (ADR-0067, gibson#1548).
//
// A connector is authorized as a component object
// ("component:connector/<catalog-id>", authz.ConnectorComponentObject) with
// the same default posture a plugin gets from RegisterComponent's ownership
// write:
//
//	(tenant:<id>, owner,          component:connector/<catalog-id>)
//	(tenant:<id>, tenant_enabled, component:connector/<catalog-id>)
//
// `owner` fires the model's `member from owner` computed grants — direct_read,
// direct_configure, and direct_execute for every member of the enabling
// tenant. `tenant_enabled` puts the connector in the tenant catalog
// (in_tenant_catalog gates every can_* relation). Admins narrow with the
// standard per-action deny toggles; nothing here is admin-only because the
// admin gate on enable/disable lives at the RPC layer (gibson#1547).
//
// The tenant-operator's ConnectorInstance authz controller converges exactly
// this set on every reconcile and removes exactly this set behind its
// finalizer on delete. Reseed, never migrate.

// ConnectorComponentTuples returns the connector's component tuple set for
// one tenant. The subject of both tuples is the bare tenant ref — the model
// computes member-level grants from `owner`; do not write `#member` subjects
// here.
func ConnectorComponentTuples(catalogID, tenantID string) []Tuple {
	object := authz.ConnectorComponentObject(catalogID)
	return []Tuple{
		{User: "tenant:" + tenantID, Relation: "owner", Object: object},
		{User: "tenant:" + tenantID, Relation: "tenant_enabled", Object: object},
	}
}

// WriteConnectorComponentGrants converges the connector's component tuples.
// Tuples are written one at a time so an already-existing tuple (idempotent
// success) never aborts the rest of the set.
func WriteConnectorComponentGrants(ctx context.Context, fgaClient Client, catalogID, tenantID string) error {
	for _, tuple := range ConnectorComponentTuples(catalogID, tenantID) {
		if err := fgaClient.Write(ctx, []Tuple{tuple}); err != nil {
			if errors.Is(err, clients.ErrAlreadyExists) {
				continue
			}
			return fmt.Errorf("fga: WriteConnectorComponentGrants connector=%s tenant=%s: %w",
				catalogID, tenantID, err)
		}
	}
	return nil
}

// LegacyConnectorInvokeTuple is the retired plugin-object borrow: before
// ADR-0067 a connector was authorized as (tenant#member, can_invoke,
// plugin:<tenant>/<connector>). The invoke path now checks can_execute on
// the connector component, so the authz controller reseeds this tuple away
// on every converge. Delete-only — nothing may ever write it again.
func LegacyConnectorInvokeTuple(catalogID, tenantID string) Tuple {
	return Tuple{
		User:     "tenant:" + tenantID + "#member",
		Relation: "can_invoke",
		Object:   fmt.Sprintf("plugin:%s/%s", tenantID, catalogID),
	}
}

// DeleteLegacyConnectorInvokeTuple removes the retired borrow tuple.
// Idempotent: Client.Delete treats a missing tuple as success.
func DeleteLegacyConnectorInvokeTuple(ctx context.Context, fgaClient Client, catalogID, tenantID string) error {
	if err := fgaClient.Delete(ctx, []Tuple{LegacyConnectorInvokeTuple(catalogID, tenantID)}); err != nil {
		return fmt.Errorf("fga: DeleteLegacyConnectorInvokeTuple connector=%s tenant=%s: %w",
			catalogID, tenantID, err)
	}
	return nil
}

// DeleteConnectorComponentGrants removes the connector's component tuples.
// Tuples are deleted one at a time: Client.Delete treats a missing tuple as
// idempotent success per call, but a transactional batch with one missing
// member would leave the present ones behind.
func DeleteConnectorComponentGrants(ctx context.Context, fgaClient Client, catalogID, tenantID string) error {
	for _, tuple := range ConnectorComponentTuples(catalogID, tenantID) {
		if err := fgaClient.Delete(ctx, []Tuple{tuple}); err != nil {
			return fmt.Errorf("fga: DeleteConnectorComponentGrants connector=%s tenant=%s: %w",
				catalogID, tenantID, err)
		}
	}
	return nil
}
