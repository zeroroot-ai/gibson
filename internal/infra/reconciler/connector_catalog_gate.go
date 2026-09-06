// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package reconciler

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

// CatalogRef is a (kind, id) pair whose canonical FGA object is
// authz.ComponentObject(Kind, ID) = "component:<kind>/<id>".
type CatalogRef struct {
	Kind string
	ID   string
}

// SeedComponentCatalogGate converges the platform catalog gate for every kind
// (ADR-0015, generalizing ADR-0067): every embedded catalog entry gets a
// `platform_enabled` tuple from the system tenant on its canonical
// `component:<kind>/<id>` object. ConnectorService checks this tuple in
// ListCatalog and EnableConnector.
//
// Add-only, startup converge. The embedded catalog table is the source of
// truth for what is listed: platform de-listing is removing the entry from
// the table (a release). Removing a tuple by hand also de-lists — the check
// is the enforcement point — but only until the next daemon start reseeds it.
// Connector components are deliberately excluded from the CatalogFanout
// tenant_enabled fan-out: a tenant enables a connector through
// EnableConnector, and the tenant-operator writes its tenant_enabled tuple.
func SeedComponentCatalogGate(ctx context.Context, authorizer authz.Authorizer, refs []CatalogRef, logger *slog.Logger) error {
	if len(refs) == 0 {
		return nil
	}
	existing, err := authorizer.ListObjects(ctx, "system_tenant:_system", "platform_enabled", "component")
	if err != nil {
		return fmt.Errorf("component catalog gate: list platform_enabled: %w", err)
	}
	existingSet := make(map[string]struct{}, len(existing))
	for _, e := range existing {
		existingSet[e] = struct{}{}
		// Tolerate unprefixed ListObjects results, as CatalogFanout does.
		existingSet["component:"+e] = struct{}{}
	}
	toWrite := make([]authz.Tuple, 0, len(refs))
	for _, ref := range refs {
		object := authz.ComponentObject(ref.Kind, ref.ID)
		if _, have := existingSet[object]; have {
			continue
		}
		toWrite = append(toWrite, authz.Tuple{
			User:     "system_tenant:_system",
			Relation: "platform_enabled",
			Object:   object,
		})
	}
	if len(toWrite) == 0 {
		return nil
	}
	if err := authorizer.Write(ctx, toWrite); err != nil {
		return fmt.Errorf("component catalog gate: write %d tuples: %w", len(toWrite), err)
	}
	logger.Info("component catalog gate seeded", "written", len(toWrite))
	return nil
}
