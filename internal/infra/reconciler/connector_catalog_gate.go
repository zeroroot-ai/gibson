// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package reconciler

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

// CatalogRef is a (kind, id) pair whose canonical FGA object is
// authz.ComponentObject(Kind, ID) = "component:<kind>/<id>".
type CatalogRef struct {
	Kind string
	ID   string
}

// SeedComponentCatalogGate converges the platform catalog gate for every kind
// (ADR-0136, generalizing ADR-0067): every embedded catalog entry gets a
// `platform_enabled` tuple from the system tenant on its canonical
// `component:<kind>/<id>` object. ConnectorService checks this tuple in
// ListCatalog and EnableConnector.
//
// Startup converge. The embedded catalog table is the source of truth for
// what is listed: platform de-listing is removing the entry from the table (a
// release). This function adds the missing tuples. PruneComponentCatalogGate
// removes the tuple of each entry that left the table (gibson#750).
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

// PruneComponentCatalogGate removes the `platform_enabled` tuple of each
// component of the given kinds that the catalog no longer lists. A component
// that leaves the embedded table thus leaves the platform at the next daemon
// start (ADR-0027, gibson#750). listed is the whole embedded table of those
// kinds, not only the entries that passed image verification: a component
// whose signature check fails is not seeded, but this function does not
// remove it either. Only tuples that exist are deleted, so the delete never
// names a missing tuple.
func PruneComponentCatalogGate(ctx context.Context, authorizer authz.Authorizer, kinds []string, listed []CatalogRef, logger *slog.Logger) error {
	if len(kinds) == 0 {
		return nil
	}
	existing, err := authorizer.ListObjects(ctx, "system_tenant:_system", "platform_enabled", "component")
	if err != nil {
		return fmt.Errorf("component catalog gate: list platform_enabled: %w", err)
	}
	owned := make(map[string]bool, len(kinds))
	for _, k := range kinds {
		owned[k] = true
	}
	keep := make(map[string]bool, len(listed))
	for _, ref := range listed {
		keep[authz.ComponentObject(ref.Kind, ref.ID)] = true
	}
	var retired []authz.Tuple
	for _, e := range existing {
		object := e
		if !strings.HasPrefix(object, "component:") {
			object = "component:" + object
		}
		kind, _, ok := strings.Cut(strings.TrimPrefix(object, "component:"), "/")
		if !ok || !owned[kind] || keep[object] {
			continue
		}
		retired = append(retired, authz.Tuple{
			User:     "system_tenant:_system",
			Relation: "platform_enabled",
			Object:   object,
		})
	}
	if len(retired) == 0 {
		return nil
	}
	if err := authorizer.Delete(ctx, retired); err != nil {
		return fmt.Errorf("component catalog gate: delete %d retired tuples: %w", len(retired), err)
	}
	logger.Info("component catalog gate pruned", "deleted", len(retired))
	return nil
}
