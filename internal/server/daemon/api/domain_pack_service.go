// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"math"
	"sort"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
	"github.com/zeroroot-ai/gibson/internal/engine/settlement/auditcel"
	"github.com/zeroroot-ai/gibson/internal/engine/settlement/celenv"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// DomainPackService is the daemon API a tenant admin drives to enable and
// disable curated Domain Packs (ADR-0133, gibson#381). It serves the catalog
// + enable/disable lifecycle: ListDomainPackCatalog, ListDomainPacks,
// EnableDomainPack, DisableDomainPack.
//
// EnableDomainPack submits a DomainPackEnabled event to the caller's tenant
// brain.Engine — Timeline-durable, replayable, and folded into that tenant's
// World only (brain.Registry structurally isolates tenants, ADR-0101), never
// another tenant's. DisableDomainPack submits DomainPackDisabled. Neither RPC
// touches pack CONTENT: the catalog is the shipped, versioned source of
// truth (ADR-0133) and this service never hot-reloads it —
// enabling/disabling is the only lever.
type DomainPackService struct {
	tenantv1.UnimplementedDomainPackServiceServer

	registry *brain.Registry
	catalog  *ontology.DomainPackCatalog

	// gate answers the platform catalog gate (ADR-0133,
	// mirroring ConnectorService's ADR-0067 gate): a pack without its
	// platform_enabled tuple from the system tenant is invisible to
	// ListDomainPackCatalog and refused by EnableDomainPack. Required — the
	// service is not registered without it.
	gate CatalogGate

	// imports stores a pack that the Platform owner imports (gibson#712).
	imports PackImportStore
}

// NewDomainPackService constructs the service over the given tenant brain
// registry, catalog, catalog gate, and the store of imported packs.
func NewDomainPackService(
	registry *brain.Registry, catalog *ontology.DomainPackCatalog, gate CatalogGate, imports PackImportStore,
) *DomainPackService {
	return &DomainPackService{registry: registry, catalog: catalog, gate: gate, imports: imports}
}

// engine resolves the caller's tenant from the ext-authz context and returns
// its brain engine (created on first use). Cross-tenant access is
// structurally impossible — a caller only ever reaches its own tenant's
// engine (mirrors worldServer.engine).
func (s *DomainPackService) engine(ctx context.Context, rpc string) (*brain.Engine, auth.TenantID, error) {
	tenantID, ok := auth.TenantFromContext(ctx)
	if !ok || tenantID.IsZero() {
		return nil, auth.TenantID{}, status_grpc.Errorf(codes.PermissionDenied, "%s: missing tenant in context", rpc)
	}
	eng, ok := TenantEngine(s.registry, tenantID.String())
	if !ok {
		return nil, auth.TenantID{}, ErrWorldUnavailable
	}
	return eng, tenantID, nil
}

// ListDomainPackCatalog returns the curated Domain Packs the tenant may
// enable.
func (s *DomainPackService) ListDomainPackCatalog(
	ctx context.Context, _ *tenantv1.ListDomainPackCatalogRequest,
) (*tenantv1.ListDomainPackCatalogResponse, error) {
	if _, _, err := s.engine(ctx, "ListDomainPackCatalog"); err != nil {
		return nil, err
	}
	packs := s.catalog.List()
	// The platform catalog gate (ADR-0133): an entry is
	// visible iff its component object carries platform_enabled from the
	// system tenant, same mechanism ConnectorService.ListCatalog uses. Fail
	// closed on a gate error.
	checks := make([]authz.CheckRequest, len(packs))
	for i, p := range packs {
		checks[i] = authz.CheckRequest{
			User:     systemTenantRef,
			Relation: "platform_enabled",
			Object:   authz.DomainPackComponentObject(p.Name),
		}
	}
	allowed, err := s.gate.BatchCheck(ctx, checks)
	if err != nil || len(allowed) != len(packs) {
		return nil, status_grpc.Errorf(codes.Internal, "ListDomainPackCatalog: catalog gate: %v", err)
	}
	out := make([]*tenantv1.DomainPackCatalogEntry, 0, len(packs))
	for i, p := range packs {
		if !allowed[i] {
			continue
		}
		out = append(out, domainPackCatalogEntryView(p))
	}
	return &tenantv1.ListDomainPackCatalogResponse{Entries: out}, nil
}

// ListDomainPacks returns the tenant's currently enabled Domain Packs.
func (s *DomainPackService) ListDomainPacks(
	ctx context.Context, _ *tenantv1.ListDomainPacksRequest,
) (*tenantv1.ListDomainPacksResponse, error) {
	e, _, err := s.engine(ctx, "ListDomainPacks")
	if err != nil {
		return nil, err
	}
	out := make([]*tenantv1.DomainPackView, 0)
	for _, p := range e.DomainPacks() {
		out = append(out, &tenantv1.DomainPackView{
			Name:       p.Name,
			Version:    int32Count(p.Version),
			Techniques: sortedPredicateKeys(p.Predicates),
		})
	}
	return &tenantv1.ListDomainPacksResponse{Packs: out}, nil
}

// EnableDomainPack folds a DomainPackEnabled event that loads the named
// catalog pack's taxonomy/ontology/CEL predicate bindings into the caller's
// tenant World.
func (s *DomainPackService) EnableDomainPack(
	ctx context.Context, req *tenantv1.EnableDomainPackRequest,
) (*tenantv1.EnableDomainPackResponse, error) {
	e, _, err := s.engine(ctx, "EnableDomainPack")
	if err != nil {
		return nil, err
	}
	name := req.GetName()
	if name == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "EnableDomainPack: name is required")
	}
	pack, ok := s.catalog.Get(name)
	if !ok {
		return nil, status_grpc.Errorf(codes.NotFound, "EnableDomainPack: domain pack %q is not in the catalog", name)
	}
	// The platform catalog gate: a de-listed pack reads as not-in-catalog,
	// matching its invisibility in ListDomainPackCatalog. Fail closed on a
	// gate error.
	allowed, err := s.gate.Check(ctx, systemTenantRef, "platform_enabled", authz.DomainPackComponentObject(pack.Name))
	if err != nil {
		return nil, status_grpc.Errorf(codes.Internal, "EnableDomainPack: catalog gate: %v", err)
	}
	if !allowed {
		return nil, status_grpc.Errorf(codes.NotFound, "EnableDomainPack: domain pack %q is not in the catalog", pack.Name)
	}
	// Every pack is free (ADR-0133 withdrawn, gibson#384): the
	// catalog gate above is the only gate on enable. No entitlement check.
	//
	// Fail closed on the pack's CEL predicates before folding the enable event
	// (ADR-0131, gibson#388/#398): DomainPack.Validate above
	// (via the catalog gate path and NewDomainPackCatalog) only checks the
	// predicate expressions are well-formed TEXT, never that they compile and
	// type-check as CEL against the gibson-owned environment. LoadDomainPack
	// compiles every technique's predicate against one shared environment and
	// fails the whole enable on the first bad one, so a pack with one broken
	// predicate never becomes live for a tenant — the guarantee its own doc
	// comment promises, run at the one point that gates a pack's Predicates
	// map from ever reaching a tenant's World (domain_pack.go's
	// applyDomainPackEnabled stores them as opaque, uncompiled text).
	if _, err := celenv.LoadDomainPack(&pack); err != nil {
		return nil, status_grpc.Errorf(codes.InvalidArgument,
			"EnableDomainPack: domain pack %q: %v", pack.Name, err)
	}
	// The same rule for the compliance mapping rules (gibson#765): each one
	// compiles against the audit event environment, or the pack does not
	// become live. The rules come from the catalog only. The request names a
	// pack and carries no rule, so a tenant cannot change a first-party rule.
	if _, err := auditcel.LoadMappingRules(&pack); err != nil {
		return nil, status_grpc.Errorf(codes.InvalidArgument,
			"EnableDomainPack: domain pack %q: %v", pack.Name, err)
	}
	e.Submit(brain.DomainPackEnabled{
		Name:                      pack.Name,
		Version:                   pack.Version,
		TaxonomyNodeLabels:        append([]string(nil), pack.TaxonomyNodeLabels...),
		TaxonomyRelationshipTypes: append([]string(nil), pack.TaxonomyRelationshipTypes...),
		Predicates:                clonePredicates(pack.Predicates),
		NonDestructivePredicates:  append([]string(nil), pack.NonDestructivePredicates...),
		Techniques:                clonePredicates(pack.Techniques),
	})
	return &tenantv1.EnableDomainPackResponse{Name: pack.Name, Version: int32Count(pack.Version)}, nil
}

// DisableDomainPack folds a DomainPackDisabled event that removes the pack's
// content from the caller's tenant World.
func (s *DomainPackService) DisableDomainPack(
	ctx context.Context, req *tenantv1.DisableDomainPackRequest,
) (*tenantv1.DisableDomainPackResponse, error) {
	e, _, err := s.engine(ctx, "DisableDomainPack")
	if err != nil {
		return nil, err
	}
	name := req.GetName()
	if name == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "DisableDomainPack: name is required")
	}
	e.Submit(brain.DomainPackDisabled{Name: name})
	return &tenantv1.DisableDomainPackResponse{}, nil
}

// domainPackCatalogEntryView maps an ontology.DomainPack to its proto catalog
// view.
func domainPackCatalogEntryView(p ontology.DomainPack) *tenantv1.DomainPackCatalogEntry {
	return &tenantv1.DomainPackCatalogEntry{
		Name:                      p.Name,
		Version:                   int32Count(p.Version),
		Author:                    p.Author,
		Visibility:                string(p.Visibility),
		TaxonomyNodeLabels:        append([]string(nil), p.TaxonomyNodeLabels...),
		TaxonomyRelationshipTypes: append([]string(nil), p.TaxonomyRelationshipTypes...),
		Techniques:                sortedPredicateKeys(p.Predicates),
	}
}

// sortedPredicateKeys returns m's keys, sorted — used to surface a pack's
// bound technique names without exposing the underlying CEL expression text.
func sortedPredicateKeys(m map[string]string) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// int32Count converts a non-negative count to int32, saturating at
// math.MaxInt32 (mirrors daemon.int32Count in world_service.go). A Pack's
// Version never realistically reaches 2^31, so saturation is a safe, honest
// bound and satisfies gosec G115 without an unchecked conversion.
func int32Count(n int) int32 {
	if n < 0 {
		return 0
	}
	if n > math.MaxInt32 {
		return math.MaxInt32
	}
	return int32(n)
}

// clonePredicates returns a defensive copy of m so the folded event never
// aliases the catalog's own DomainPack.Predicates map.
func clonePredicates(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
