// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// newDomainPackService builds a DomainPackService over a fresh brain.Registry,
// the given catalog, and an allow-all catalog gate (the seeded steady state,
// mirroring newConnectorService).
func newDomainPackService(t *testing.T, catalog *ontology.DomainPackCatalog) (*DomainPackService, *brain.Registry) {
	t.Helper()
	return newDomainPackServiceWithGate(t, catalog, &stubCatalogGate{})
}

func newDomainPackServiceWithGate(t *testing.T, catalog *ontology.DomainPackCatalog, gate CatalogGate) (*DomainPackService, *brain.Registry) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	reg := brain.NewRegistry(ctx)
	return NewDomainPackService(reg, catalog, gate), reg
}

// waitForDomainPacks polls until ListDomainPacks returns n packs or the
// deadline passes — Engine.Submit is asynchronous (mirrors
// TestWorldService_TenantScopedRead's poll loop).
func waitForDomainPacks(t *testing.T, s *DomainPackService, ctx context.Context, n int) *tenantv1.ListDomainPacksResponse {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var resp *tenantv1.ListDomainPacksResponse
	for time.Now().Before(deadline) {
		var err error
		resp, err = s.ListDomainPacks(ctx, &tenantv1.ListDomainPacksRequest{})
		require.NoError(t, err)
		if len(resp.GetPacks()) == n {
			return resp
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("ListDomainPacks never reached %d packs, last = %+v", n, resp.GetPacks())
	return nil
}

func mainPack() ontology.DomainPack {
	return ontology.DomainPack{
		Name:                      "main",
		Version:                   1,
		Visibility:                ontology.PackVisibilityPublic,
		Author:                    "zeroroot",
		TaxonomyNodeLabels:        []string{"Container"},
		TaxonomyRelationshipTypes: []string{"RUNS_ON"},
		Predicates:                map[string]string{"privilege_escalation": `evidence.exists(e, e.kind == "root_shell")`},
	}
}

// -----------------------------------------------------------------------
// ListDomainPackCatalog
// -----------------------------------------------------------------------

func TestListDomainPackCatalog_ReturnsGatedEntries(t *testing.T) {
	catalog := ontology.NewDomainPackCatalog(mainPack())
	s, _ := newDomainPackService(t, catalog)

	resp, err := s.ListDomainPackCatalog(tenantCtx("acme"), &tenantv1.ListDomainPackCatalogRequest{})
	require.NoError(t, err)
	require.Len(t, resp.GetEntries(), 1)
	entry := resp.GetEntries()[0]
	assert.Equal(t, "main", entry.GetName())
	assert.Equal(t, int32(1), entry.GetVersion())
	assert.Equal(t, "zeroroot", entry.GetAuthor())
	assert.Equal(t, "public", entry.GetVisibility())
	assert.Equal(t, []string{"Container"}, entry.GetTaxonomyNodeLabels())
	assert.Equal(t, []string{"privilege_escalation"}, entry.GetTechniques())
}

func TestListDomainPackCatalog_Empty(t *testing.T) {
	s, _ := newDomainPackService(t, ontology.NewDomainPackCatalog())
	resp, err := s.ListDomainPackCatalog(tenantCtx("acme"), &tenantv1.ListDomainPackCatalogRequest{})
	require.NoError(t, err)
	assert.Empty(t, resp.GetEntries())
}

func TestListDomainPackCatalog_HidesDelistedEntry(t *testing.T) {
	catalog := ontology.NewDomainPackCatalog(mainPack())
	gate := &stubCatalogGate{denied: []string{"component:domainpack/main"}}
	s, _ := newDomainPackServiceWithGate(t, catalog, gate)

	resp, err := s.ListDomainPackCatalog(tenantCtx("acme"), &tenantv1.ListDomainPackCatalogRequest{})
	require.NoError(t, err)
	assert.Empty(t, resp.GetEntries(), "a de-listed pack must be invisible")
}

func TestListDomainPackCatalog_GateErrorIsInternal(t *testing.T) {
	catalog := ontology.NewDomainPackCatalog(mainPack())
	gate := &stubCatalogGate{err: errConnectorBoom}
	s, _ := newDomainPackServiceWithGate(t, catalog, gate)

	_, err := s.ListDomainPackCatalog(tenantCtx("acme"), &tenantv1.ListDomainPackCatalogRequest{})
	assert.Equal(t, codes.Internal, grpcCode(err), "a gate error must fail closed, never fail open")
}

func TestListDomainPackCatalog_NoTenant(t *testing.T) {
	s, _ := newDomainPackService(t, ontology.NewDomainPackCatalog())
	_, err := s.ListDomainPackCatalog(context.Background(), &tenantv1.ListDomainPackCatalogRequest{})
	assert.Equal(t, codes.PermissionDenied, grpcCode(err))
}

// -----------------------------------------------------------------------
// EnableDomainPack / ListDomainPacks
// -----------------------------------------------------------------------

func TestEnableDomainPack_MakesItLiveInTenantOnly(t *testing.T) {
	catalog := ontology.NewDomainPackCatalog(mainPack())
	s, _ := newDomainPackService(t, catalog)

	resp, err := s.EnableDomainPack(tenantCtx("acme"), &tenantv1.EnableDomainPackRequest{Name: "main"})
	require.NoError(t, err)
	assert.Equal(t, "main", resp.GetName())
	assert.Equal(t, int32(1), resp.GetVersion())

	got := waitForDomainPacks(t, s, tenantCtx("acme"), 1)
	assert.Equal(t, "main", got.GetPacks()[0].GetName())
	assert.Equal(t, []string{"privilege_escalation"}, got.GetPacks()[0].GetTechniques())

	// ADR-0033 decision 1: "per-tenant, not per-install" — another tenant
	// must never see acme's enabled pack.
	other, err := s.ListDomainPacks(tenantCtx("other"), &tenantv1.ListDomainPacksRequest{})
	require.NoError(t, err)
	assert.Empty(t, other.GetPacks(), "enabling a pack in one tenant must never leak into another")
}

func TestEnableDomainPack_UnknownName(t *testing.T) {
	s, _ := newDomainPackService(t, ontology.NewDomainPackCatalog())
	_, err := s.EnableDomainPack(tenantCtx("acme"), &tenantv1.EnableDomainPackRequest{Name: "nonexistent"})
	assert.Equal(t, codes.NotFound, grpcCode(err))
}

func TestEnableDomainPack_EmptyName(t *testing.T) {
	s, _ := newDomainPackService(t, ontology.NewDomainPackCatalog())
	_, err := s.EnableDomainPack(tenantCtx("acme"), &tenantv1.EnableDomainPackRequest{})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
}

func TestEnableDomainPack_DelistedIsNotFound(t *testing.T) {
	catalog := ontology.NewDomainPackCatalog(mainPack())
	gate := &stubCatalogGate{denied: []string{"component:domainpack/main"}}
	s, _ := newDomainPackServiceWithGate(t, catalog, gate)

	_, err := s.EnableDomainPack(tenantCtx("acme"), &tenantv1.EnableDomainPackRequest{Name: "main"})
	assert.Equal(t, codes.NotFound, grpcCode(err))
}

func TestEnableDomainPack_GateErrorIsInternal(t *testing.T) {
	catalog := ontology.NewDomainPackCatalog(mainPack())
	gate := &stubCatalogGate{err: errConnectorBoom}
	s, _ := newDomainPackServiceWithGate(t, catalog, gate)

	_, err := s.EnableDomainPack(tenantCtx("acme"), &tenantv1.EnableDomainPackRequest{Name: "main"})
	assert.Equal(t, codes.Internal, grpcCode(err))
}

func TestEnableDomainPack_EntitledPackFailsClosed(t *testing.T) {
	entitled := mainPack()
	entitled.Name = "premium"
	entitled.Entitlement = "premium_intel"
	catalog := ontology.NewDomainPackCatalog(entitled)
	s, _ := newDomainPackService(t, catalog)

	_, err := s.EnableDomainPack(tenantCtx("acme"), &tenantv1.EnableDomainPackRequest{Name: "premium"})
	assert.Equal(t, codes.FailedPrecondition, grpcCode(err),
		"a pack with a non-empty Entitlement must fail closed until the commercial seam is wired")
}

func TestEnableDomainPack_NoTenant(t *testing.T) {
	s, _ := newDomainPackService(t, ontology.NewDomainPackCatalog())
	_, err := s.EnableDomainPack(context.Background(), &tenantv1.EnableDomainPackRequest{Name: "main"})
	assert.Equal(t, codes.PermissionDenied, grpcCode(err))
}

// -----------------------------------------------------------------------
// DisableDomainPack
// -----------------------------------------------------------------------

func TestDisableDomainPack_RemovesIt(t *testing.T) {
	catalog := ontology.NewDomainPackCatalog(mainPack())
	s, _ := newDomainPackService(t, catalog)

	_, err := s.EnableDomainPack(tenantCtx("acme"), &tenantv1.EnableDomainPackRequest{Name: "main"})
	require.NoError(t, err)
	waitForDomainPacks(t, s, tenantCtx("acme"), 1)

	_, err = s.DisableDomainPack(tenantCtx("acme"), &tenantv1.DisableDomainPackRequest{Name: "main"})
	require.NoError(t, err)
	waitForDomainPacks(t, s, tenantCtx("acme"), 0)
}

func TestDisableDomainPack_EmptyName(t *testing.T) {
	s, _ := newDomainPackService(t, ontology.NewDomainPackCatalog())
	_, err := s.DisableDomainPack(tenantCtx("acme"), &tenantv1.DisableDomainPackRequest{})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
}

func TestDisableDomainPack_NoTenant(t *testing.T) {
	s, _ := newDomainPackService(t, ontology.NewDomainPackCatalog())
	_, err := s.DisableDomainPack(context.Background(), &tenantv1.DisableDomainPackRequest{Name: "main"})
	assert.Equal(t, codes.PermissionDenied, grpcCode(err))
}

// -----------------------------------------------------------------------
// ListDomainPacks
// -----------------------------------------------------------------------

func TestListDomainPacks_NoTenant(t *testing.T) {
	s, _ := newDomainPackService(t, ontology.NewDomainPackCatalog())
	_, err := s.ListDomainPacks(context.Background(), &tenantv1.ListDomainPacksRequest{})
	assert.Equal(t, codes.PermissionDenied, grpcCode(err))
}

func TestListDomainPacks_EmptyByDefault(t *testing.T) {
	s, _ := newDomainPackService(t, ontology.NewDomainPackCatalog())
	resp, err := s.ListDomainPacks(tenantCtx("acme"), &tenantv1.ListDomainPacksRequest{})
	require.NoError(t, err)
	assert.Empty(t, resp.GetPacks())
}
