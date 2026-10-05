// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
	"github.com/zeroroot-ai/gibson/internal/engine/settlement/celenv"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// TestEnableDomainPack_MainCatalogPack_BindingsGoLive is the acceptance test
// for gibson#382 (epic #376, ADR-0133): the real, seeded "main" catalog pack
// (ontology.MainDomainPack — the same value the daemon wires into its
// DomainPackCatalog at startup, see internal/server/daemon/infrastructure.go)
// is default-off for a fresh tenant, and EnableDomainPack makes its CEL
// predicate bindings live — present in that tenant's World, and still
// compiling against the gibson-owned CEL environment once they get there —
// in that tenant alone.
func TestEnableDomainPack_MainCatalogPack_BindingsGoLive(t *testing.T) {
	catalog := ontology.NewDomainPackCatalog(ontology.MainDomainPack())
	s, registry := newDomainPackService(t, catalog)

	// Default-off (ADR-0133): a fresh tenant starts with no
	// enabled packs, so none of the catalog pack's predicates are bound to
	// anything yet — no bet could settle TRUE against them.
	before, err := s.ListDomainPacks(tenantCtx("acme"), &tenantv1.ListDomainPacksRequest{})
	require.NoError(t, err)
	assert.Empty(t, before.GetPacks(), "a fresh tenant must start with the main pack disabled")

	resp, err := s.EnableDomainPack(tenantCtx("acme"), &tenantv1.EnableDomainPackRequest{Name: ontology.MainDomainPackName})
	require.NoError(t, err)
	assert.Equal(t, ontology.MainDomainPackName, resp.GetName())

	waitForDomainPacks(tenantCtx("acme"), t, s, 1)

	snap := registry.For("acme").DomainPacks()
	require.Len(t, snap, 1)
	assert.Equal(t, ontology.MainDomainPackName, snap[0].Name)
	assert.Equal(t, ontology.MainDomainPack().Predicates, snap[0].Predicates,
		"the bindings folded into the tenant World must be exactly what the catalog shipped")

	// Still loadable — compiles and type-checks against the gibson-owned CEL
	// environment — now that it has traveled through the brain event fold,
	// the same LoadDomainPack path gibson#389's SubmitProof handler will run.
	compiled, err := celenv.LoadDomainPack(&ontology.DomainPack{
		Name:       snap[0].Name,
		Version:    snap[0].Version,
		Predicates: snap[0].Predicates,
	})
	require.NoError(t, err)
	assert.Len(t, compiled, len(snap[0].Predicates))

	// ADR-0133: "per-tenant, not per-install" — another tenant
	// must never see acme's enabled pack.
	other, err := s.ListDomainPacks(tenantCtx("other"), &tenantv1.ListDomainPacksRequest{})
	require.NoError(t, err)
	assert.Empty(t, other.GetPacks(), "enabling a pack in one tenant must never leak into another")
}
