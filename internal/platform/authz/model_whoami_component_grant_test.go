// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build integration

package authz_test

import (
	"context"
	"log/slog"
	"testing"
	"time"

	fgaclient "github.com/openfga/go-sdk/client"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/sdk/auth"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/identity"
	identitypb "github.com/zeroroot-ai/sdk/api/gen/gibson/identity/v1"
)

// noPrincipalLookup is the lookup of a WhoAmI self query, which resolves no
// other principal.
type noPrincipalLookup struct{}

func (noPrincipalLookup) Resolve(context.Context, string) (identity.PrincipalRecord, error) {
	return identity.PrincipalRecord{}, identity.ErrPrincipalNotFound
}

// TestIntegration_FGA_WhoAmI_ComponentPrincipalGrant enrolls a component
// principal, grants one action, and reads the grant back through WhoAmI. It
// runs the model that ships (model.fga) on a real OpenFGA server, with the
// real authorizer.
//
// WhoAmI used to read three relations that no code wrote, so its component
// grant list was empty for each principal (gibson#705). One grant now gives
// the access, and a tenant deny takes it away.
func TestIntegration_FGA_WhoAmI_ComponentPrincipalGrant(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	_, baseURL, containerCleanup := setupFGAContainer(t, ctx)
	defer containerCleanup()

	mgmt := newRawFGAClient(t, baseURL)
	storeResp, err := mgmt.CreateStore(ctx).Body(fgaclient.ClientCreateStoreRequest{
		Name: storeNameFor("whoami-component-grant", t),
	}).Execute()
	require.NoError(t, err, "create FGA store")
	storeID := storeResp.GetId()
	modelID := loadModelFromDSL(t, ctx, baseURL, storeID)

	az, err := authz.NewFgaAuthorizer(ctx, authz.FgaConfig{
		Endpoint:  baseURL,
		StoreID:   storeID,
		ModelID:   modelID,
		TimeoutMs: 5000,
		Logger:    slog.Default(),
	})
	require.NoError(t, err)
	defer func() { _ = az.Close() }()

	srv, err := identity.NewServer(identity.Config{Authorizer: az, Lookup: noPrincipalLookup{}})
	require.NoError(t, err)

	const (
		principal = "agent_principal:acct-1"
		tenantID  = "acme"
		tenant    = "tenant:" + tenantID
		backplane = "component:_system"
		nmap      = "component:tool/nmap"
	)

	// whoAmI returns the effective component grants of the principal, by
	// component.
	whoAmI := func() map[string]*identitypb.ComponentGrantEffective {
		t.Helper()
		tid, err := auth.NewTenantID(tenantID)
		require.NoError(t, err)
		callCtx := auth.WithIdentity(ctx, auth.Identity{Subject: principal, Tenant: tid})
		resp, err := srv.WhoAmI(callCtx, &identitypb.WhoAmIRequest{})
		require.NoError(t, err)
		out := make(map[string]*identitypb.ComponentGrantEffective, len(resp.GetComponentGrants()))
		for _, g := range resp.GetComponentGrants() {
			out[g.GetComponentRef()] = g
		}
		return out
	}

	// Enrollment: the principal is a member of its tenant and can execute on
	// the backplane. Both components are in the catalog of the tenant.
	require.NoError(t, az.Write(ctx, []authz.Tuple{
		{User: principal, Relation: "member", Object: tenant},
		{User: principal, Relation: "direct_execute", Object: backplane},
		{User: tenant, Relation: "tenant_enabled", Object: backplane},
		{User: tenant, Relation: "tenant_enabled", Object: nmap},
	}))

	grants := whoAmI()
	require.Contains(t, grants, backplane, "WhoAmI must show the grant from enrollment")
	require.True(t, grants[backplane].GetCanExecute())
	require.NotContains(t, grants, nmap, "no grant on nmap yet")

	// Grant one action: read on nmap. This is the tuple that WriteAgentGrants
	// writes for can_read.
	require.NoError(t, az.Write(ctx, []authz.Tuple{
		{User: principal, Relation: "direct_read", Object: nmap},
	}))

	grants = whoAmI()
	require.Contains(t, grants, nmap, "WhoAmI must show the new grant")
	require.True(t, grants[nmap].GetCanRead(), "the grant gives read")
	require.False(t, grants[nmap].GetCanConfigure(), "the grant gives read only")
	require.False(t, grants[nmap].GetCanExecute(), "the grant gives read only")

	// The tenant deny wins over the grant of a component principal.
	require.NoError(t, az.Write(ctx, []authz.Tuple{
		{User: tenant, Relation: "tenant_read_disabled", Object: nmap},
	}))
	grants = whoAmI()
	require.NotContains(t, grants, nmap, "tenant_read_disabled must remove the read access")
	require.Contains(t, grants, backplane, "the deny on nmap does not touch the backplane")
}
