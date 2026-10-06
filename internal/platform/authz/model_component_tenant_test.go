// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build integration

package authz_test

import (
	"context"
	"testing"
	"time"

	fgaclient "github.com/openfga/go-sdk/client"
	"github.com/stretchr/testify/require"
)

// TestModel_AComponentGrantStaysInItsTenant proves the rule of the
// tenant-less component object (objects.go): tenant A and tenant B each
// publish a component with the same kind and name, so both use one FGA
// object. Each tuple that tenant A writes on that object (a direct grant of
// each kind, a tenant-wide grant, an enable, a deny, an owner) gives a
// principal of tenant B nothing and takes nothing from it. The data plane
// half of the rule, a lookup by (tenant, name), is proven by
// TestRedisRegistry_TenantIsolation in internal/platform/component.
func TestModel_AComponentGrantStaysInItsTenant(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	_, baseURL, containerCleanup := setupFGAContainer(t, ctx)
	defer containerCleanup()

	mgmt := newRawFGAClient(t, baseURL)
	storeResp, err := mgmt.CreateStore(ctx).Body(fgaclient.ClientCreateStoreRequest{
		Name: storeNameFor("component-tenant", t),
	}).Execute()
	require.NoError(t, err)
	storeID := storeResp.GetId()
	modelID := loadModelFromDSL(t, ctx, baseURL, storeID)
	c, err := fgaclient.NewSdkClient(&fgaclient.ClientConfiguration{
		ApiUrl: baseURL, StoreId: storeID, AuthorizationModelId: modelID,
	})
	require.NoError(t, err)

	write := func(tuples ...fgaclient.ClientTupleKey) {
		t.Helper()
		_, err := c.Write(ctx).Body(fgaclient.ClientWriteRequest{Writes: tuples}).Execute()
		require.NoError(t, err)
	}
	check := func(user, relation, object string) bool {
		t.Helper()
		resp, err := c.Check(ctx).Body(fgaclient.ClientCheckRequest{User: user, Relation: relation, Object: object}).Execute()
		require.NoErrorf(t, err, "Check(%s, %s, %s)", user, relation, object)
		return resp.GetAllowed()
	}

	const (
		tenantA = "tenant:a"
		tenantB = "tenant:b"
		agentA  = "agent_principal:a1"
		agentB  = "agent_principal:b1"
		userA   = "user:a-admin"
		userB   = "user:b-member"
		shared  = "component:tool/scanner"
	)
	relations := []string{"can_read", "can_configure", "can_execute", "can_poll_work"}

	// Membership, and tenant A publishes and enables the shared name.
	write(
		fgaclient.ClientTupleKey{User: agentA, Relation: "member", Object: tenantA},
		fgaclient.ClientTupleKey{User: userA, Relation: "member", Object: tenantA},
		fgaclient.ClientTupleKey{User: agentB, Relation: "member", Object: tenantB},
		fgaclient.ClientTupleKey{User: userB, Relation: "member", Object: tenantB},
		fgaclient.ClientTupleKey{User: tenantA, Relation: "owner", Object: shared},
		fgaclient.ClientTupleKey{User: tenantA, Relation: "tenant_enabled", Object: shared},
	)
	// Tenant A grants each direct relation to its own principal and to all
	// of its members.
	for _, rel := range []string{"direct_read", "direct_configure", "direct_execute", "direct_receive_work"} {
		write(
			fgaclient.ClientTupleKey{User: agentA, Relation: rel, Object: shared},
			fgaclient.ClientTupleKey{User: tenantA + "#member", Relation: rel, Object: shared},
		)
	}
	require.True(t, check(agentA, "can_execute", shared), "the grant of tenant A works in tenant A")

	// 1. Tenant B has not enabled the name. Its principals get nothing from
	// the grants, the owner tuple or the enable of tenant A.
	for _, rel := range relations {
		require.Falsef(t, check(agentB, rel, shared), "%s of tenant B from the tuples of tenant A", rel)
		require.Falsef(t, check(userB, rel, shared), "%s of a user of tenant B from the tuples of tenant A", rel)
	}

	// 2. Tenant B publishes the same name and grants its own principal. The
	// enable of tenant A is not the enable of tenant B.
	write(
		fgaclient.ClientTupleKey{User: tenantB, Relation: "owner", Object: shared},
		fgaclient.ClientTupleKey{User: agentB, Relation: "direct_execute", Object: shared},
	)
	require.False(t, check(agentB, "can_execute", shared), "the enable of tenant A must not open the name for tenant B")

	// 3. Tenant B enables its name. Its principal gets its own grant, and a
	// deny that tenant A writes for its tenant takes nothing from tenant B.
	write(fgaclient.ClientTupleKey{User: tenantB, Relation: "tenant_enabled", Object: shared})
	require.True(t, check(agentB, "can_execute", shared), "the grant of tenant B works in tenant B")
	write(fgaclient.ClientTupleKey{User: tenantA, Relation: "tenant_execute_disabled", Object: shared})
	require.False(t, check(agentA, "can_execute", shared), "the deny of tenant A applies in tenant A")
	require.True(t, check(agentB, "can_execute", shared), "the deny of tenant A must not apply in tenant B")

}
