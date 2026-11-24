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

// TestModel_TenantCanExecute runs the rule on a real OpenFGA with the real model.
// The tenant may run a connector for itself when it owns the grant and enabled
// it, and the tenant execute kill switch is off. The userset of the tenant members
// cannot ask can_execute at all (run 45352739081), which is why the rule exists.
func TestModel_TenantCanExecute(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	_, baseURL, containerCleanup := setupFGAContainer(t, ctx)
	defer containerCleanup()

	mgmt := newRawFGAClient(t, baseURL)
	storeResp, err := mgmt.CreateStore(ctx).Body(fgaclient.ClientCreateStoreRequest{
		Name: storeNameFor("tenant-can-execute", t),
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
		tenantA   = "tenant:a"
		tenantB   = "tenant:b"
		connector = "component:connector/github"
		tool      = "component:tool/nmap"
	)

	// The tenant operator writes owner and tenant_enabled for an enabled connector.
	write(
		fgaclient.ClientTupleKey{User: "user:a-member", Relation: "member", Object: tenantA},
		fgaclient.ClientTupleKey{User: tenantA, Relation: "owner", Object: connector},
		fgaclient.ClientTupleKey{User: tenantA, Relation: "tenant_enabled", Object: connector},
	)
	require.True(t, check(tenantA, "tenant_can_execute", connector), "the tenant that enabled the connector may run it")
	require.True(t, check("user:a-member", "can_execute", connector), "a member of the tenant still runs it as a person")

	// The userset of the members cannot ask can_execute. This is the fact that the
	// rule works around. If OpenFGA ever answers true, the rule is not needed.
	require.False(t, check(tenantA+"#member", "can_execute", connector), "a userset is a member of nothing")

	// Tenant B did not enable it, and the tuples of tenant A give it nothing.
	require.False(t, check(tenantB, "tenant_can_execute", connector), "another tenant has no grant")
	write(fgaclient.ClientTupleKey{User: tenantB, Relation: "tenant_enabled", Object: connector})
	require.False(t, check(tenantB, "tenant_can_execute", connector), "tenant_enabled with no owner is not a grant")
	require.True(t, check(tenantA, "tenant_can_execute", connector), "the tuples of tenant B take nothing from tenant A")

	// A component that the tenant enabled with a member grant and no owner tuple is
	// false: the rule fails closed.
	write(
		fgaclient.ClientTupleKey{User: tenantA, Relation: "tenant_enabled", Object: tool},
		fgaclient.ClientTupleKey{User: tenantA + "#member", Relation: "direct_execute", Object: tool},
	)
	require.False(t, check(tenantA, "tenant_can_execute", tool), "a component with no owner tuple is not a tenant grant")

	// The kill switch of tenant A stops tenant A and not tenant B.
	write(
		fgaclient.ClientTupleKey{User: tenantB, Relation: "owner", Object: connector},
		fgaclient.ClientTupleKey{User: tenantA, Relation: "tenant_execute_disabled", Object: connector},
	)
	require.False(t, check(tenantA, "tenant_can_execute", connector), "the kill switch stops the tenant")
	require.True(t, check(tenantB, "tenant_can_execute", connector), "the kill switch of tenant A does not stop tenant B")
}
