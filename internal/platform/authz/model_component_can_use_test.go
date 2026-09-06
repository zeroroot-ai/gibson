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

// TestModel_ComponentCanUse: every HarnessCallbackService RPC is annotated
// with relation "can_use" on the backplane component (component:_system).
// The model must define it, and it must be exactly the execute right: an
// enrolled principal with direct_execute on a tenant-enabled backplane may
// use it; without the tenant_enabled tuple it may not.
func TestModel_ComponentCanUse(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	_, baseURL, containerCleanup := setupFGAContainer(t, ctx)
	defer containerCleanup()

	mgmt := newRawFGAClient(t, baseURL)
	storeResp, err := mgmt.CreateStore(ctx).Body(fgaclient.ClientCreateStoreRequest{
		Name: storeNameFor("component-can-use", t),
	}).Execute()
	require.NoError(t, err, "component-can-use: create FGA store")
	storeID := storeResp.GetId()
	modelID := loadModelFromDSL(t, ctx, baseURL, storeID)
	c, err := fgaclient.NewSdkClient(&fgaclient.ClientConfiguration{
		ApiUrl:               baseURL,
		StoreId:              storeID,
		AuthorizationModelId: modelID,
	})
	require.NoError(t, err, "component-can-use: construct store client")

	check := func(user, relation, object string) bool {
		t.Helper()
		resp, err := c.Check(ctx).Body(fgaclient.ClientCheckRequest{User: user, Relation: relation, Object: object}).Execute()
		require.NoErrorf(t, err, "component-can-use: Check(%s, %s, %s) returned error", user, relation, object)
		return resp.GetAllowed()
	}
	const (
		agent     = "agent_principal:A"
		tenant    = "tenant:T"
		backplane = "component:_system"
	)
	// What enrollment writes (CreateAgentIdentity): tenant membership for the
	// principal and execute on the backplane. in_tenant_catalog is
	// "member from tenant_enabled", so membership is part of the grant.
	_, err = c.Write(ctx).Body(fgaclient.ClientWriteRequest{
		Writes: []fgaclient.ClientTupleKey{
			{User: agent, Relation: "member", Object: tenant},
			{User: agent, Relation: "direct_execute", Object: backplane},
		},
	}).Execute()
	require.NoError(t, err)
	require.False(t, check(agent, "can_use", backplane), "can_use without tenant_enabled must be denied")

	_, err = c.Write(ctx).Body(fgaclient.ClientWriteRequest{
		Writes: []fgaclient.ClientTupleKey{
			{User: tenant, Relation: "tenant_enabled", Object: backplane},
		},
	}).Execute()
	require.NoError(t, err)
	require.True(t, check(agent, "can_use", backplane), "an enrolled agent may use the tenant-enabled backplane")
	require.Equal(t, check(agent, "can_execute", backplane), check(agent, "can_use", backplane), "can_use is the execute right")
	require.False(t, check("agent_principal:other", "can_use", backplane), "a principal without direct_execute may not")
}
