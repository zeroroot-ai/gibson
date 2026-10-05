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

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

// TestIntegration_FGA_GrantTupleRelations runs each allowed grant against the
// model that ships (model.fga) on a real OpenFGA server.
//
// For each action, the tuple on the relation from authz.GrantTupleRelation
// gives a positive Check on the action. For the three component actions,
// OpenFGA refuses a tuple on the action itself, because the action is a
// computed relation. That refusal is why WriteAgentGrants could not grant
// these actions (gibson#703).
func TestIntegration_FGA_GrantTupleRelations(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	_, baseURL, containerCleanup := setupFGAContainer(t, ctx)
	defer containerCleanup()

	mgmt := newRawFGAClient(t, baseURL)
	storeResp, err := mgmt.CreateStore(ctx).Body(fgaclient.ClientCreateStoreRequest{
		Name: storeNameFor("grant-tuple-relations", t),
	}).Execute()
	require.NoError(t, err, "create FGA store")
	storeID := storeResp.GetId()
	modelID := loadModelFromDSL(t, ctx, baseURL, storeID)
	c, err := fgaclient.NewSdkClient(&fgaclient.ClientConfiguration{
		ApiUrl:               baseURL,
		StoreId:              storeID,
		AuthorizationModelId: modelID,
	})
	require.NoError(t, err, "construct store client")

	check := func(user, relation, object string) bool {
		t.Helper()
		resp, err := c.Check(ctx).Body(fgaclient.ClientCheckRequest{User: user, Relation: relation, Object: object}).Execute()
		require.NoErrorf(t, err, "Check(%s, %s, %s) returned an error", user, relation, object)
		return resp.GetAllowed()
	}
	write := func(user, relation, object string) error {
		_, err := c.Write(ctx).Body(fgaclient.ClientWriteRequest{
			Writes: []fgaclient.ClientTupleKey{{User: user, Relation: relation, Object: object}},
		}).Execute()
		return err
	}
	remove := func(user, relation, object string) error {
		_, err := c.Write(ctx).Body(fgaclient.ClientWriteRequest{
			Deletes: []fgaclient.ClientTupleKeyWithoutCondition{{User: user, Relation: relation, Object: object}},
		}).Execute()
		return err
	}

	const (
		tenant    = "tenant:T"
		component = "component:gitlab"
		plugin    = "plugin:gitlab"
	)
	// The component is in the catalog of the tenant. Each component action
	// needs that, in addition to the grant.
	require.NoError(t, write(tenant, "tenant_enabled", component))

	cases := []struct {
		action   string
		object   string
		target   string
		computed bool
	}{
		{"can_read", component, "agent_principal:reader", true},
		{"can_configure", component, "agent_principal:configurer", true},
		{"can_execute", component, "agent_principal:executor", true},
		{"can_invoke", plugin, "tool_principal:invoker", false},
	}

	// The test covers each action that a grant can name.
	covered := make([]string, 0, len(cases))
	for _, tc := range cases {
		covered = append(covered, tc.action)
	}
	require.ElementsMatch(t, authz.GrantActions(), covered, "a grant action has no case in this test")

	for _, tc := range cases {
		t.Run(tc.action, func(t *testing.T) {
			relation, ok := authz.GrantTupleRelation(tc.action)
			require.True(t, ok)

			// Enrollment makes the principal a member of its tenant.
			require.NoError(t, write(tc.target, "member", tenant))
			require.False(t, check(tc.target, tc.action, tc.object), "no grant, no access")

			if tc.computed {
				require.Error(t, write(tc.target, tc.action, tc.object),
					"OpenFGA must refuse a tuple on the computed relation %s", tc.action)
			}

			require.NoError(t, write(tc.target, relation, tc.object), "write the grant tuple")
			require.True(t, check(tc.target, tc.action, tc.object),
				"a tuple on %s must give a positive Check on %s", relation, tc.action)

			// The delete of the same tuple removes the access.
			require.NoError(t, remove(tc.target, relation, tc.object), "delete the grant tuple")
			require.False(t, check(tc.target, tc.action, tc.object), "no access after the delete")
		})
	}
}
