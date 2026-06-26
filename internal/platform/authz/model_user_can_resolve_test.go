//go:build integration
// +build integration

package authz_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	fgaclient "github.com/openfga/go-sdk/client"
	"github.com/stretchr/testify/require"
)

// TestModel_RejectsUserCanResolve pins the structural exclusion that has
// been load-bearing since spec non-plugin-secret-isolation: only
// plugin_principal-typed subjects can hold a `can_resolve` relation on
// secret objects. Any user-typed, agent_principal-typed, or tool_principal-
// typed `can_resolve` write MUST be rejected by the FGA write API at insert
// time, because the schema's `define can_resolve: [plugin_principal]`
// restricts the allowed subject types.
//
// Spec: secrets-blast-radius-reduction R4.2.
//
// Why this test exists:
//
//	The model.fga file's old comment block (pre-cleanup) described a
//	tuple shape `(user:<daemon_service_id>, can_resolve, secret:tenant
//	-<tenant_id>:*)` which CANNOT be written today and MUST not be
//	re-introduced by a future contributor "fixing" the model to match
//	the comment. This test fails closed if anyone widens can_resolve
//	to accept additional subject types.
func TestModel_RejectsUserCanResolve(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	_, baseURL, cleanup := setupFGAContainer(t, ctx)
	defer cleanup()

	mgmt := newRawFGAClient(t, baseURL)
	storeResp, err := mgmt.CreateStore(ctx).Body(fgaclient.ClientCreateStoreRequest{
		Name: fmt.Sprintf("test-%s", t.Name()),
	}).Execute()
	require.NoError(t, err)
	storeID := storeResp.GetId()

	_ = loadModelFromDSL(t, ctx, baseURL, storeID)

	// Re-create a client scoped to the test store (the SDK's store
	// binding is set on construction; same pattern as
	// integration_helpers_test.go writeTestModel).
	client, err := fgaclient.NewSdkClient(&fgaclient.ClientConfiguration{
		ApiUrl:  baseURL,
		StoreId: storeID,
	})
	require.NoError(t, err)

	cases := []struct {
		name   string
		user   string
		object string
	}{
		{
			name:   "user-typed",
			user:   "user:daemon-service-id-test",
			object: "secret:tenant-acme-llm-anthropic-api-key",
		},
		{
			name:   "agent_principal-typed",
			user:   "agent_principal:enrollment-test",
			object: "secret:tenant-acme-integration-token",
		},
		{
			name:   "tool_principal-typed",
			user:   "tool_principal:enrollment-test",
			object: "secret:tenant-acme-any-secret",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := client.Write(ctx).Body(fgaclient.ClientWriteRequest{
				Writes: []fgaclient.ClientTupleKey{{
					User:     tc.user,
					Relation: "can_resolve",
					Object:   tc.object,
				}},
			}).Execute()
			require.Error(t, err, "write must be rejected (model restricts can_resolve to plugin_principal only)")
			lower := strings.ToLower(err.Error())
			require.Truef(t,
				strings.Contains(lower, "type") ||
					strings.Contains(lower, "validation") ||
					strings.Contains(lower, "invalid"),
				"error should mention type-restriction (got: %v)", err,
			)
		})
	}

	// Sanity-check: a plugin_principal-typed write MUST succeed (proves
	// the test infrastructure is wired correctly and not just rejecting
	// every write).
	t.Run("plugin_principal-typed-allowed", func(t *testing.T) {
		_, err := client.Write(ctx).Body(fgaclient.ClientWriteRequest{
			Writes: []fgaclient.ClientTupleKey{{
				User:     "plugin_principal:enrollment-test",
				Relation: "can_resolve",
				Object:   "secret:tenant-acme-llm-anthropic-api-key",
			}},
		}).Execute()
		require.NoError(t, err, "plugin_principal can_resolve write must succeed")
	})
}
