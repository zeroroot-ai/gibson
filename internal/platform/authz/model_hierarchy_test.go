//go:build integration
// +build integration

package authz_test

// TestModel_TenantRoleHierarchy exercises the three-tier tenant role hierarchy
// introduced by spec tenant-role-taxonomy. It uses an ephemeral OpenFGA
// container and loads model.fga via loadModelFromDSL (same path as the
// production fga-init Job), so the test validates the actual DSL.
//
// Three cases per Req 1.5:
//   1. owner → admin + member checks return true (downward propagation)
//   2. admin → owner check returns false (upward propagation blocked)
//   3. member → admin + owner checks return false (upward propagation blocked)
//
// Cleanup runs on both success and failure so no stray tuples persist.
// Spec: tenant-role-taxonomy.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	fgaclient "github.com/openfga/go-sdk/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// storeNameFor returns a deterministic OpenFGA store name derived from the
// test name. OpenFGA enforces the regex
// ^[a-zA-Z0-9\s\.\-/^_&@]{3,64}$ on store names, and table-driven sub-test
// names like "TestModel_TenantRoleHierarchy/owner_implies_admin_and_member"
// blow past the 64-char ceiling. Hashing keeps every store name a fixed
// 39 chars while preserving 1:1 mapping to the originating sub-test for
// debuggability (the hash prefix is reproducible from the test name).
func storeNameFor(prefix string, t *testing.T) string {
	sum := sha256.Sum256([]byte(t.Name()))
	return prefix + "-" + hex.EncodeToString(sum[:16])
}

func TestModel_TenantRoleHierarchy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	_, baseURL, containerCleanup := setupFGAContainer(t, ctx)
	defer containerCleanup()

	// newStoreClient creates an isolated store + loads model.fga for each
	// sub-test so tuples from one case never affect another.
	newStoreClient := func(t *testing.T) *fgaclient.OpenFgaClient {
		t.Helper()

		mgmt := newRawFGAClient(t, baseURL)
		storeResp, err := mgmt.CreateStore(ctx).Body(fgaclient.ClientCreateStoreRequest{
			Name: storeNameFor("hierarchy", t),
		}).Execute()
		require.NoError(t, err, "tenant-role-taxonomy: create FGA store")

		storeID := storeResp.GetId()
		modelID := loadModelFromDSL(t, ctx, baseURL, storeID)

		c, err := fgaclient.NewSdkClient(&fgaclient.ClientConfiguration{
			ApiUrl:               baseURL,
			StoreId:              storeID,
			AuthorizationModelId: modelID,
		})
		require.NoError(t, err, "tenant-role-taxonomy: construct store client")
		return c
	}

	// checkAllowed is a thin wrapper that returns the boolean allowed value
	// and fails the test if the Check call itself errors.
	checkAllowed := func(t *testing.T, c *fgaclient.OpenFgaClient, user, relation, object string) bool {
		t.Helper()
		resp, err := c.Check(ctx).Body(fgaclient.ClientCheckRequest{
			User:     user,
			Relation: relation,
			Object:   object,
		}).Execute()
		require.NoErrorf(t, err,
			"tenant-role-taxonomy: Check(%s, %s, %s) returned error", user, relation, object)
		return resp.GetAllowed()
	}

	// Case 1 (Req 1.5.1): owner tuple → admin and member checks both true.
	t.Run("owner_implies_admin_and_member", func(t *testing.T) {
		c := newStoreClient(t)
		const (
			user   = "user:U_owner"
			tenant = "tenant:T"
		)

		// Write owner tuple; clean up even if assertions fail.
		_, err := c.Write(ctx).Body(fgaclient.ClientWriteRequest{
			Writes: []fgaclient.ClientTupleKey{
				{User: user, Relation: "owner", Object: tenant},
			},
		}).Execute()
		require.NoError(t, err, "tenant-role-taxonomy case 1: write owner tuple")
		t.Cleanup(func() {
			// Best-effort delete; tolerate "not found" so re-runs don't block.
			_, _ = c.Write(ctx).Body(fgaclient.ClientWriteRequest{
				Deletes: []fgaclient.ClientTupleKeyWithoutCondition{
					{User: user, Relation: "owner", Object: tenant},
				},
			}).Execute()
		})

		assert.True(t, checkAllowed(t, c, user, "admin", tenant),
			"tenant-role-taxonomy case 1 FAILED: owner should satisfy admin check (computed union)")
		assert.True(t, checkAllowed(t, c, user, "member", tenant),
			"tenant-role-taxonomy case 1 FAILED: owner should satisfy member check (computed union)")
	})

	// Case 2 (Req 1.5.2): admin tuple → owner check false (no upward propagation).
	t.Run("admin_does_not_imply_owner", func(t *testing.T) {
		c := newStoreClient(t)
		const (
			user   = "user:U_admin"
			tenant = "tenant:T"
		)

		_, err := c.Write(ctx).Body(fgaclient.ClientWriteRequest{
			Writes: []fgaclient.ClientTupleKey{
				{User: user, Relation: "admin", Object: tenant},
			},
		}).Execute()
		require.NoError(t, err, "tenant-role-taxonomy case 2: write admin tuple")
		t.Cleanup(func() {
			_, _ = c.Write(ctx).Body(fgaclient.ClientWriteRequest{
				Deletes: []fgaclient.ClientTupleKeyWithoutCondition{
					{User: user, Relation: "admin", Object: tenant},
				},
			}).Execute()
		})

		assert.False(t, checkAllowed(t, c, user, "owner", tenant),
			"tenant-role-taxonomy case 2 FAILED: admin should NOT satisfy owner check")
	})

	// Case 3 (Req 1.5.3): member tuple → admin and owner checks both false.
	t.Run("member_does_not_imply_admin_or_owner", func(t *testing.T) {
		c := newStoreClient(t)
		const (
			user   = "user:U_member"
			tenant = "tenant:T"
		)

		_, err := c.Write(ctx).Body(fgaclient.ClientWriteRequest{
			Writes: []fgaclient.ClientTupleKey{
				{User: user, Relation: "member", Object: tenant},
			},
		}).Execute()
		require.NoError(t, err, "tenant-role-taxonomy case 3: write member tuple")
		t.Cleanup(func() {
			_, _ = c.Write(ctx).Body(fgaclient.ClientWriteRequest{
				Deletes: []fgaclient.ClientTupleKeyWithoutCondition{
					{User: user, Relation: "member", Object: tenant},
				},
			}).Execute()
		})

		assert.False(t, checkAllowed(t, c, user, "admin", tenant),
			"tenant-role-taxonomy case 3 FAILED: member should NOT satisfy admin check")
		assert.False(t, checkAllowed(t, c, user, "owner", tenant),
			"tenant-role-taxonomy case 3 FAILED: member should NOT satisfy owner check")
	})
}
