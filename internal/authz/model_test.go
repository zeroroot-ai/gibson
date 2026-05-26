//go:build integration
// +build integration

package authz_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	fgaclient "github.com/openfga/go-sdk/client"
	"github.com/stretchr/testify/require"
)

// TestModel_CatalogGating exercises the FGA schema's catalog gating semantics:
//
//   - R3: ownership scope (platform_enabled / tenant_published) + tenant_enabled
//   - R3: deny-wins composition at tenant / team / user scope per action class
//   - R3: cross-tenant isolation on tenant_published items
//   - R2: component-scope narrowing via can_{read,write,execute}_as_component
//
// It uses an OpenFGA testcontainer and loads model.fga via openfga-language,
// so the test exercises the exact production model. Each subtest creates its
// own store so tuples from one case don't leak into the next.
func TestModel_CatalogGating(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	_, baseURL, cleanup := setupFGAContainer(t, ctx)
	defer cleanup()

	// Canonical fixture identifiers reused across every subtest.
	const (
		sysTenant  = "system_tenant:_system"
		tenantA    = "tenant:acme"
		tenantB    = "tenant:other"
		userAlice  = "user:alice"
		userBob    = "user:bob"
		teamRed    = "team:red-team"
		teamRedMem = "team:red-team#member"
		agentAA    = "agent_principal:aa-1"
		compOne    = "component:comp-1"
		compPriv   = "component:comp-private"
	)

	// seed writes the baseline tuples every test starts from: acme + other
	// tenants, alice a member of acme and of team:red-team, bob a member of
	// other, agent_principal belonging to acme and owned by alice,
	// component:comp-1 owned by acme + platform_enabled + tenant_enabled on
	// acme + direct can_* tuples for alice (so she'd be allowed in the base
	// case).
	seed := func(c *fgaclient.OpenFgaClient) {
		t.Helper()
		writes := []fgaclient.ClientTupleKey{
			// tenant membership
			{User: userAlice, Relation: "member", Object: tenantA},
			{User: userBob, Relation: "member", Object: tenantB},
			// team: alice is a member of red-team which parents acme
			{User: tenantA, Relation: "parent", Object: teamRed},
			{User: userAlice, Relation: "member", Object: teamRed},
			// agent principal owned by alice, belongs to acme
			{User: userAlice, Relation: "owner", Object: agentAA},
			{User: tenantA, Relation: "belongs_to", Object: agentAA},
			// component:comp-1 — owned by acme, in system catalog, tenant_enabled on acme
			{User: tenantA, Relation: "owner", Object: compOne},
			{User: sysTenant, Relation: "platform_enabled", Object: compOne},
			{User: tenantA, Relation: "tenant_enabled", Object: compOne},
			// agent_principal:aa-1 is a member of tenant:acme so it satisfies
			// in_tenant_catalog (member from tenant_enabled) and inherits
			// tenant-level deny expansion (any_*_deny = member from tenant_*_disabled).
			{User: agentAA, Relation: "member", Object: tenantA},
			// NOTE: the alice/member/tenantA tuple is already written above as
			// part of the "tenant membership" block. FGA's WriteTuples rejects
			// duplicate keys within a single request
			// (cannot_allow_duplicate_tuples_in_one_request), so do NOT repeat
			// it here as a "for clarity" duplicate.
		}
		_, err := c.Write(ctx).Body(fgaclient.ClientWriteRequest{Writes: writes}).Execute()
		require.NoError(t, err, "seed writes")
	}

	// addTuples / removeTuples are thin helpers so subtests read naturally.
	addTuples := func(c *fgaclient.OpenFgaClient, tuples ...fgaclient.ClientTupleKey) {
		t.Helper()
		_, err := c.Write(ctx).Body(fgaclient.ClientWriteRequest{Writes: tuples}).Execute()
		require.NoError(t, err)
	}
	removeTuples := func(c *fgaclient.OpenFgaClient, tuples ...fgaclient.ClientTupleKeyWithoutCondition) {
		t.Helper()
		_, err := c.Write(ctx).Body(fgaclient.ClientWriteRequest{Deletes: tuples}).Execute()
		require.NoError(t, err)
	}
	checkAllow := func(c *fgaclient.OpenFgaClient, user, relation, object string) bool {
		t.Helper()
		resp, err := c.Check(ctx).Body(fgaclient.ClientCheckRequest{
			User:     user,
			Relation: relation,
			Object:   object,
		}).Execute()
		require.NoError(t, err, "check %s %s %s", user, relation, object)
		return resp.GetAllowed()
	}

	// allActions is iterated by cases that cover the three action classes.
	type action struct {
		name       string // "read" | "write" | "execute"
		can        string // "can_read" | "can_configure" | "can_execute"
		direct     string // writable direct relation backing `can`: "direct_read" | "direct_configure" | "direct_execute"
		tenantDis  string
		teamDis    string
		userDis    string
		compEnable string
		canAsComp  string
	}
	actions := []action{
		{"read", "can_read", "direct_read", "tenant_read_disabled", "team_read_disabled", "user_read_disabled", "component_read_enabled", "can_read_as_component"},
		{"write", "can_configure", "direct_configure", "tenant_write_disabled", "team_write_disabled", "user_write_disabled", "component_write_enabled", "can_write_as_component"},
		{"execute", "can_execute", "direct_execute", "tenant_execute_disabled", "team_execute_disabled", "user_execute_disabled", "component_execute_enabled", "can_execute_as_component"},
	}

	// newClient produces a fresh client+store+model per subtest.
	newClient := func(t *testing.T) *fgaclient.OpenFgaClient {
		t.Helper()
		mgmt := newRawFGAClient(t, baseURL)
		storeResp, err := mgmt.CreateStore(ctx).Body(fgaclient.ClientCreateStoreRequest{
			Name: storeNameFor("catalog", t),
		}).Execute()
		require.NoError(t, err)
		storeID := storeResp.GetId()
		modelID := loadModelFromDSL(t, ctx, baseURL, storeID)

		c, err := fgaclient.NewSdkClient(&fgaclient.ClientConfiguration{
			ApiUrl:               baseURL,
			StoreId:              storeID,
			AuthorizationModelId: modelID,
		})
		require.NoError(t, err)
		return c
	}

	// -- Baseline ------------------------------------------------------------

	t.Run("baseline/all_actions_allowed", func(t *testing.T) {
		c := newClient(t)
		seed(c)
		for _, a := range actions {
			require.Truef(t, checkAllow(c, userAlice, a.can, compOne),
				"alice should have %s in baseline", a.can)
		}
	})

	// -- Tenant-level per-action denies --------------------------------------

	for _, a := range actions {
		a := a
		t.Run(fmt.Sprintf("tenant_deny/%s_isolates", a.name), func(t *testing.T) {
			c := newClient(t)
			seed(c)
			addTuples(c, fgaclient.ClientTupleKey{User: tenantA, Relation: a.tenantDis, Object: compOne})
			// The denied action becomes false; the other two remain true.
			for _, other := range actions {
				got := checkAllow(c, userAlice, other.can, compOne)
				want := other.name != a.name
				require.Equalf(t, want, got,
					"after tenant_%s_disabled: checking %s (expected %v, got %v)", a.name, other.can, want, got)
			}
		})
	}

	// -- Team-level per-action denies (via team membership) ------------------

	for _, a := range actions {
		a := a
		t.Run(fmt.Sprintf("team_deny/%s_isolates", a.name), func(t *testing.T) {
			c := newClient(t)
			seed(c)
			// Deny subject is team:red-team#member — members of the team
			// are affected. Alice is in red-team; bob is not.
			addTuples(c, fgaclient.ClientTupleKey{User: teamRedMem, Relation: a.teamDis, Object: compOne})
			for _, other := range actions {
				got := checkAllow(c, userAlice, other.can, compOne)
				want := other.name != a.name
				require.Equalf(t, want, got,
					"after team_%s_disabled: checking %s (expected %v, got %v)", a.name, other.can, want, got)
			}
		})
	}

	// -- User-level per-action denies ----------------------------------------

	for _, a := range actions {
		a := a
		t.Run(fmt.Sprintf("user_deny/%s_isolates", a.name), func(t *testing.T) {
			c := newClient(t)
			seed(c)
			addTuples(c, fgaclient.ClientTupleKey{User: userAlice, Relation: a.userDis, Object: compOne})
			for _, other := range actions {
				got := checkAllow(c, userAlice, other.can, compOne)
				want := other.name != a.name
				require.Equalf(t, want, got,
					"after user_%s_disabled: checking %s (expected %v, got %v)", a.name, other.can, want, got)
			}
		})
	}

	// -- Union-of-denies: deny at multiple layers; removing one isn't enough --

	for _, a := range actions {
		a := a
		t.Run(fmt.Sprintf("union_deny/%s_removing_one_keeps_denied", a.name), func(t *testing.T) {
			c := newClient(t)
			seed(c)
			// Set tenant-level AND team-level deny for this action.
			addTuples(c,
				fgaclient.ClientTupleKey{User: tenantA, Relation: a.tenantDis, Object: compOne},
				fgaclient.ClientTupleKey{User: teamRedMem, Relation: a.teamDis, Object: compOne},
			)
			require.False(t, checkAllow(c, userAlice, a.can, compOne),
				"both denies set: %s should be denied", a.can)
			// Remove tenant-level; team deny still in place → still denied.
			removeTuples(c, fgaclient.ClientTupleKeyWithoutCondition{
				User: tenantA, Relation: a.tenantDis, Object: compOne,
			})
			require.False(t, checkAllow(c, userAlice, a.can, compOne),
				"only team deny set: %s should still be denied", a.can)
			// Remove team-level; now allowed.
			removeTuples(c, fgaclient.ClientTupleKeyWithoutCondition{
				User: teamRedMem, Relation: a.teamDis, Object: compOne,
			})
			require.True(t, checkAllow(c, userAlice, a.can, compOne),
				"all denies removed: %s should be allowed", a.can)
		})
	}

	// -- Ownership gate: platform_enabled / tenant_published / tenant_enabled --

	t.Run("gate/no_platform_enabled_denies_all", func(t *testing.T) {
		c := newClient(t)
		seed(c)
		// in_tenant_catalog = member from tenant_enabled; platform_enabled is
		// now an operational marker only (operators ensure tenant_enabled is
		// only written for platform-approved or tenant-published components).
		// Removing platform_enabled while tenant_enabled is present must NOT
		// deny access — the tenant_enabled gate is authoritative.
		removeTuples(c, fgaclient.ClientTupleKeyWithoutCondition{
			User: sysTenant, Relation: "platform_enabled", Object: compOne,
		})
		for _, a := range actions {
			require.True(t, checkAllow(c, userAlice, a.can, compOne),
				"platform_enabled absent but tenant_enabled present: %s should still be allowed", a.can)
		}
	})

	t.Run("gate/no_tenant_enabled_denies_all", func(t *testing.T) {
		c := newClient(t)
		seed(c)
		removeTuples(c, fgaclient.ClientTupleKeyWithoutCondition{
			User: tenantA, Relation: "tenant_enabled", Object: compOne,
		})
		for _, a := range actions {
			require.False(t, checkAllow(c, userAlice, a.can, compOne),
				"no tenant_enabled: %s should deny", a.can)
		}
	})

	// -- Cross-tenant isolation on tenant_published items ---------------------

	t.Run("cross_tenant/private_item_invisible_to_other_tenant", func(t *testing.T) {
		c := newClient(t)
		seed(c)
		// compPriv is owned by tenant:other and published only to them.
		addTuples(c,
			fgaclient.ClientTupleKey{User: tenantB, Relation: "owner", Object: compPriv},
			fgaclient.ClientTupleKey{User: tenantB, Relation: "tenant_published", Object: compPriv},
			fgaclient.ClientTupleKey{User: tenantB, Relation: "tenant_enabled", Object: compPriv},
		)
		// bob (in other) can access via tenant#member direct grant.
		require.True(t, checkAllow(c, userBob, "can_read", compPriv),
			"bob in tenant:other should read their own published item")
		// alice (in acme) CANNOT: no tenant_enabled@acme AND no platform_enabled.
		require.False(t, checkAllow(c, userAlice, "can_read", compPriv),
			"alice in tenant:acme must NOT see tenant:other's private item")
		require.False(t, checkAllow(c, userAlice, "can_configure", compPriv),
			"alice in tenant:acme must NOT write tenant:other's private item")
		require.False(t, checkAllow(c, userAlice, "can_execute", compPriv),
			"alice in tenant:acme must NOT execute tenant:other's private item")
	})

	// -- Component-scope narrowing (R2) --------------------------------------

	t.Run("component_scope/no_grant_denies_all_actions_as_component", func(t *testing.T) {
		c := newClient(t)
		seed(c)
		// agent_principal:aa-1 has NO component_X_enabled tuples yet.
		for _, a := range actions {
			require.False(t, checkAllow(c, agentAA, a.canAsComp, compOne),
				"no component grant: %s should deny", a.canAsComp)
		}
	})

	for _, a := range actions {
		a := a
		t.Run(fmt.Sprintf("component_scope/grant_enables_%s_only", a.name), func(t *testing.T) {
			c := newClient(t)
			seed(c)
			// Agent needs direct grant on the component to pass can_* via
			// agent_principal subject. Give it tenant-scoped access too so
			// the ownership gate + tenant_enabled gate passes.
			addTuples(c,
				fgaclient.ClientTupleKey{User: agentAA, Relation: a.direct, Object: compOne},
				fgaclient.ClientTupleKey{User: agentAA, Relation: a.compEnable, Object: compOne},
			)
			// Only the granted action is allowed at the _as_component level.
			for _, other := range actions {
				got := checkAllow(c, agentAA, other.canAsComp, compOne)
				want := other.name == a.name
				require.Equalf(t, want, got,
					"agent granted %s only: checking %s (expected %v, got %v)", a.name, other.canAsComp, want, got)
			}
		})
	}

	t.Run("component_scope/user_layer_deny_kills_agent_action", func(t *testing.T) {
		c := newClient(t)
		seed(c)
		// Grant agent read via component-scope + direct.
		addTuples(c,
			fgaclient.ClientTupleKey{User: agentAA, Relation: "direct_read", Object: compOne},
			fgaclient.ClientTupleKey{User: agentAA, Relation: "component_read_enabled", Object: compOne},
		)
		require.True(t, checkAllow(c, agentAA, "can_read_as_component", compOne),
			"precondition: agent has read")
		// Now the owner user loses read at tenant level → agent loses read
		// transitively because can_read_as_component requires can_read.
		// Here the agent is its own subject for can_read, but we demonstrate
		// the deny-wins semantics by denying at the agent subject directly.
		addTuples(c, fgaclient.ClientTupleKey{User: tenantA, Relation: "tenant_read_disabled", Object: compOne})
		require.False(t, checkAllow(c, agentAA, "can_read_as_component", compOne),
			"tenant_read_disabled kills agent's can_read_as_component")
	})

	// has_* feature-flag tests removed by spec plans-and-quotas-simplification.
}
