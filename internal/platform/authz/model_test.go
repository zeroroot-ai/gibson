// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

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
		name      string // "read" | "write" | "execute"
		can       string // "can_read" | "can_configure" | "can_execute"
		direct    string // writable direct relation backing `can`: "direct_read" | "direct_configure" | "direct_execute"
		tenantDis string
		teamDis   string
		userDis   string
	}
	actions := []action{
		{"read", "can_read", "direct_read", "tenant_read_disabled", "team_read_disabled", "user_read_disabled"},
		{"write", "can_configure", "direct_configure", "tenant_write_disabled", "team_write_disabled", "user_write_disabled"},
		{"execute", "can_execute", "direct_execute", "tenant_execute_disabled", "team_execute_disabled", "user_execute_disabled"},
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

	// -- A component principal is checked like a user (ADR-0041) -------------
	//
	// One grant: the tuple on the direct_ relation is the approval. The model
	// has no second per-component enablement. compPlat is in the catalog of
	// acme and has no owner tuple, so membership of acme alone gives no
	// action on it.
	const compPlat = "component:comp-platform"
	seedPlat := func(c *fgaclient.OpenFgaClient) {
		t.Helper()
		seed(c)
		addTuples(c, fgaclient.ClientTupleKey{User: tenantA, Relation: "tenant_enabled", Object: compPlat})
	}

	t.Run("component_principal/no_grant_denies_each_action", func(t *testing.T) {
		c := newClient(t)
		seedPlat(c)
		for _, a := range actions {
			require.False(t, checkAllow(c, agentAA, a.can, compPlat),
				"no grant: %s must deny", a.can)
		}
	})

	for _, a := range actions {
		a := a
		t.Run(fmt.Sprintf("component_principal/one_grant_gives_%s_only", a.name), func(t *testing.T) {
			c := newClient(t)
			seedPlat(c)
			// The one tuple on the direct_ relation is the whole grant.
			addTuples(c, fgaclient.ClientTupleKey{User: agentAA, Relation: a.direct, Object: compPlat})
			for _, other := range actions {
				got := checkAllow(c, agentAA, other.can, compPlat)
				want := other.name == a.name
				require.Equalf(t, want, got,
					"agent granted %s only: checking %s (expected %v, got %v)", a.name, other.can, want, got)
			}
		})
	}

	for _, a := range actions {
		a := a
		t.Run(fmt.Sprintf("component_principal/tenant_deny_wins_for_%s", a.name), func(t *testing.T) {
			c := newClient(t)
			seedPlat(c)
			addTuples(c, fgaclient.ClientTupleKey{User: agentAA, Relation: a.direct, Object: compPlat})
			require.True(t, checkAllow(c, agentAA, a.can, compPlat), "precondition: the agent has %s", a.can)
			// The principal is a member of its tenant, so the tenant deny
			// reaches it.
			addTuples(c, fgaclient.ClientTupleKey{User: tenantA, Relation: a.tenantDis, Object: compPlat})
			require.False(t, checkAllow(c, agentAA, a.can, compPlat),
				"%s must win over the grant of a component principal", a.tenantDis)
		})
	}

	// The team deny and the user deny still win for each subject that they
	// can name (the team_deny and user_deny subtests above). The model gives
	// them no path to a component principal: a principal cannot be a member
	// of a team, and a user deny takes a user only. OpenFGA refuses each
	// such tuple, so no state exists in which a component principal escapes
	// a team deny or a user deny that names it.
	t.Run("component_principal/team_and_user_deny_cannot_name_a_principal", func(t *testing.T) {
		c := newClient(t)
		seedPlat(c)
		_, err := c.Write(ctx).Body(fgaclient.ClientWriteRequest{Writes: []fgaclient.ClientTupleKey{
			{User: agentAA, Relation: "member", Object: teamRed},
		}}).Execute()
		require.Error(t, err, "a component principal must not be a team member")
		for _, a := range actions {
			_, err := c.Write(ctx).Body(fgaclient.ClientWriteRequest{Writes: []fgaclient.ClientTupleKey{
				{User: agentAA, Relation: a.userDis, Object: compPlat},
			}}).Execute()
			require.Errorf(t, err, "%s must take a user only", a.userDis)
		}
	})

	// The six relations of the second approval are gone (gibson#705). A
	// tuple or a check on one of them is an error, not a silent deny.
	t.Run("component_principal/second_approval_relations_are_gone", func(t *testing.T) {
		c := newClient(t)
		seedPlat(c)
		for _, relation := range []string{
			"component_read_enabled", "component_write_enabled", "component_execute_enabled",
		} {
			_, err := c.Write(ctx).Body(fgaclient.ClientWriteRequest{Writes: []fgaclient.ClientTupleKey{
				{User: agentAA, Relation: relation, Object: compPlat},
			}}).Execute()
			require.Errorf(t, err, "the model must not have the relation %s", relation)
		}
		for _, relation := range []string{
			"can_read_as_component", "can_write_as_component", "can_execute_as_component",
		} {
			_, err := c.Check(ctx).Body(fgaclient.ClientCheckRequest{
				User: agentAA, Relation: relation, Object: compPlat,
			}).Execute()
			require.Errorf(t, err, "the model must not have the relation %s", relation)
		}
	})

	// ADR-0046: the FGA model is symmetric across the three principal kinds.
	// tool_principal and plugin_principal are grantable the same component
	// relations as agent_principal — capability is enrollment policy, not a
	// type-system wall. Exercised on component:_system (the client backplane),
	// with the option-B universal `tenant_enabled` baseline in place.
	t.Run("adr0046/symmetric_principals_on_system_backplane", func(t *testing.T) {
		c := newClient(t)
		const sysComp = "component:_system"
		// Option-B baseline: the system surface is tenant_enabled for the tenant.
		// One principal of each kind, member of acme. Grant execute to the agent
		// and the tool (NOT the plugin). The tool_principal direct_execute write
		// must SUCCEED — on the pre-ADR-0046 model OpenFGA rejects it (the type
		// is not an allowed grantee), so addTuples' require.NoError fails.
		addTuples(c,
			fgaclient.ClientTupleKey{User: tenantA, Relation: "tenant_enabled", Object: sysComp},
			fgaclient.ClientTupleKey{User: "agent_principal:a", Relation: "member", Object: tenantA},
			fgaclient.ClientTupleKey{User: "tool_principal:t", Relation: "member", Object: tenantA},
			fgaclient.ClientTupleKey{User: "plugin_principal:p", Relation: "member", Object: tenantA},
			fgaclient.ClientTupleKey{User: "agent_principal:a", Relation: "direct_execute", Object: sysComp},
			fgaclient.ClientTupleKey{User: "tool_principal:t", Relation: "direct_execute", Object: sysComp},
		)
		require.True(t, checkAllow(c, "agent_principal:a", "can_execute", sysComp),
			"granted agent_principal must can_execute component:_system")
		require.True(t, checkAllow(c, "tool_principal:t", "can_execute", sysComp),
			"granted tool_principal must can_execute component:_system (symmetry)")
		require.False(t, checkAllow(c, "plugin_principal:p", "can_execute", sysComp),
			"un-granted plugin_principal must NOT can_execute component:_system (grant is the gate)")
	})

	// ADR-0046 / option B: without the `tenant_enabled component:_system`
	// baseline, even a granted agent is denied — confirming the baseline (and
	// not the grant alone) is required, i.e. why direct_execute alone is a no-op.
	t.Run("adr0046/system_backplane_requires_tenant_enabled_baseline", func(t *testing.T) {
		c := newClient(t)
		const sysComp = "component:_system"
		addTuples(c,
			fgaclient.ClientTupleKey{User: "agent_principal:a", Relation: "member", Object: tenantA},
			fgaclient.ClientTupleKey{User: "agent_principal:a", Relation: "direct_execute", Object: sysComp},
		)
		require.False(t, checkAllow(c, "agent_principal:a", "can_execute", sysComp),
			"direct_execute without tenant_enabled baseline is a no-op (in_tenant_catalog unsatisfied)")
	})

	// has_* feature-flag tests removed by spec plans-and-quotas-simplification.
}
