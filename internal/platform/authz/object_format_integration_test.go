// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build integration

package authz_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	fgaclient "github.com/openfga/go-sdk/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

// TestTenantQualifiedObjects_ValidAndRoundTrip is the gibson#1024 regression
// guard: the tenant-qualified FGA objects gibson writes (plugin can_invoke,
// secret can_resolve) must be ACCEPTED by OpenFGA on Write AND Check, and a
// Check must match what was Written.
//
// The historical "type:tenant:name" (two-colon) form was rejected by OpenFGA
// with "invalid 'object' field format" — the id may not contain a colon — so
// every such write silently failed and the corresponding check could never
// match. The canonical form now joins tenant and name with
// authz.TenantQualifiedSep ("/"). This test fails closed if anyone reintroduces
// a colon into a tenant-qualified object.
func TestTenantQualifiedObjects_ValidAndRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	_, baseURL, cleanup := setupFGAContainer(t, ctx)
	defer cleanup()

	mgmt := newRawFGAClient(t, baseURL)
	storeResp, err := mgmt.CreateStore(ctx).Body(fgaclient.ClientCreateStoreRequest{Name: fmt.Sprintf("test-%s", t.Name())}).Execute()
	require.NoError(t, err)
	storeID := storeResp.GetId()
	_ = loadModelFromDSL(t, ctx, baseURL, storeID)

	client, err := fgaclient.NewSdkClient(&fgaclient.ClientConfiguration{ApiUrl: baseURL, StoreId: storeID})
	require.NoError(t, err)

	roundTrip := func(t *testing.T, user, relation, object string) {
		t.Helper()
		// The object id (everything after the first colon) must itself be
		// colon-free — OpenFGA rejects an id containing a colon.
		_, id, _ := strings.Cut(object, ":")
		require.NotContains(t, id, ":",
			"tenant-qualified object id must not contain a colon (OpenFGA rejects it): %q", object)

		_, werr := client.Write(ctx).Body(fgaclient.ClientWriteRequest{
			Writes: []fgaclient.ClientTupleKey{{User: user, Relation: relation, Object: object}},
		}).Execute()
		require.NoError(t, werr, "Write must be accepted for object %q (gibson#1024)", object)

		resp, cerr := client.Check(ctx).Body(fgaclient.ClientCheckRequest{User: user, Relation: relation, Object: object}).Execute()
		require.NoError(t, cerr, "Check must be accepted for object %q", object)
		assert.True(t, resp.GetAllowed(), "Check must match the tuple just written for %q", object)
	}

	t.Run("plugin can_invoke (PluginObject)", func(t *testing.T) {
		// Exactly what the catalog authorizer checks and the tenant-operator seeds.
		roundTrip(t, "tool_principal:scanner", "can_invoke", authz.PluginObject("acme", "gitlab"))
	})

	t.Run("secret can_resolve (production tenant-qualified shape)", func(t *testing.T) {
		// Mirrors the plugin_admin / tenant-operator can_resolve writers.
		roundTrip(t, "plugin_principal:install-1", "can_resolve", "secret:tenant-acme"+authz.TenantQualifiedSep+"llm-anthropic-api-key")
	})

	t.Run("team parent (TeamObject)", func(t *testing.T) {
		// gibson#1231. Every unit test around team objects runs against a
		// double, so nothing else in the suite proves that OpenFGA actually
		// accepts a "/" inside a TEAM object id — and if it did not, the whole
		// team surface would fail at runtime with no local signal.
		obj, err := authz.TeamObject("acme", "ops")
		require.NoError(t, err)
		require.Equal(t, "team:acme/ops", obj)
		roundTrip(t, "tenant:acme", "parent", obj)
	})

	t.Run("team member userset (component access subject shape)", func(t *testing.T) {
		// SetComponentAccess writes the team as a USERSET on a component
		// object, so the namespaced id has to survive on the subject side too.
		obj, err := authz.TeamObject("acme", "ops")
		require.NoError(t, err)
		roundTrip(t, obj+"#member", "team_execute_disabled", "component:agent/zerocool")
	})

	t.Run("two tenants at the same team id do not collide", func(t *testing.T) {
		// The property the namespace exists for, asserted against the real
		// server rather than the in-memory double: same caller-chosen id, two
		// tenants, two objects, and neither tenant parents the other's.
		victim, err := authz.TeamObject("victim-co", "ops")
		require.NoError(t, err)
		squatter, err := authz.TeamObject("evil-co", "ops")
		require.NoError(t, err)
		require.NotEqual(t, victim, squatter)

		roundTrip(t, "tenant:victim-co", "parent", victim)
		roundTrip(t, "tenant:evil-co", "parent", squatter)

		resp, cerr := client.Check(ctx).Body(fgaclient.ClientCheckRequest{
			User: "tenant:evil-co", Relation: "parent", Object: victim,
		}).Execute()
		require.NoError(t, cerr)
		assert.False(t, resp.GetAllowed(),
			"evil-co must not parent victim-co's team; a true here is the squat gibson#1231 is about")
	})
}
