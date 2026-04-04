//go:build e2e
// +build e2e

package e2e

// capability_enforcement_test.go contains integration tests that verify the
// Casbin-backed capability enforcement layer in isolation.
//
// Every test uses an in-memory Casbin enforcer (model from string, no adapter)
// and, where Redis state is required, a miniredis instance.  No external
// infrastructure is needed.  Run with:
//
//	go test -tags=e2e -race ./tests/e2e/...
//
// Design notes:
//
//   - The Casbin model in internal/auth/casbin.go uses exact matching for the
//     (obj, act) tuple.  A wildcard "*" capability policy therefore only matches
//     when the enforcer is called with the literal string "*" for resource or
//     action.  The AuthorizingHarness fallback path (identity.HasCapability)
//     handles the practical wildcard case for harness calls; the tests below
//     exercise both the pure-Casbin path and the capability-slice fallback.
//
//   - Component scope (AllowedKinds / AllowedNames) is enforced by checking the
//     fields on APIKeyRecord directly — the daemon server compares these before
//     accepting a RegisterComponent RPC.  The relevant helper (scopePermits) is
//     tested via the exported record fields rather than unexported daemon logic.

import (
	"context"
	"fmt"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zero-day-ai/gibson/internal/auth"
	"github.com/zero-day-ai/gibson/internal/component"
	sdkauth "github.com/zero-day-ai/sdk/auth"
)

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// newInMemoryEnforcer creates a Casbin enforcer using the same model string as
// internal/auth/casbin.go but backed by an in-memory (nil) adapter so that no
// Redis connection is required during tests.
func newInMemoryEnforcer(t *testing.T) *casbin.Enforcer {
	t.Helper()

	// Mirror the exact model string used in internal/auth/casbin.go.
	const casbinModel = `
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act
`
	m, err := model.NewModelFromString(casbinModel)
	require.NoError(t, err, "failed to parse Casbin model")

	// Passing only the model (no adapter) produces an in-memory enforcer whose
	// policies exist for the lifetime of the test only.
	e, err := casbin.NewEnforcer(m)
	require.NoError(t, err, "failed to create in-memory Casbin enforcer")

	return e
}

// newAPIKeyAuthenticatorWithEnforcer wires an APIKeyAuthenticator to a
// miniredis instance and attaches the supplied Casbin enforcer.
func newAPIKeyAuthenticatorWithEnforcer(t *testing.T, enforcer *casbin.Enforcer) (*auth.APIKeyAuthenticator, *miniredis.Miniredis) {
	t.Helper()

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	a, err := auth.NewAPIKeyAuthenticator(client)
	require.NoError(t, err, "failed to create APIKeyAuthenticator")
	a.WithEnforcer(enforcer)

	return a, mr
}

// identityWithCapabilities constructs an *auth.Identity carrying the provided
// capabilities slice.  This mirrors what APIKeyAuthenticator.Authenticate
// produces after loading an APIKeyRecord.
func identityWithCapabilities(subject, tenant string, caps []string) *auth.Identity {
	return &auth.Identity{
		Identity: sdkauth.Identity{
			Subject: subject,
			Issuer:  "apikey",
			Groups:  []string{},
			Claims: map[string]any{
				"tenant_id": tenant,
			},
			Capabilities: caps,
		},
		Roles:        []string{},
		Permissions:  []auth.Permission{},
		Capabilities: caps,
	}
}

// enforceExpect is a convenience wrapper that calls enforcer.Enforce and asserts
// the outcome using the provided allowed flag.
func enforceExpect(t *testing.T, e *casbin.Enforcer, sub, dom, obj, act string, wantAllow bool) {
	t.Helper()

	got, err := e.Enforce(sub, dom, obj, act)
	require.NoError(t, err, "Enforce(%q, %q, %q, %q) must not return an error", sub, dom, obj, act)

	if wantAllow {
		assert.True(t, got,
			"Enforce(%q, %q, %q, %q) expected=allow, got=deny", sub, dom, obj, act)
	} else {
		assert.False(t, got,
			"Enforce(%q, %q, %q, %q) expected=deny, got=allow", sub, dom, obj, act)
	}
}

// ---------------------------------------------------------------------------
// Scenario 1: Scoped key — missions:read only
// ---------------------------------------------------------------------------

// TestCapabilityEnforcement_MissionsReadOnly verifies that a key created with
// capabilities=["missions:read"] may query missions but is denied mission
// execution and all other resources.
func TestCapabilityEnforcement_MissionsReadOnly(t *testing.T) {
	t.Parallel()

	const (
		tenant   = "acme-corp"
		resource = "missions"
	)

	enforcer := newInMemoryEnforcer(t)
	a, _ := newAPIKeyAuthenticatorWithEnforcer(t, enforcer)

	// CreateKey with capability "missions:read" → adds policy (keyID, tenant, "missions", "read").
	rawKey, record, err := a.CreateKey(context.Background(), tenant, nil, nil, []string{"missions:read"}, "", "")
	require.NoError(t, err)

	t.Logf("created key %s with capabilities=%v", record.KeyID, record.Capabilities)

	t.Run("missions:read is allowed", func(t *testing.T) {
		t.Parallel()
		enforceExpect(t, enforcer, record.KeyID, tenant, resource, "read", true)
	})

	t.Run("missions:execute is denied by Casbin", func(t *testing.T) {
		t.Parallel()
		// "execute" was never added to the policy for this key.
		enforceExpect(t, enforcer, record.KeyID, tenant, resource, "execute", false)
	})

	t.Run("Authenticate returns identity with correct capabilities", func(t *testing.T) {
		t.Parallel()

		identity, err := a.Authenticate(context.Background(), rawKey)
		require.NoError(t, err)
		assert.Equal(t, []string{"missions:read"}, identity.Capabilities,
			"authenticated identity must carry the original capabilities")

		// HasCapability follows the compound "resource:action" format used by the
		// SDK Identity method (checks the Capabilities slice directly).
		assert.True(t, identity.HasCapability("missions:read"),
			"identity.HasCapability must confirm the granted capability")
		assert.False(t, identity.HasCapability("missions:execute"),
			"identity.HasCapability must not confirm a capability that was not granted")
	})

	t.Run("graphrag:write is denied — unrelated resource", func(t *testing.T) {
		t.Parallel()
		enforceExpect(t, enforcer, record.KeyID, tenant, "graphrag", "write", false)
	})

	t.Run("wildcard shortcut is denied — no * policy exists", func(t *testing.T) {
		t.Parallel()
		// A wildcard policy (*,*) is only added when capabilities=["*"]; this key
		// has a scoped capability so the wildcard literal must be denied.
		enforceExpect(t, enforcer, record.KeyID, tenant, "*", "*", false)
	})
}

// ---------------------------------------------------------------------------
// Scenario 2: Scoped key — graphrag:read only
// ---------------------------------------------------------------------------

// TestCapabilityEnforcement_GraphRAGReadOnly verifies that a key created with
// capabilities=["graphrag:read"] permits GraphRAG reads and denies writes and
// all other resources.
func TestCapabilityEnforcement_GraphRAGReadOnly(t *testing.T) {
	t.Parallel()

	const (
		tenant   = "widgets-inc"
		resource = "graphrag"
	)

	enforcer := newInMemoryEnforcer(t)
	a, _ := newAPIKeyAuthenticatorWithEnforcer(t, enforcer)

	rawKey, record, err := a.CreateKey(context.Background(), tenant, nil, nil, []string{"graphrag:read"}, "", "")
	require.NoError(t, err)

	t.Logf("created key %s with capabilities=%v", record.KeyID, record.Capabilities)

	t.Run("graphrag:read is allowed", func(t *testing.T) {
		t.Parallel()
		enforceExpect(t, enforcer, record.KeyID, tenant, resource, "read", true)
	})

	t.Run("graphrag:write is denied by Casbin", func(t *testing.T) {
		t.Parallel()
		enforceExpect(t, enforcer, record.KeyID, tenant, resource, "write", false)
	})

	t.Run("missions:read is denied — different resource", func(t *testing.T) {
		t.Parallel()
		enforceExpect(t, enforcer, record.KeyID, tenant, "missions", "read", false)
	})

	t.Run("identity capability slice reflects the grant", func(t *testing.T) {
		t.Parallel()

		identity, err := a.Authenticate(context.Background(), rawKey)
		require.NoError(t, err)

		assert.True(t, identity.HasCapability("graphrag:read"))
		assert.False(t, identity.HasCapability("graphrag:write"))
	})

	t.Run("tenant isolation — same key denied under different tenant domain", func(t *testing.T) {
		t.Parallel()
		// Policy is (keyID, "widgets-inc", "graphrag", "read"). Enforcing under a
		// different domain must return deny regardless of matching resource/action.
		enforceExpect(t, enforcer, record.KeyID, "other-tenant", resource, "read", false)
	})
}

// ---------------------------------------------------------------------------
// Scenario 3: Wildcard key — full access
// ---------------------------------------------------------------------------

// TestCapabilityEnforcement_WildcardKey verifies that a key created with
// capabilities=["*"] stores a single (*,*) policy and that the authenticated
// identity's HasCapability fallback allows any operation.
func TestCapabilityEnforcement_WildcardKey(t *testing.T) {
	t.Parallel()

	const tenant = "enterprise-tenant"

	enforcer := newInMemoryEnforcer(t)
	a, _ := newAPIKeyAuthenticatorWithEnforcer(t, enforcer)

	rawKey, record, err := a.CreateKey(context.Background(), tenant, nil, nil, []string{"*"}, "", "")
	require.NoError(t, err)

	t.Logf("created wildcard key %s", record.KeyID)

	// The Casbin model uses exact matching so Enforce(sub, dom, "*", "*") only
	// passes when the literal "*" is used.  Production enforcement uses the
	// identity.HasCapability("*") fallback after Casbin denies arbitrary tuples.
	// Both paths are verified below.

	t.Run("Casbin policy exists for (* , *)", func(t *testing.T) {
		t.Parallel()
		enforceExpect(t, enforcer, record.KeyID, tenant, "*", "*", true)
	})

	t.Run("Casbin denies specific resources — exact-match model limitation", func(t *testing.T) {
		t.Parallel()
		// The model is exact-match only; a (*,*) policy does not expand to
		// (missions, execute) at the Casbin level.  The AuthorizingHarness
		// fallback (HasCapability("*")) covers this case in production.
		enforceExpect(t, enforcer, record.KeyID, tenant, "missions", "execute", false)
		enforceExpect(t, enforcer, record.KeyID, tenant, "graphrag", "write", false)
	})

	t.Run("identity.HasCapability provides the wildcard fallback", func(t *testing.T) {
		t.Parallel()

		identity, err := a.Authenticate(context.Background(), rawKey)
		require.NoError(t, err)
		require.Equal(t, []string{"*"}, identity.Capabilities)

		// The SDK HasCapability method checks both exact match and the wildcard "*".
		assert.True(t, identity.HasCapability("*"),
			"HasCapability(*) must be true for a wildcard-capped identity")
		assert.True(t, identity.HasCapability("missions:execute"),
			"HasCapability must match any capability against the wildcard grant")
		assert.True(t, identity.HasCapability("graphrag:write"),
			"HasCapability must match graphrag:write against wildcard")
		assert.True(t, identity.HasCapability("plugin:gitlab:read"),
			"HasCapability must match compound capability against wildcard")
	})

	t.Run("legacy key (empty capabilities) normalises to wildcard", func(t *testing.T) {
		t.Parallel()

		// A key created with nil capabilities gets an empty Capabilities slice in
		// the record. Authenticate normalises this to ["*"] on every auth call.
		rawKeyLegacy, _, err := a.CreateKey(context.Background(), tenant, nil, nil, nil, "", "")
		require.NoError(t, err)

		identity, err := a.Authenticate(context.Background(), rawKeyLegacy)
		require.NoError(t, err)

		assert.Equal(t, []string{"*"}, identity.Capabilities,
			"nil capabilities must be normalised to [\"*\"] by Authenticate")
		assert.True(t, identity.HasCapability("missions:execute"),
			"legacy wildcard identity must pass any HasCapability check")
	})
}

// ---------------------------------------------------------------------------
// Scenario 4: Plugin access — tenant admin disables gitlab:write
// ---------------------------------------------------------------------------

// TestCapabilityEnforcement_PluginAccessControl verifies that the
// RedisPluginAccessStore correctly applies per-plugin read/write granularity
// and that Casbin policies are synced when access levels change.
func TestCapabilityEnforcement_PluginAccessControl(t *testing.T) {
	t.Parallel()

	const (
		tenant     = "security-ops"
		pluginName = "gitlab"
	)

	mr := miniredis.RunT(t)
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = redisClient.Close() })

	enforcer := newInMemoryEnforcer(t)
	logger := quietLogger()

	// The store needs no encryptor/keyProvider for access-control tests that
	// don't exercise GetDecryptedConfig.  Pass nil for those dependencies; the
	// methods under test (Enable, CheckAccess, SetAccessGranularity) do not touch
	// the crypto path.
	store := component.NewRedisPluginAccessStore(redisClient, nil, nil, nil, logger)
	store.SetEnforcer(enforcer)

	ctx := context.Background()

	// Enable the plugin with full read+write access (legacy: both granular flags
	// default to false → EffectiveRead/WriteEnabled both return true).
	err := store.Enable(ctx, tenant, pluginName, nil, "tenant-admin")
	require.NoError(t, err, "Enable must succeed for a new plugin")

	t.Run("read access is allowed after Enable", func(t *testing.T) {
		t.Parallel()

		err := store.CheckAccess(ctx, tenant, pluginName, false /* read */)
		assert.NoError(t, err, "CheckAccess(read) must succeed after Enable")
	})

	t.Run("write access is allowed after Enable", func(t *testing.T) {
		t.Parallel()

		err := store.CheckAccess(ctx, tenant, pluginName, true /* write */)
		assert.NoError(t, err, "CheckAccess(write) must succeed after Enable")
	})

	t.Run("Casbin reflects read+write policy after Enable", func(t *testing.T) {
		t.Parallel()

		resource := fmt.Sprintf("plugin:%s", pluginName)
		enforceExpect(t, enforcer, "tenant-admin", tenant, resource, "read", true)
		enforceExpect(t, enforcer, "tenant-admin", tenant, resource, "write", true)
	})

	// Tenant admin revokes write access — read-only mode.
	err = store.SetAccessGranularity(ctx, tenant, pluginName, true /* read */, false /* write */)
	require.NoError(t, err, "SetAccessGranularity must succeed")

	t.Run("write access is denied after disabling write", func(t *testing.T) {
		t.Parallel()

		err := store.CheckAccess(ctx, tenant, pluginName, true /* write */)
		assert.ErrorIs(t, err, component.ErrPluginAccessDenied,
			"CheckAccess(write) must return ErrPluginAccessDenied when WriteEnabled=false")
	})

	t.Run("read access is still allowed after disabling write", func(t *testing.T) {
		t.Parallel()

		err := store.CheckAccess(ctx, tenant, pluginName, false /* read */)
		assert.NoError(t, err,
			"CheckAccess(read) must still succeed when only write is disabled")
	})

	t.Run("Casbin removes write policy after disabling write", func(t *testing.T) {
		t.Parallel()

		resource := fmt.Sprintf("plugin:%s", pluginName)
		enforceExpect(t, enforcer, "tenant-admin", tenant, resource, "read", true)
		enforceExpect(t, enforcer, "tenant-admin", tenant, resource, "write", false)
	})

	// Completely disable the plugin.
	err = store.Disable(ctx, tenant, pluginName)
	require.NoError(t, err, "Disable must succeed")

	t.Run("read access is denied after Disable", func(t *testing.T) {
		t.Parallel()

		err := store.CheckAccess(ctx, tenant, pluginName, false /* read */)
		assert.ErrorIs(t, err, component.ErrPluginNotEnabled,
			"CheckAccess must return ErrPluginNotEnabled after Disable")
	})

	t.Run("Casbin removes all policies after Disable", func(t *testing.T) {
		t.Parallel()

		resource := fmt.Sprintf("plugin:%s", pluginName)
		enforceExpect(t, enforcer, "tenant-admin", tenant, resource, "read", false)
		enforceExpect(t, enforcer, "tenant-admin", tenant, resource, "write", false)
	})
}

// TestCapabilityEnforcement_PluginAccessControl_CrossTenant verifies that plugin
// access records for one tenant do not bleed into another tenant's namespace.
func TestCapabilityEnforcement_PluginAccessControl_CrossTenant(t *testing.T) {
	t.Parallel()

	const pluginName = "gitlab"

	mr := miniredis.RunT(t)
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = redisClient.Close() })

	enforcer := newInMemoryEnforcer(t)
	store := component.NewRedisPluginAccessStore(redisClient, nil, nil, nil, quietLogger())
	store.SetEnforcer(enforcer)

	ctx := context.Background()

	// Tenant A enables gitlab; Tenant B does not.
	err := store.Enable(ctx, "tenant-a", pluginName, nil, "admin")
	require.NoError(t, err)

	t.Run("tenant-a has read access", func(t *testing.T) {
		t.Parallel()
		err := store.CheckAccess(ctx, "tenant-a", pluginName, false)
		assert.NoError(t, err)
	})

	t.Run("tenant-b has no access — plugin not enabled", func(t *testing.T) {
		t.Parallel()
		err := store.CheckAccess(ctx, "tenant-b", pluginName, false)
		assert.ErrorIs(t, err, component.ErrPluginNotEnabled,
			"tenant-b must not inherit tenant-a's plugin access")
	})

	t.Run("Casbin tenant-b policy does not exist", func(t *testing.T) {
		t.Parallel()
		resource := fmt.Sprintf("plugin:%s", pluginName)
		enforceExpect(t, enforcer, "tenant-admin", "tenant-b", resource, "read", false)
	})
}

// ---------------------------------------------------------------------------
// Scenario 5: Component scope enforcement (AllowedKinds / AllowedNames)
// ---------------------------------------------------------------------------

// TestCapabilityEnforcement_ComponentScope verifies that API key records encode
// AllowedKinds and AllowedNames constraints and that the helper logic correctly
// permits or denies registration attempts based on those constraints.
//
// Gibson's daemon server enforces scope by inspecting the identity's claims
// (allowed_kinds / allowed_names) before accepting a RegisterComponent RPC.
// These tests exercise that logic via the APIKeyRecord fields and the
// authenticated Identity claims rather than a live gRPC call.
func TestCapabilityEnforcement_ComponentScope(t *testing.T) {
	t.Parallel()

	const tenant = "infra-team"

	enforcer := newInMemoryEnforcer(t)
	a, _ := newAPIKeyAuthenticatorWithEnforcer(t, enforcer)

	ctx := context.Background()

	// Create a key scoped to agent kind and the specific name "recon-agent".
	rawKey, record, err := a.CreateKey(ctx, tenant,
		[]string{"agent"},        // AllowedKinds
		[]string{"recon-agent"},  // AllowedNames
		[]string{"missions:read", "graphrag:read"},
		"", "",
	)
	require.NoError(t, err)
	t.Logf("created scoped key %s: kinds=%v names=%v", record.KeyID, record.AllowedKinds, record.AllowedNames)

	t.Run("record stores AllowedKinds and AllowedNames correctly", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t, []string{"agent"}, record.AllowedKinds)
		assert.Equal(t, []string{"recon-agent"}, record.AllowedNames)
	})

	t.Run("Authenticate surfaces AllowedKinds and AllowedNames in claims", func(t *testing.T) {
		t.Parallel()

		identity, err := a.Authenticate(ctx, rawKey)
		require.NoError(t, err)

		kinds, ok := identity.Claims["allowed_kinds"].([]string)
		require.True(t, ok, "allowed_kinds claim must be a []string")
		assert.Equal(t, []string{"agent"}, kinds,
			"allowed_kinds claim must match the record")

		names, ok := identity.Claims["allowed_names"].([]string)
		require.True(t, ok, "allowed_names claim must be a []string")
		assert.Equal(t, []string{"recon-agent"}, names,
			"allowed_names claim must match the record")
	})

	t.Run("registering as agent:recon-agent is permitted", func(t *testing.T) {
		t.Parallel()

		identity, err := a.Authenticate(ctx, rawKey)
		require.NoError(t, err)

		ok := componentScopePermits(identity, "agent", "recon-agent")
		assert.True(t, ok, "agent:recon-agent must be within the key's AllowedKinds/AllowedNames")
	})

	t.Run("registering as tool:nmap is denied — kind not in AllowedKinds", func(t *testing.T) {
		t.Parallel()

		identity, err := a.Authenticate(ctx, rawKey)
		require.NoError(t, err)

		ok := componentScopePermits(identity, "tool", "nmap")
		assert.False(t, ok,
			"tool:nmap must be denied — 'tool' is not in AllowedKinds=['agent']")
	})

	t.Run("registering as agent:pentest-agent is denied — name not in AllowedNames", func(t *testing.T) {
		t.Parallel()

		identity, err := a.Authenticate(ctx, rawKey)
		require.NoError(t, err)

		ok := componentScopePermits(identity, "agent", "pentest-agent")
		assert.False(t, ok,
			"agent:pentest-agent must be denied — 'pentest-agent' is not in AllowedNames")
	})

	t.Run("unrestricted key permits all kinds and names", func(t *testing.T) {
		t.Parallel()

		// A key with empty AllowedKinds and AllowedNames allows any registration.
		rawKeyFull, _, err := a.CreateKey(ctx, tenant, nil, nil, []string{"*"}, "", "")
		require.NoError(t, err)

		identity, err := a.Authenticate(ctx, rawKeyFull)
		require.NoError(t, err)

		assert.True(t, componentScopePermits(identity, "tool", "nmap"),
			"unrestricted key must allow tool:nmap registration")
		assert.True(t, componentScopePermits(identity, "agent", "recon-agent"),
			"unrestricted key must allow agent:recon-agent registration")
		assert.True(t, componentScopePermits(identity, "plugin", "gitlab"),
			"unrestricted key must allow plugin:gitlab registration")
	})
}

// ---------------------------------------------------------------------------
// Scenario 6: Multiple capabilities on the same key
// ---------------------------------------------------------------------------

// TestCapabilityEnforcement_MultipleCapabilities verifies that CreateKey adds a
// Casbin policy row for each capability in the list and that each is independently
// enforced.
func TestCapabilityEnforcement_MultipleCapabilities(t *testing.T) {
	t.Parallel()

	const tenant = "multi-team"

	enforcer := newInMemoryEnforcer(t)
	a, _ := newAPIKeyAuthenticatorWithEnforcer(t, enforcer)

	caps := []string{"missions:read", "missions:execute", "graphrag:read", "findings:write"}

	rawKey, record, err := a.CreateKey(context.Background(), tenant, nil, nil, caps, "", "")
	require.NoError(t, err)
	t.Logf("created key %s with %d capabilities", record.KeyID, len(caps))

	tests := []struct {
		resource  string
		action    string
		wantAllow bool
	}{
		{"missions", "read", true},
		{"missions", "execute", true},
		{"graphrag", "read", true},
		{"findings", "write", true},
		// Not granted:
		{"graphrag", "write", false},
		{"findings", "read", false},
		{"llm", "complete", false},
		{"plugin:gitlab", "read", false},
	}

	for _, tc := range tests {
		tc := tc
		name := fmt.Sprintf("%s:%s_expect_%v", tc.resource, tc.action, tc.wantAllow)
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			enforceExpect(t, enforcer, record.KeyID, tenant, tc.resource, tc.action, tc.wantAllow)
		})
	}

	t.Run("identity HasCapability matches all granted capabilities", func(t *testing.T) {
		t.Parallel()

		identity, err := a.Authenticate(context.Background(), rawKey)
		require.NoError(t, err)
		require.Equal(t, caps, identity.Capabilities)

		for _, cap := range caps {
			assert.True(t, identity.HasCapability(cap),
				"HasCapability must return true for granted capability %q", cap)
		}

		assert.False(t, identity.HasCapability("graphrag:write"),
			"HasCapability must return false for a capability not in the list")
	})
}

// ---------------------------------------------------------------------------
// Scenario 7: Key revocation removes Casbin policies
// ---------------------------------------------------------------------------

// TestCapabilityEnforcement_RevocationRemovesPolicies verifies that revoking an
// API key via RevokeKey removes its Casbin policy rows so that subsequent
// Enforce calls return deny even if somehow the key secret were leaked.
func TestCapabilityEnforcement_RevocationRemovesPolicies(t *testing.T) {
	t.Parallel()

	const tenant = "revoke-test"

	enforcer := newInMemoryEnforcer(t)
	a, _ := newAPIKeyAuthenticatorWithEnforcer(t, enforcer)

	ctx := context.Background()

	_, record, err := a.CreateKey(ctx, tenant, nil, nil, []string{"missions:read", "graphrag:write"}, "", "")
	require.NoError(t, err)

	// Verify policies are active before revocation.
	enforceExpect(t, enforcer, record.KeyID, tenant, "missions", "read", true)
	enforceExpect(t, enforcer, record.KeyID, tenant, "graphrag", "write", true)

	// Revoke the key.
	err = a.RevokeKey(ctx, record.KeyID)
	require.NoError(t, err, "RevokeKey must succeed")

	t.Run("missions:read policy removed after revocation", func(t *testing.T) {
		t.Parallel()
		enforceExpect(t, enforcer, record.KeyID, tenant, "missions", "read", false)
	})

	t.Run("graphrag:write policy removed after revocation", func(t *testing.T) {
		t.Parallel()
		enforceExpect(t, enforcer, record.KeyID, tenant, "graphrag", "write", false)
	})
}

// ---------------------------------------------------------------------------
// Scenario 8: SyncAllPolicies reconciles Casbin from Redis
// ---------------------------------------------------------------------------

// TestCapabilityEnforcement_SyncAllPolicies verifies that SyncAllPolicies loads
// every active key's capabilities from Redis into the in-memory Casbin enforcer.
// This models the daemon startup path where Casbin is initialised from ground-truth
// key records after an enforcer restart.
func TestCapabilityEnforcement_SyncAllPolicies(t *testing.T) {
	t.Parallel()

	const tenant = "sync-team"

	// Use a fresh enforcer that has NO policies loaded yet, mimicking a cold start.
	enforcer := newInMemoryEnforcer(t)
	a, _ := newAPIKeyAuthenticatorWithEnforcer(t, enforcer)

	ctx := context.Background()

	// Create two keys with different capabilities.
	_, rec1, err := a.CreateKey(ctx, tenant, nil, nil, []string{"missions:read"}, "", "")
	require.NoError(t, err)
	_, rec2, err := a.CreateKey(ctx, tenant, nil, nil, []string{"graphrag:write", "findings:read"}, "", "")
	require.NoError(t, err)

	// Simulate a cold enforcer restart by creating a brand-new empty enforcer and
	// re-attaching it to the authenticator.
	freshEnforcer := newInMemoryEnforcer(t)
	a.WithEnforcer(freshEnforcer)

	// Before sync, the fresh enforcer has no policies.
	enforceExpect(t, freshEnforcer, rec1.KeyID, tenant, "missions", "read", false)
	enforceExpect(t, freshEnforcer, rec2.KeyID, tenant, "graphrag", "write", false)

	// Run SyncAllPolicies to reconcile from Redis.
	err = a.SyncAllPolicies(ctx)
	require.NoError(t, err, "SyncAllPolicies must succeed")

	t.Run("rec1 missions:read policy restored", func(t *testing.T) {
		t.Parallel()
		enforceExpect(t, freshEnforcer, rec1.KeyID, tenant, "missions", "read", true)
	})

	t.Run("rec2 graphrag:write policy restored", func(t *testing.T) {
		t.Parallel()
		enforceExpect(t, freshEnforcer, rec2.KeyID, tenant, "graphrag", "write", true)
	})

	t.Run("rec2 findings:read policy restored", func(t *testing.T) {
		t.Parallel()
		enforceExpect(t, freshEnforcer, rec2.KeyID, tenant, "findings", "read", true)
	})

	t.Run("cross-key policies do not bleed", func(t *testing.T) {
		t.Parallel()
		// rec1 was not granted graphrag:write — it must not appear after sync.
		enforceExpect(t, freshEnforcer, rec1.KeyID, tenant, "graphrag", "write", false)
	})
}

// ---------------------------------------------------------------------------
// Internal helpers (package-level, not exported)
// ---------------------------------------------------------------------------

// componentScopePermits mirrors the scope-check logic performed by the daemon's
// RegisterComponent handler when validating a connecting component's identity.
//
// The rules are:
//  1. If AllowedKinds is non-empty, the registering component's kind must appear
//     in the list.
//  2. If AllowedNames is non-empty, the registering component's name must appear
//     in the list.
//  3. An empty (zero-length) slice for either field means "no restriction".
//
// This helper exists in the test file because the actual enforcement lives in the
// daemon server package (internal/daemon/api/server.go) which is not suitable for
// direct instantiation in unit-style tests.  The helper replicates the logic
// faithfully so these tests serve as a specification.
func componentScopePermits(identity *auth.Identity, kind, name string) bool {
	allowedKinds, _ := identity.Claims["allowed_kinds"].([]string)
	allowedNames, _ := identity.Claims["allowed_names"].([]string)

	// An empty restriction list means "all permitted".
	if len(allowedKinds) > 0 {
		found := false
		for _, k := range allowedKinds {
			if k == kind {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if len(allowedNames) > 0 {
		found := false
		for _, n := range allowedNames {
			if n == name {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}
