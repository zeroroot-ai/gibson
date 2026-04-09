package daemon

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/authz"
	"github.com/zero-day-ai/gibson/internal/config"
	"github.com/zero-day-ai/gibson/internal/observability"
)

// newMinimalDaemon constructs the smallest possible daemonImpl sufficient to
// call initAuthorizer / handleAuthzFailure without triggering real I/O.
func newMinimalDaemon(cfg *config.Config) *daemonImpl {
	logCfg := observability.ConfigFromEnv()
	logCfg.Component = "daemon-test"
	logger := observability.NewLogger(logCfg)

	return &daemonImpl{
		config:         cfg,
		logger:         logger,
		activeMissions: make(map[string]context.CancelFunc),
		agentState:     make(map[string]*AgentRuntimeState),
	}
}

// TestInitAuthorizer_Disabled verifies that authz.enabled=false always
// injects a noopAuthorizer and returns nil — the fast path.
func TestInitAuthorizer_Disabled(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Authz.Enabled = false

	d := newMinimalDaemon(cfg)
	err := d.initAuthorizer(context.Background())
	require.NoError(t, err)
	require.NotNil(t, d.authorizer, "authorizer must not be nil even when disabled")

	// Verify it's the no-op: Check should always return true with no error
	allowed, checkErr := d.authorizer.Check(context.Background(), "user:test", "member", "tenant:test")
	assert.NoError(t, checkErr)
	assert.True(t, allowed, "noopAuthorizer.Check must return true")
}

// TestInitAuthorizer_EnabledFGAUnreachable_RequireReady verifies that when
// authz.enabled=true and FGA is unreachable with require_ready=true, the
// daemon returns an error (fail-closed / production behavior).
func TestInitAuthorizer_EnabledFGAUnreachable_RequireReady(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Authz.Enabled = true
	cfg.Authz.RequireReady = true
	// Point at an endpoint that will never be reachable (IANA test subnet)
	cfg.Authz.Fga.Endpoint = "192.0.2.1:8080"
	cfg.Authz.Fga.TimeoutMs = 200 // short timeout so the test doesn't hang
	// Provide fake store/model IDs so resolution doesn't fail before the probe
	cfg.Authz.Fga.StoreID = "fake-store-id"
	cfg.Authz.Fga.ModelID = "fake-model-id"

	d := newMinimalDaemon(cfg)
	err := d.initAuthorizer(context.Background())
	require.Error(t, err, "should fail when FGA is unreachable and require_ready=true")
	assert.Contains(t, err.Error(), "authorization service")
}

// TestInitAuthorizer_EnabledFGAUnreachable_DevMode verifies that when
// authz.enabled=true and FGA is unreachable with require_ready=false, the
// daemon falls back to noopAuthorizer and returns nil (dev mode behavior).
func TestInitAuthorizer_EnabledFGAUnreachable_DevMode(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Authz.Enabled = true
	cfg.Authz.RequireReady = false // dev mode
	// Point at an endpoint that will never be reachable
	cfg.Authz.Fga.Endpoint = "192.0.2.1:8080"
	cfg.Authz.Fga.TimeoutMs = 200
	cfg.Authz.Fga.StoreID = "fake-store-id"
	cfg.Authz.Fga.ModelID = "fake-model-id"

	d := newMinimalDaemon(cfg)
	err := d.initAuthorizer(context.Background())
	require.NoError(t, err, "should succeed in dev mode even when FGA is unreachable")
	require.NotNil(t, d.authorizer, "authorizer must be set to noop in dev mode")

	// The fallback noop should allow all checks
	allowed, checkErr := d.authorizer.Check(context.Background(), "user:test", "member", "tenant:test")
	assert.NoError(t, checkErr)
	assert.True(t, allowed)
}

// TestHandleAuthzFailure_RequireReadyTrue verifies that require_ready=true
// causes handleAuthzFailure to return the original error (fail-closed).
func TestHandleAuthzFailure_RequireReadyTrue(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Authz.RequireReady = true

	d := newMinimalDaemon(cfg)
	originalErr := errors.New("connectivity probe failed")
	err := d.handleAuthzFailure(context.Background(), cfg.Authz, originalErr)

	require.Error(t, err)
	assert.Equal(t, originalErr, err, "original error must be returned unchanged")
	// authorizer is still set to noop (safe default even before returning error)
	require.NotNil(t, d.authorizer)
}

// TestHandleAuthzFailure_RequireReadyFalse verifies that require_ready=false
// causes handleAuthzFailure to inject noopAuthorizer and return nil (dev mode).
func TestHandleAuthzFailure_RequireReadyFalse(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Authz.RequireReady = false

	d := newMinimalDaemon(cfg)
	originalErr := fmt.Errorf("connectivity probe failed")
	err := d.handleAuthzFailure(context.Background(), cfg.Authz, originalErr)

	require.NoError(t, err)
	require.NotNil(t, d.authorizer, "noopAuthorizer must be set in dev mode fallback")
}

// TestInitAuthorizer_AuthorizerAlwaysNonNil verifies the invariant that
// d.authorizer is always non-nil after initAuthorizer returns (regardless of
// error). This is important so other subsystems can always call d.authorizer
// without nil checks.
func TestInitAuthorizer_AuthorizerAlwaysNonNil(t *testing.T) {
	cases := []struct {
		name         string
		enabled      bool
		requireReady bool
	}{
		{"disabled", false, true},
		{"enabled-require-ready", true, true},
		{"enabled-dev-mode", true, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.Authz.Enabled = tc.enabled
			cfg.Authz.RequireReady = tc.requireReady
			cfg.Authz.Fga.Endpoint = "192.0.2.1:8080" // unreachable
			cfg.Authz.Fga.TimeoutMs = 100
			cfg.Authz.Fga.StoreID = "fake-store"
			cfg.Authz.Fga.ModelID = "fake-model"

			d := newMinimalDaemon(cfg)
			_ = d.initAuthorizer(context.Background()) // ignore error

			// The invariant: authorizer must never be nil
			assert.NotNil(t, d.authorizer,
				"d.authorizer must never be nil after initAuthorizer (case: %s)", tc.name)
		})
	}
}

// TestInitAuthorizer_DisabledIsNoopNotFGA verifies that the disabled fast path
// does not construct any FGA client (no network calls, no ID resolution).
// We validate by checking that the returned authorizer returns empty store/model IDs,
// which only the noopAuthorizer does.
func TestInitAuthorizer_DisabledIsNoopNotFGA(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Authz.Enabled = false
	// These should be ignored entirely
	cfg.Authz.Fga.StoreID = "should-be-ignored"
	cfg.Authz.Fga.ModelID = "should-be-ignored"

	d := newMinimalDaemon(cfg)
	err := d.initAuthorizer(context.Background())
	require.NoError(t, err)

	// noopAuthorizer returns empty strings for StoreID and ModelID
	assert.Equal(t, "", d.authorizer.StoreID(), "noopAuthorizer.StoreID must return empty string")
	assert.Equal(t, "", d.authorizer.ModelID(), "noopAuthorizer.ModelID must return empty string")
}

// TestInitAuthorizer_DefaultConfig verifies that the default config
// (authz.enabled=false) produces a working noopAuthorizer without any
// external dependencies.
func TestInitAuthorizer_DefaultConfig(t *testing.T) {
	cfg := config.DefaultConfig()
	// Verify the default has authz disabled
	require.False(t, cfg.Authz.Enabled, "default config must have authz disabled")

	d := newMinimalDaemon(cfg)
	err := d.initAuthorizer(context.Background())
	require.NoError(t, err)

	// Must be able to call all Authorizer methods without panic
	ctx := context.Background()
	allowed, err := d.authorizer.Check(ctx, "user:x", "member", "tenant:y")
	assert.NoError(t, err)
	assert.True(t, allowed)

	batchResults, err := d.authorizer.BatchCheck(ctx, []authz.CheckRequest{
		{User: "user:x", Relation: "member", Object: "tenant:y"},
	})
	assert.NoError(t, err)
	assert.Len(t, batchResults, 1)

	err = d.authorizer.Write(ctx, []authz.Tuple{{User: "user:x", Relation: "member", Object: "tenant:y"}})
	assert.NoError(t, err)

	err = d.authorizer.Delete(ctx, []authz.Tuple{{User: "user:x", Relation: "member", Object: "tenant:y"}})
	assert.NoError(t, err)

	objects, err := d.authorizer.ListObjects(ctx, "user:x", "member", "tenant")
	assert.NoError(t, err)
	assert.Empty(t, objects)

	users, err := d.authorizer.ListUsers(ctx, "tenant", "tenant:y", "member")
	assert.NoError(t, err)
	assert.Empty(t, users)

	assert.NoError(t, d.authorizer.Close())
}
