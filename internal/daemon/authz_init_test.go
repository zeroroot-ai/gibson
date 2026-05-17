package daemon

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/config"
	"github.com/zero-day-ai/gibson/internal/observability"
)

// newMinimalDaemon constructs the smallest possible daemonImpl sufficient to
// call initAuthorizer without triggering real I/O.
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

// TestInitAuthorizer_FGAUnreachable_ExitsLoudly verifies the new contract from
// one-code-path slice deploy#195: when FGA cannot be reached at startup, the
// daemon returns an error that names "FGA" so the operator can find the cause
// in the CrashLoopBackOff event. There is no longer any silent fallback.
func TestInitAuthorizer_FGAUnreachable_ExitsLoudly(t *testing.T) {
	cfg := config.DefaultConfig()
	// Point at an endpoint that will never be reachable (IANA test subnet)
	cfg.Authz.Fga.Endpoint = "192.0.2.1:8080"
	cfg.Authz.Fga.TimeoutMs = 200 // short timeout so the test doesn't hang
	// Provide fake store/model IDs so resolution doesn't fail before the probe
	cfg.Authz.Fga.StoreID = "fake-store-id"
	cfg.Authz.Fga.ModelID = "fake-model-id"

	d := newMinimalDaemon(cfg)
	err := d.initAuthorizer(context.Background())

	require.Error(t, err, "initAuthorizer must fail when FGA is unreachable (no more noop fallback)")
	// The error must mention FGA so an operator scanning logs / CrashLoopBackOff
	// reasons can identify the broken dependency.
	assert.True(t,
		strings.Contains(err.Error(), "FGA") || strings.Contains(err.Error(), "fga"),
		"error message must name FGA, got: %s", err.Error(),
	)
}

// TestInitAuthorizer_NoSilentFallback verifies the daemon does not silently
// return success while leaving the authz path permissive. After deploy#195 a
// failed FGA startup must produce a non-nil error — never (nil, nil).
func TestInitAuthorizer_NoSilentFallback(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Authz.Fga.Endpoint = "192.0.2.1:8080" // unreachable
	cfg.Authz.Fga.TimeoutMs = 100
	cfg.Authz.Fga.StoreID = "fake-store"
	cfg.Authz.Fga.ModelID = "fake-model"

	d := newMinimalDaemon(cfg)
	err := d.initAuthorizer(context.Background())

	require.Error(t, err, "FGA unreachable must produce an error (no silent fallback)")
}
