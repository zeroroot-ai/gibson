// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/infra/config"
	"github.com/zeroroot-ai/gibson/internal/infra/observability"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/capabilitygrant"
)

func TestNewHarnessFactory_WithoutRegistryAdapter(t *testing.T) {
	logger := observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr})

	// Create daemon with minimal infrastructure (no registry adapter)
	d := &daemonImpl{
		logger:          logger,
		registryAdapter: nil, // No registry adapter
	}

	// Create minimal infrastructure manually
	d.infrastructure = &Infrastructure{}

	// Create harness factory - should still work even without registry adapter
	ctx := context.Background()
	factory, err := d.newHarnessFactory(ctx)
	require.NoError(t, err)
	assert.NotNil(t, factory, "Harness factory should be created even without registry adapter")
}

// TestTaskGrantVerifier_RefusesUntilTheKeyExists: the callback listener always
// gets a verifier, and until the daemon has a signing key that verifier answers
// ErrNoSigningKey. A presented grant is refused, never trusted (gibson#1605).
func TestTaskGrantVerifier_RefusesUntilTheKeyExists(t *testing.T) {
	d := &daemonImpl{}
	v := d.taskGrantVerifier()
	if v == nil {
		t.Fatal("the listener must always get a verifier, or a nil check becomes the gate")
	}
	if _, err := v.Verify(context.Background(), "x.y.z"); !errors.Is(err, capabilitygrant.ErrNoSigningKey) {
		t.Fatalf("err = %v, want ErrNoSigningKey", err)
	}
}

// TestTaskGrantVerifier_ReadsTheMinterPerCall: the Minter is built during
// Start, after the callback options are assembled, so the verifier has to read
// it per call rather than capture it.
func TestTaskGrantVerifier_ReadsTheMinterPerCall(t *testing.T) {
	d := &daemonImpl{}
	v := d.taskGrantVerifier()
	if _, err := v.Verify(context.Background(), "x.y.z"); !errors.Is(err, capabilitygrant.ErrNoSigningKey) {
		t.Fatalf("before the key: err = %v, want ErrNoSigningKey", err)
	}
	d.cgMinter = testCGMinter(t)
	if _, err := v.Verify(context.Background(), "x.y.z"); errors.Is(err, capabilitygrant.ErrNoSigningKey) {
		t.Fatal("after the key exists the same verifier must reach it")
	}
}

// testCGMinter builds a Minter over a fixed master key.
func testCGMinter(t *testing.T) *capabilitygrant.Minter {
	t.Helper()
	m, err := capabilitygrant.NewMinter(context.Background(), capabilitygrant.Config{
		Issuer: "https://test.daemon", Audience: "test-daemon",
		KeyProvider: fixedKeyProvider{key: []byte("kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk")},
		KeyID:       "k1",
	})
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}
	return m
}

// fixedKeyProvider hands out one master key.
type fixedKeyProvider struct{ key []byte }

func (f fixedKeyProvider) GetEncryptionKey(context.Context) ([]byte, error) { return f.key, nil }
func (f fixedKeyProvider) Name() string                                     { return "test" }
func (f fixedKeyProvider) Health(context.Context) types.HealthStatus {
	return types.HealthStatus{State: types.HealthStateHealthy}
}
func (f fixedKeyProvider) Close() error { return nil }

// The daemon does not start without a setec address (ADR-0142, gibson#756).
func TestNewHarnessFactory_RequiresTheSetecAddress(t *testing.T) {
	logger := observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr})
	newDaemon := func(addr string) *daemonImpl {
		cfg := config.DefaultConfig()
		cfg.Sandbox.Setec.Address = addr
		return &daemonImpl{
			config:         cfg,
			logger:         logger,
			infrastructure: &Infrastructure{},
		}
	}
	_, err := newDaemon("").newHarnessFactory(context.Background())
	require.ErrorIs(t, err, config.ErrNoSetecAddress)
}
