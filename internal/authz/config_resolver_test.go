package authz

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestResolveStoreAndModelIDs_FromConfig verifies that config file values
// take priority and return immediately without touching env vars.
func TestResolveStoreAndModelIDs_FromConfig(t *testing.T) {
	// Ensure env doesn't sneak in even if set on the host.
	t.Setenv(envStoreID, "should-not-be-read")
	t.Setenv(envModelID, "should-not-be-read")

	cfg := IDConfig{
		StoreID: "store-from-config",
		ModelID: "model-from-config",
	}

	storeID, modelID, err := ResolveStoreAndModelIDs(context.Background(), cfg)
	require.NoError(t, err)
	assert.Equal(t, "store-from-config", storeID)
	assert.Equal(t, "model-from-config", modelID)
}

// TestResolveStoreAndModelIDs_FromEnvVars verifies that env vars satisfy
// resolution when the config is empty. This is the production path —
// the chart projects gibson-fga-config via envFrom.
func TestResolveStoreAndModelIDs_FromEnvVars(t *testing.T) {
	t.Setenv(envStoreID, "store-from-env")
	t.Setenv(envModelID, "model-from-env")

	storeID, modelID, err := ResolveStoreAndModelIDs(context.Background(), IDConfig{})
	require.NoError(t, err)
	assert.Equal(t, "store-from-env", storeID)
	assert.Equal(t, "model-from-env", modelID)
}

// TestResolveStoreAndModelIDs_PartialConfig tests the mixed source case:
// config supplies one ID, env supplies the other.
func TestResolveStoreAndModelIDs_PartialConfig(t *testing.T) {
	t.Setenv(envStoreID, "store-from-env-should-be-ignored")
	t.Setenv(envModelID, "model-from-env")

	cfg := IDConfig{
		StoreID: "store-from-config",
		ModelID: "",
	}

	storeID, modelID, err := ResolveStoreAndModelIDs(context.Background(), cfg)
	require.NoError(t, err)
	assert.Equal(t, "store-from-config", storeID)
	assert.Equal(t, "model-from-env", modelID)
}

// TestResolveStoreAndModelIDs_NothingSet returns a typed error mentioning
// the env vars the chart must wire. This is the error the daemon emits at
// startup when the gibson-fga-config ConfigMap is missing or empty.
func TestResolveStoreAndModelIDs_NothingSet(t *testing.T) {
	// Clear any host-side env leakage.
	os.Unsetenv(envStoreID)
	os.Unsetenv(envModelID)

	_, _, err := ResolveStoreAndModelIDs(context.Background(), IDConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), envStoreID)
	assert.Contains(t, err.Error(), envModelID)
	assert.Contains(t, err.Error(), "gibson-fga-config")
}

// TestResolveStoreAndModelIDs_EnvWithEmptyValues treats an env var present
// but empty as "not set", matching the kubelet behaviour when a ConfigMap
// key is present but its value is the empty string.
func TestResolveStoreAndModelIDs_EnvWithEmptyValues(t *testing.T) {
	t.Setenv(envStoreID, "")
	t.Setenv(envModelID, "")

	_, _, err := ResolveStoreAndModelIDs(context.Background(), IDConfig{})
	require.Error(t, err)
}
