package authz

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// TestResolveStoreAndModelIDs_FromConfig verifies that config file values
// take priority and return immediately without touching k8s or env vars.
func TestResolveStoreAndModelIDs_FromConfig(t *testing.T) {
	cfg := IDConfig{
		StoreID: "store-from-config",
		ModelID: "model-from-config",
	}

	storeID, modelID, err := ResolveStoreAndModelIDs(context.Background(), cfg, nil)
	require.NoError(t, err)
	assert.Equal(t, "store-from-config", storeID)
	assert.Equal(t, "model-from-config", modelID)
}

// TestResolveStoreAndModelIDs_FromConfigMap verifies that a fake k8s client
// returning a populated ConfigMap satisfies resolution.
func TestResolveStoreAndModelIDs_FromConfigMap(t *testing.T) {
	fakeClient := fake.NewSimpleClientset(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fgaConfigMapName,
			Namespace: fgaConfigMapNamespace,
		},
		Data: map[string]string{
			cmKeyStoreID: "store-from-cm",
			cmKeyModelID: "model-from-cm",
		},
	})

	storeID, modelID, err := ResolveStoreAndModelIDs(context.Background(), IDConfig{}, fakeClient)
	require.NoError(t, err)
	assert.Equal(t, "store-from-cm", storeID)
	assert.Equal(t, "model-from-cm", modelID)
}

// TestResolveStoreAndModelIDs_PartialConfig tests that a partial config file
// (store_id set but model_id empty) falls through to the ConfigMap for the
// missing model_id while keeping the config store_id.
func TestResolveStoreAndModelIDs_PartialConfig(t *testing.T) {
	fakeClient := fake.NewSimpleClientset(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fgaConfigMapName,
			Namespace: fgaConfigMapNamespace,
		},
		Data: map[string]string{
			cmKeyStoreID: "store-from-cm", // should be ignored — config takes priority for store
			cmKeyModelID: "model-from-cm", // should be used for missing model
		},
	})

	cfg := IDConfig{
		StoreID: "store-from-config",
		ModelID: "",
	}

	storeID, modelID, err := ResolveStoreAndModelIDs(context.Background(), cfg, fakeClient)
	require.NoError(t, err)
	assert.Equal(t, "store-from-config", storeID)
	assert.Equal(t, "model-from-cm", modelID)
}

// TestResolveStoreAndModelIDs_FromEnvVars verifies that env vars are used
// as the final fallback when both config and ConfigMap fail.
func TestResolveStoreAndModelIDs_FromEnvVars(t *testing.T) {
	t.Setenv(envStoreID, "store-from-env")
	t.Setenv(envModelID, "model-from-env")

	// Empty config, no k8s client (will fail in-cluster detection gracefully)
	storeID, modelID, err := ResolveStoreAndModelIDs(context.Background(), IDConfig{}, nil)
	require.NoError(t, err)
	assert.Equal(t, "store-from-env", storeID)
	assert.Equal(t, "model-from-env", modelID)
}

// TestResolveStoreAndModelIDs_AllSourcesFail verifies the descriptive error
// when none of the three sources produces usable IDs.
func TestResolveStoreAndModelIDs_AllSourcesFail(t *testing.T) {
	// Ensure env vars are not set during this test
	t.Setenv(envStoreID, "")
	t.Setenv(envModelID, "")

	_, _, err := ResolveStoreAndModelIDs(context.Background(), IDConfig{}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "FGA store_id and model_id could not be resolved")
	assert.Contains(t, err.Error(), "config file")
	assert.Contains(t, err.Error(), "ConfigMap")
	assert.Contains(t, err.Error(), "env vars")
}

// TestResolveStoreAndModelIDs_ConfigMapMissingKeys verifies that a ConfigMap
// that exists but lacks the required keys returns a descriptive error.
func TestResolveStoreAndModelIDs_ConfigMapMissingKeys(t *testing.T) {
	t.Setenv(envStoreID, "")
	t.Setenv(envModelID, "")

	fakeClient := fake.NewSimpleClientset(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fgaConfigMapName,
			Namespace: fgaConfigMapNamespace,
		},
		Data: map[string]string{
			// Intentionally missing store_id and model_id
		},
	})

	// The ConfigMap error is non-fatal — it falls through to env vars (also empty).
	_, _, err := ResolveStoreAndModelIDs(context.Background(), IDConfig{}, fakeClient)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "FGA store_id and model_id could not be resolved")
}

// TestResolveStoreAndModelIDs_ConfigMapMissingModelFallsToEnv verifies that
// when the ConfigMap is missing model_id (which makes it return an error),
// resolution falls through to env vars for both IDs.
//
// The ConfigMap resolver requires BOTH keys to be present; if either is missing
// it returns an error and the whole CM source is skipped.
func TestResolveStoreAndModelIDs_ConfigMapMissingModelFallsToEnv(t *testing.T) {
	t.Setenv(envStoreID, "store-from-env")
	t.Setenv(envModelID, "model-from-env")

	// ConfigMap has only store_id — this causes the CM resolver to return an error,
	// so the entire CM source is skipped and env vars are used for both IDs.
	fakeClient := fake.NewSimpleClientset(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fgaConfigMapName,
			Namespace: fgaConfigMapNamespace,
		},
		Data: map[string]string{
			cmKeyStoreID: "store-from-cm",
			// model_id missing — CM resolver returns error, whole CM is skipped
		},
	})

	storeID, modelID, err := ResolveStoreAndModelIDs(context.Background(), IDConfig{}, fakeClient)
	require.NoError(t, err)
	// CM returns error (missing model_id) so env vars provide both
	assert.Equal(t, "store-from-env", storeID)
	assert.Equal(t, "model-from-env", modelID)
}

// TestResolveStoreAndModelIDs_EmptyEnvVars verifies that empty strings from
// env vars are not treated as valid IDs (i.e., they trigger the error path).
func TestResolveStoreAndModelIDs_EmptyEnvVars(t *testing.T) {
	// Explicitly empty (not unset) env vars
	require.NoError(t, os.Setenv(envStoreID, ""))
	require.NoError(t, os.Setenv(envModelID, ""))
	t.Cleanup(func() {
		os.Unsetenv(envStoreID)
		os.Unsetenv(envModelID)
	})

	_, _, err := ResolveStoreAndModelIDs(context.Background(), IDConfig{}, nil)
	require.Error(t, err)
}
