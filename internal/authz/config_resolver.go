package authz

import (
	"context"
	"fmt"
	"os"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	// fgaConfigMapName is the Kubernetes ConfigMap populated by the gibson-fga-init Job.
	fgaConfigMapName = "gibson-fga-config"

	// fgaConfigMapNamespace is the namespace where the ConfigMap lives.
	// Matches the Gibson deployment namespace.
	fgaConfigMapNamespace = "gibson"

	// cmKeyStoreID is the ConfigMap key for the FGA store ID.
	cmKeyStoreID = "store_id"

	// cmKeyModelID is the ConfigMap key for the FGA model ID.
	cmKeyModelID = "model_id"

	// envStoreID is the environment variable name for the FGA store ID fallback.
	envStoreID = "GIBSON_AUTHZ_FGA_STORE_ID"

	// envModelID is the environment variable name for the FGA model ID fallback.
	envModelID = "GIBSON_AUTHZ_FGA_MODEL_ID"
)

// IDConfig holds pre-populated store/model IDs read from the daemon config file.
// Both fields may be empty, in which case ResolveStoreAndModelIDs falls through
// to the ConfigMap and then to environment variables.
type IDConfig struct {
	// StoreID from the daemon config file (may be empty).
	StoreID string
	// ModelID from the daemon config file (may be empty).
	ModelID string
}

// ResolveStoreAndModelIDs determines the FGA store ID and model ID from one
// of three sources, in priority order:
//
//  1. Config file values (cfg.StoreID and cfg.ModelID) — highest priority
//  2. Kubernetes ConfigMap "gibson-fga-config" in namespace "gibson" (in-cluster)
//  3. Environment variables GIBSON_AUTHZ_FGA_STORE_ID and GIBSON_AUTHZ_FGA_MODEL_ID
//
// If both IDs are already populated in cfg, the function returns immediately
// without touching Kubernetes or environment variables.
//
// The k8sClient parameter is optional. If nil, the function attempts to create
// a client from in-cluster config. If not running in Kubernetes, it falls
// through gracefully to the env var source.
//
// Returns a descriptive error if all three sources fail to produce both IDs.
func ResolveStoreAndModelIDs(ctx context.Context, cfg IDConfig, k8sClient kubernetes.Interface) (storeID, modelID string, err error) {
	// Source 1: config file values.
	if cfg.StoreID != "" && cfg.ModelID != "" {
		return cfg.StoreID, cfg.ModelID, nil
	}

	storeID = cfg.StoreID
	modelID = cfg.ModelID

	// Source 2: Kubernetes ConfigMap (only if at least one ID is missing).
	cmStoreID, cmModelID, cmErr := resolveFromConfigMap(ctx, k8sClient)
	if cmErr == nil {
		if storeID == "" {
			storeID = cmStoreID
		}
		if modelID == "" {
			modelID = cmModelID
		}
	}

	// Source 3: environment variables.
	if storeID == "" {
		storeID = os.Getenv(envStoreID)
	}
	if modelID == "" {
		modelID = os.Getenv(envModelID)
	}

	// Validate — both IDs must be non-empty.
	if storeID == "" || modelID == "" {
		return "", "", fmt.Errorf(
			"authz: FGA store_id and model_id could not be resolved — tried: "+
				"(1) config file [store_id=%q model_id=%q], "+
				"(2) ConfigMap %s/%s [err=%v], "+
				"(3) env vars %s=%q %s=%q — "+
				"ensure the gibson-fga-init Job has run successfully",
			cfg.StoreID, cfg.ModelID,
			fgaConfigMapNamespace, fgaConfigMapName, cmErr,
			envStoreID, os.Getenv(envStoreID),
			envModelID, os.Getenv(envModelID),
		)
	}

	return storeID, modelID, nil
}

// resolveFromConfigMap reads the FGA store and model IDs from the
// gibson-fga-config ConfigMap in the gibson namespace.
//
// If k8sClient is nil it attempts to build one from in-cluster config.
// Returns ("", "", err) if the ConfigMap is unreachable or the keys are missing.
func resolveFromConfigMap(ctx context.Context, k8sClient kubernetes.Interface) (storeID, modelID string, err error) {
	if k8sClient == nil {
		cfg, cfgErr := rest.InClusterConfig()
		if cfgErr != nil {
			// Not running in Kubernetes — fall through to env vars.
			return "", "", fmt.Errorf("not running in-cluster: %w", cfgErr)
		}
		k8sClient, err = kubernetes.NewForConfig(cfg)
		if err != nil {
			return "", "", fmt.Errorf("failed to build k8s client: %w", err)
		}
	}

	cm, err := k8sClient.CoreV1().ConfigMaps(fgaConfigMapNamespace).Get(ctx, fgaConfigMapName, metav1.GetOptions{})
	if err != nil {
		return "", "", fmt.Errorf("ConfigMap %s/%s not found: %w", fgaConfigMapNamespace, fgaConfigMapName, err)
	}

	storeID = cm.Data[cmKeyStoreID]
	modelID = cm.Data[cmKeyModelID]

	if storeID == "" || modelID == "" {
		return "", "", fmt.Errorf(
			"ConfigMap %s/%s exists but is missing keys (store_id=%q model_id=%q) — "+
				"has the gibson-fga-init Job completed successfully?",
			fgaConfigMapNamespace, fgaConfigMapName, storeID, modelID,
		)
	}

	return storeID, modelID, nil
}
