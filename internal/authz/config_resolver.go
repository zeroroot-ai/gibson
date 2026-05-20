package authz

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"
)

// Per ADR-0023, the daemon does not call the Kubernetes API at runtime.
// The previous resolver path that GETted the gibson-fga-config ConfigMap
// is deleted. The chart now projects the same ConfigMap's keys as env
// vars on the daemon container via:
//
//	envFrom:
//	  - configMapRef:
//	      name: gibson-fga-config
//
// The ConfigMap's data keys are `store_id` and `model_id`, which kubelet
// projects as the env vars below.

const (
	// envStoreID is the environment variable the daemon reads for the
	// FGA store ID. Populated by the chart's envFrom on gibson-fga-config.
	envStoreID = "GIBSON_AUTHZ_FGA_STORE_ID"

	// envModelID is the environment variable the daemon reads for the
	// FGA model ID. Same projection mechanism.
	envModelID = "GIBSON_AUTHZ_FGA_MODEL_ID"
)

// IDConfig holds pre-populated store/model IDs read from the daemon
// config file. Both fields may be empty, in which case
// ResolveStoreAndModelIDs falls through to environment variables.
type IDConfig struct {
	// StoreID from the daemon config file (may be empty).
	StoreID string
	// ModelID from the daemon config file (may be empty).
	ModelID string
}

// ResolveStoreAndModelIDs determines the FGA store ID and model ID from
// two sources, in priority order:
//
//  1. Config file values (cfg.StoreID and cfg.ModelID) — highest priority
//  2. Environment variables GIBSON_AUTHZ_FGA_STORE_ID and
//     GIBSON_AUTHZ_FGA_MODEL_ID, populated by the chart from the
//     gibson-fga-config ConfigMap.
//
// If both IDs are already populated in cfg, the function returns
// immediately without touching the environment.
//
// Returns a descriptive error when both sources fail to produce both
// IDs. The error names the env vars that need to be set so a
// chart-render-vs-runtime mismatch is debuggable from a single log line.
//
// Spec: ADR-0023 (daemon-no-K8s-API); supersedes the previous
// ConfigMap-GET path.
func ResolveStoreAndModelIDs(_ context.Context, cfg IDConfig) (storeID, modelID string, err error) {
	storeID = cfg.StoreID
	modelID = cfg.ModelID

	if storeID == "" {
		storeID = os.Getenv(envStoreID)
	}
	if modelID == "" {
		modelID = os.Getenv(envModelID)
	}

	if storeID == "" || modelID == "" {
		return "", "", fmt.Errorf(
			"authz: FGA store/model IDs not resolved — set via daemon config file or %s + %s env vars (chart wires both via `envFrom: configMapRef: gibson-fga-config`)",
			envStoreID, envModelID,
		)
	}

	return storeID, modelID, nil
}

// ResolveWithRetry polls for FGA store/model IDs with exponential backoff.
// Used during daemon startup to wait for the gibson-fga-init Job to
// complete — the Job writes the ConfigMap whose keys the chart projects
// into the daemon's env. Until the Job finishes the env vars are absent
// (or empty), so this loop blocks until both arrive.
//
// Starts at a 2s interval and doubles up to a 15s maximum. Returns as
// soon as both IDs are non-empty. Returns an error only if ctx is
// cancelled or maxWait is exceeded. If logger is nil, retry logs are
// suppressed.
//
// Spec: ADR-0023. The previous signature took a kubernetes.Interface;
// it is gone — the env-only path needs no K8s client.
func ResolveWithRetry(ctx context.Context, cfg IDConfig, logger *slog.Logger, maxWait time.Duration) (storeID, modelID string, err error) {
	const (
		minInterval = 2 * time.Second
		maxInterval = 15 * time.Second
	)

	deadline := time.Now().Add(maxWait)
	interval := minInterval
	attempt := 0

	for {
		attempt++
		storeID, modelID, err = ResolveStoreAndModelIDs(ctx, cfg)
		if err == nil {
			return storeID, modelID, nil
		}

		if logger != nil {
			logger.Info("authz: waiting for FGA env vars",
				"attempt", attempt,
				"error", err,
				"retry_in", interval,
			)
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			return "", "", fmt.Errorf("authz: FGA IDs not available after %s (%d attempts): %w", maxWait, attempt, err)
		}

		sleep := interval
		if sleep > remaining {
			sleep = remaining
		}

		select {
		case <-ctx.Done():
			return "", "", fmt.Errorf("authz: context cancelled while waiting for FGA IDs: %w", ctx.Err())
		case <-time.After(sleep):
		}

		interval *= 2
		if interval > maxInterval {
			interval = maxInterval
		}
	}
}
