// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/zeroroot-ai/gibson/internal/platform/secrets"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
	"github.com/zeroroot-ai/sdk/auth"
	sdktypes "github.com/zeroroot-ai/sdk/types"
)

// secretPlaneProbeAdapter asks the secret source of the platform (the
// broker of the system tenant) to answer now. It does not read the cached
// health map, which holds nothing until a secret operation ran and would
// then report a dead source as healthy (hosted#174).
type secretPlaneProbeAdapter struct {
	registry *secrets.Registry
}

var _ api.SecretPlaneProbe = (*secretPlaneProbeAdapter)(nil)

func (a *secretPlaneProbeAdapter) Probe(ctx context.Context) error {
	broker, err := a.registry.For(ctx, auth.SystemTenant)
	if err != nil {
		return fmt.Errorf("open the system-tenant broker: %w", err)
	}
	if err := broker.Health(ctx); err != nil {
		return fmt.Errorf("system-tenant broker health: %w", err)
	}
	return nil
}

// secretSourceReadiness is the readiness check of the secret source. It is
// a start gate (hosted#174): each call probes the source with the bound of
// AdminGetPlatformHealth, and the daemon is not ready until a probe passes.
// After the first pass a failed probe does not change readiness. A short
// outage of the source must not take every daemon pod out of its Service at
// once, while the pods still serve on the secrets they loaded. That failure
// shows on AdminGetPlatformHealth and in the ExternalSecretNotReady alert.
func secretSourceReadiness(probe api.SecretPlaneProbe) func(context.Context) sdktypes.HealthStatus {
	var passed atomic.Bool
	return func(ctx context.Context) sdktypes.HealthStatus {
		probeCtx, cancel := context.WithTimeout(ctx, api.SecretPlaneProbeTimeout)
		defer cancel()
		err := probe.Probe(probeCtx)
		switch {
		case err == nil:
			passed.Store(true)
			return sdktypes.NewHealthyStatus("broker: the system-tenant secret source answered")
		case !passed.Load():
			return sdktypes.NewUnhealthyStatus("broker: the system-tenant secret source has not answered since start: "+err.Error(), nil)
		default:
			return sdktypes.NewHealthyStatus("broker: the secret source did not answer; the daemon serves on its loaded secrets, see the platform health: " + err.Error())
		}
	}
}
