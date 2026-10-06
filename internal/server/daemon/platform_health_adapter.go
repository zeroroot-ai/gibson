// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"fmt"

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

// secretSourceReadiness is the readiness check of the secret source. Each
// call probes the source with the bound of AdminGetPlatformHealth. The
// daemon is not ready until a probe passes, and a later failed probe makes
// it not ready again: a silent source is never read as healthy (hosted#174).
func secretSourceReadiness(probe api.SecretPlaneProbe) func(context.Context) sdktypes.HealthStatus {
	return func(ctx context.Context) sdktypes.HealthStatus {
		probeCtx, cancel := context.WithTimeout(ctx, api.SecretPlaneProbeTimeout)
		defer cancel()
		if err := probe.Probe(probeCtx); err != nil {
			return sdktypes.NewUnhealthyStatus("broker: the system-tenant secret source did not answer: "+err.Error(), nil)
		}
		return sdktypes.NewHealthyStatus("broker: the system-tenant secret source answered")
	}
}
