// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/platform/secrets"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
	"github.com/zeroroot-ai/sdk/auth"
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
