// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package reconciler holds the daemon's add-only converges over the FGA
// store: the platform catalog gate, the connector catalog, and the system
// backplane baseline every registered tenant needs.
package reconciler

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

// SystemBackplaneObject is the synthetic component every enrolled agent, tool
// and plugin drives or receives work through (ADR-0046). Its per-tenant
// gate is the same one every catalog component has: model.fga evaluates
// can_execute, can_receive_work and so can_poll_work as
// `(direct grant AND in_tenant_catalog)`, and in_tenant_catalog is
// `member from tenant_enabled`. A component principal holds its direct grant
// from enrolment (capabilitygrant.ClientCapabilityGrants) and its tenant
// membership from the same place. What nothing wrote was the tenant side:
// `tenant:<t> tenant_enabled component:_system`.
const SystemBackplaneObject = "component:_system"

// platformObject is the object every tenant registers under
// (operators/tenant/internal/grants.PlatformRegistrationTuple writes
// `tenant:<t> parent system_tenant:_system`).
const platformObject = "system_tenant:_system"

// DefaultSystemBackplaneInterval is the cadence RunSystemBackplaneBaseline
// converges at. A tenant registered between two ticks waits at most this
// long before its components can register; the SDK retries enrolment on a
// back-off, so the wait is absorbed there.
const DefaultSystemBackplaneInterval = 30 * time.Second

// SeedSystemBackplaneBaseline writes the tenant_enabled baseline on the
// system backplane for every tenant registered under the platform that does
// not hold it yet, and returns how many it wrote. Add-only converge, the
// same shape as SeedComponentCatalogGate: a tuple removed by hand de-lists
// the tenant until the next tick.
//
// Without this tuple no component enrolled through capability-grant can
// call ComponentService through Envoy: RegisterComponent, Heartbeat,
// PollWork and WatchComponentEvents are all gated on can_poll_work against
// component:_system, and ext-authz denied every one of them for the first
// plugin that ever tried on kind (gibson#154, run 35630951761). The
// catalog fan-out reconciler that used to seed it did not survive the
// history reset; the tenant operator still writes the parent tuple this
// enumerates, which is why the seed lives here and not at enrolment: one
// writer, per tenant, not one per enrolling principal.
func SeedSystemBackplaneBaseline(ctx context.Context, authorizer authz.Authorizer, logger *slog.Logger) (int, error) {
	tenants, err := authorizer.ListUsersOfType(ctx, "system_tenant", platformObject, "parent", "tenant")
	if err != nil {
		return 0, fmt.Errorf("system backplane baseline: list tenants under %s: %w", platformObject, err)
	}
	if len(tenants) == 0 {
		return 0, nil
	}
	enabled, err := authorizer.ListUsersOfType(ctx, "component", SystemBackplaneObject, "tenant_enabled", "tenant")
	if err != nil {
		return 0, fmt.Errorf("system backplane baseline: list tenant_enabled on %s: %w", SystemBackplaneObject, err)
	}
	have := make(map[string]struct{}, len(enabled))
	for _, t := range enabled {
		have[tenantRef(t)] = struct{}{}
	}
	toWrite := make([]authz.Tuple, 0, len(tenants))
	for _, t := range tenants {
		ref := tenantRef(t)
		if _, ok := have[ref]; ok {
			continue
		}
		toWrite = append(toWrite, authz.Tuple{User: ref, Relation: "tenant_enabled", Object: SystemBackplaneObject})
	}
	if len(toWrite) == 0 {
		return 0, nil
	}
	if err := authorizer.Write(ctx, toWrite); err != nil {
		return 0, fmt.Errorf("system backplane baseline: write %d tuples: %w", len(toWrite), err)
	}
	logger.Info("system backplane baseline seeded", "tenants", len(toWrite))
	return len(toWrite), nil
}

// tenantRef normalises a ListUsers result to the `tenant:<id>` FGA user.
// The FGA client returns typed references; a bare id is tolerated the way
// SeedComponentCatalogGate tolerates unprefixed objects.
func tenantRef(s string) string {
	if strings.HasPrefix(s, "tenant:") {
		return s
	}
	return "tenant:" + s
}

// RunSystemBackplaneBaseline converges once now and then every interval
// until ctx ends. A failed tick is logged and the next tick retries; the
// daemon serves everything else meanwhile, and a component whose tenant is
// not yet enabled is denied at the edge and retries its enrolment.
func RunSystemBackplaneBaseline(ctx context.Context, authorizer authz.Authorizer, interval time.Duration, logger *slog.Logger) {
	if interval <= 0 {
		interval = DefaultSystemBackplaneInterval
	}
	tick := func() {
		if _, err := SeedSystemBackplaneBaseline(ctx, authorizer, logger); err != nil {
			logger.Warn("system backplane baseline converge failed; next tick retries", "error", err)
		}
	}
	tick()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tick()
		}
	}
}
