package daemon

// readiness.go wires platform-clients/readiness probes for the daemon's
// /readyz endpoint.
//
// The daemon already exposes /readyz via sdk/health/http.Server (which
// evaluates the checks registered via RegisterReadinessCheck). This file
// adds platform-clients/readiness.Probe implementations that are registered
// alongside the existing probes with the "pc_" prefix, providing the
// canonical platform-clients format for tooling that expects it.
//
// Probe coverage (P1 audit finding, zeroroot-ai/.github#101):
//   - "postgres"   — dashboard shared Postgres reachability
//   - "authz_fga"  — FGA connectivity via a no-op Check probe
//
// Per-tenant Redis and Neo4j are NOT listed here — those are lazily
// provisioned and checked at request time. The system-level Redis is
// already covered by the existing "redis" RegisterReadinessCheck.
//
// Spec: zeroroot-ai/.github#101 (P1 — /readyz distinct from /healthz,
// platform-clients/readiness probes).

import (
	"context"
	"fmt"

	pcreadiness "github.com/zeroroot-ai/gibson/internal/infra/readiness"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

// platformReadinessProbe wraps a named function as a pcreadiness.Probe.
type platformReadinessProbe struct {
	name  string
	check func(ctx context.Context) error
}

func (p *platformReadinessProbe) Name() string                    { return p.name }
func (p *platformReadinessProbe) Check(ctx context.Context) error { return p.check(ctx) }

// newPlatformReadinessProbes returns a slice of platform-clients Probe
// implementations for the daemon's infrastructure dependencies.
// The caller registers each probe via healthServer.RegisterReadinessCheck.
func (d *daemonImpl) newPlatformReadinessProbes() []pcreadiness.Probe {
	var probes []pcreadiness.Probe

	// Platform Postgres (dashboard shared DB) — always present after a
	// successful Start(): initPlatformPostgres is fatal on failure (gibson#246).
	db := d.platformDB
	probes = append(probes, &platformReadinessProbe{
		name: "postgres",
		check: func(ctx context.Context) error {
			if err := db.PingContext(ctx); err != nil {
				return fmt.Errorf("postgres ping failed: %w", err)
			}
			return nil
		},
	})

	// FGA authorizer — nil when initAuthorizer has not run yet.
	if d.authorizer != nil {
		a := d.authorizer
		probes = append(probes, &platformReadinessProbe{
			name: "authz_fga",
			check: func(ctx context.Context) error {
				// Check a known-nonexistent tuple: any transport error
				// surfaces as unhealthy; a well-formed FGA response (even
				// denied) means FGA is reachable → healthy.
				_, err := a.Check(ctx, "user:_probe", "member", "tenant:_probe")
				if err != nil && (authz.IsUnavailable(err) || authz.IsTimeout(err)) {
					return fmt.Errorf("fga connectivity probe failed: %w", err)
				}
				return nil
			},
		})
	}

	return probes
}

// newPlatformReadinessAggregator constructs a platform-clients Aggregator
// with the daemon's infrastructure probes registered. Its ReadyHandler can
// be mounted on any http.ServeMux for a dedicated /readyz/platform path.
func (d *daemonImpl) newPlatformReadinessAggregator() *pcreadiness.Aggregator {
	agg := pcreadiness.NewAggregator()
	for _, p := range d.newPlatformReadinessProbes() {
		agg.Register(p)
	}
	return agg
}
