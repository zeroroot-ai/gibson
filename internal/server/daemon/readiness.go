// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

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
	sdksecrets "github.com/zeroroot-ai/gibson/internal/infra/secrets"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/sdk/auth"
)

// secretsBrokerHealthChecker is the narrow slice of *secrets.Registry the
// secrets-broker readiness probe needs. It is an interface so the check is
// unit-testable with a fake registry (the concrete *secrets.Registry satisfies
// it directly).
type secretsBrokerHealthChecker interface {
	For(ctx context.Context, tenant auth.TenantID) (sdksecrets.Broker, error)
	Health(ctx context.Context) map[auth.TenantID]error
}

// secretsBrokerReadinessCheck returns a /readyz check that fails when the
// secrets broker cannot serve the daemon's credentials.
//
// A broker that is unreachable, sealed, or circuit-open makes EVERY tenant
// credential unresolvable (LLM keys, plugin tokens, connector grants). Without
// this gate the daemon stays Ready while silently unable to read any secret —
// a configured provider then surfaces as "provider not found" and a broken
// backend sails through a rollout. This fails the pod LOUDLY instead.
func secretsBrokerReadinessCheck(reg secretsBrokerHealthChecker) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		// Passive: any already-cached tenant whose broker has gone unhealthy
		// fails readiness (the running-degradation case). Never fails vacuously
		// on a healthy install — no cached tenant means nothing to fail.
		for tenant, herr := range reg.Health(ctx) {
			if herr != nil {
				return fmt.Errorf("secrets broker unhealthy for tenant %s: %w", tenant, herr)
			}
		}
		// Active: best-effort reach the platform (system-tenant) broker so a
		// broken backend is caught before any tenant is cached (the fresh-rollout
		// case). A broker that is RESOLVABLE but unhealthy fails readiness. One
		// that does not resolve at all is a configuration state, NOT an outage,
		// and must not wedge readiness perpetually — so that case is tolerated.
		if broker, err := reg.For(ctx, auth.SystemTenant); err == nil {
			if herr := broker.Health(ctx); herr != nil {
				return fmt.Errorf("platform secrets broker health probe failed: %w", herr)
			}
		}
		return nil
	}
}

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

	// Secrets broker (OpenBao) — the daemon's single credential store. A broker
	// that is unreachable, sealed, or circuit-open makes EVERY tenant credential
	// unresolvable: LLM provider keys, plugin tokens, connector grants. Without
	// this gate the daemon stays Ready while silently unable to read any secret,
	// so a configured LLM provider surfaces as "provider not found" and a broken
	// secrets backend sails through a rollout. Gating readiness on it fails the
	// pod LOUDLY (never Ready) so the deploy is blocked, not silently degraded.
	if d.secretsRegistry != nil {
		probes = append(probes, &platformReadinessProbe{
			name:  "secrets_broker",
			check: secretsBrokerReadinessCheck(d.secretsRegistry),
		})
	}

	return probes
}
