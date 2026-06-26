// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

// Package health implements readyz probes for every downstream subsystem the
// operator depends on. Each ping function accepts a narrow interface so tests
// can inject fakes without importing the concrete client packages.
package health

import (
	"context"
	"time"
)

const subCheckTimeout = time.Second

// DashboardPinger is implemented by any client that can health-check the dashboard.
type DashboardPinger interface {
	Ping(ctx context.Context) error
}

// FGAPinger is the subset of fga.Client used by PingFGA.
type FGAPinger interface {
	Ping(ctx context.Context) error
}

// RedisPinger is the subset of redisstate.Client used by PingRedis.
type RedisPinger interface {
	Ping(ctx context.Context) error
}

// Neo4jPinger is the subset of neo4jstate.Client used by PingNeo4j.
type Neo4jPinger interface {
	Ping(ctx context.Context) error
}

// StripePinger is the subset of stripe.Client used by PingStripe.
type StripePinger interface {
	Ping(ctx context.Context) error
}

// PingDashboard verifies the dashboard admin API is reachable. Uses a 1s per-call timeout.
func PingDashboard(ctx context.Context, c DashboardPinger) error {
	ctx, cancel := context.WithTimeout(ctx, subCheckTimeout)
	defer cancel()
	return c.Ping(ctx)
}

// PingFGA verifies the OpenFGA store is reachable by performing a cheap read
// with an empty filter. Uses a 1s per-call timeout.
func PingFGA(ctx context.Context, c FGAPinger) error {
	ctx, cancel := context.WithTimeout(ctx, subCheckTimeout)
	defer cancel()
	return c.Ping(ctx)
}

// PingRedis verifies the Redis connection by sending a PING command.
// Uses a 1s per-call timeout.
func PingRedis(ctx context.Context, c RedisPinger) error {
	ctx, cancel := context.WithTimeout(ctx, subCheckTimeout)
	defer cancel()
	return c.Ping(ctx)
}

// PingNeo4j verifies the Neo4j connection by running CALL dbms.components().
// Uses a 1s per-call timeout.
func PingNeo4j(ctx context.Context, c Neo4jPinger) error {
	ctx, cancel := context.WithTimeout(ctx, subCheckTimeout)
	defer cancel()
	return c.Ping(ctx)
}

// PingStripe verifies the Stripe API key by calling balance.Get. If the client
// is nil (STRIPE_API_KEY unset), this is a no-op and returns nil; the caller
// is responsible for marking the check as "skipped" in the summary.
// Uses a 1s per-call timeout.
func PingStripe(ctx context.Context, c StripePinger) error {
	if c == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, subCheckTimeout)
	defer cancel()
	return c.Ping(ctx)
}
