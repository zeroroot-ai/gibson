// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

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
