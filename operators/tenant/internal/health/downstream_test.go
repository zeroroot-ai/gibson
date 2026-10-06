// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package health_test

import (
	"context"
	"time"
)

// --- minimal pinger fakes ---

type okPinger struct{}

func (okPinger) Ping(_ context.Context) error { return nil }

type errPinger struct{ err error }

func (e errPinger) Ping(_ context.Context) error { return e.err }

type slowPinger struct{ delay time.Duration }

func (s slowPinger) Ping(ctx context.Context) error {
	select {
	case <-time.After(s.delay):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// --- PingDashboard ---

// --- PingFGA ---

// --- PingRedis ---

// --- PingNeo4j ---

// --- PingStripe ---

// --- Composite ---
