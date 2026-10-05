// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package observability

import (
	"context"
	"sync"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// HealthChecker defines the interface that components must implement to be monitored.
// Components provide their current health status when queried.
type HealthChecker interface {
	// Health returns the current health status of the component.
	// The context can be used for timeout control and cancellation.
	Health(ctx context.Context) types.HealthStatus
}

// componentState tracks the current and previous health status of a component
// to detect state transitions (healthy -> degraded, degraded -> healthy, etc.)
type componentState struct {
	checker       HealthChecker
	lastStatus    types.HealthStatus
	lastCheckedAt time.Time
}

// HealthMonitor coordinates health checking across multiple system components.
// It tracks component health, emits metrics, logs state changes, and supports
// both on-demand and periodic health checks.
//
// The monitor is safe for concurrent use and supports dynamic component registration.
type HealthMonitor struct {
	metrics    harness.MetricsRecorder
	logger     *Logger
	components map[string]*componentState
	mu         sync.RWMutex
}
