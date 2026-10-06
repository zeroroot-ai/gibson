// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package observability

import (
	"context"

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
}
