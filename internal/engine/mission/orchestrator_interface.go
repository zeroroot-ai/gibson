// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package mission

import (
	"context"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// TargetStore provides access to target entities needed by the orchestrator.
// This interface allows the orchestrator to load full target details including
// connection parameters that agents need for testing.
type TargetStore interface {
	// Get retrieves a target by ID, returning the full target entity with connection details
	Get(ctx context.Context, id types.ID) (*types.Target, error)
}
