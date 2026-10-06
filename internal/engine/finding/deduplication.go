// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package finding

import (
	"sync"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// Deduplicator identifies and merges duplicate findings based on content similarity.
// It maintains a hash index for fast duplicate detection and supports evidence merging.
//
// Thread-safety: All methods use read-write locks to ensure safe concurrent access.
type Deduplicator struct {
	mu       sync.RWMutex
	findings map[types.ID]*EnhancedFinding // finding ID -> finding
}
