// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package finding

import (
	"context"
)

// FindingStore provides persistence for EnhancedFindings
type FindingStore interface {
	// Store persists an enhanced finding
	Store(ctx context.Context, finding EnhancedFinding) error
}
