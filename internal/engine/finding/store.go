// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package finding

import (
	"context"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
)

// FindingStore provides persistence for EnhancedFindings
type FindingStore interface {
	// Store persists an enhanced finding
	Store(ctx context.Context, finding EnhancedFinding) error
}

// FindingFilter provides filtering options for finding queries.
// TenantID, when set, scopes all queries to that tenant's findings only,
// providing defense-in-depth isolation at the query layer. When TenantID is
// empty (single-tenant mode), queries are not tenant-scoped.
type FindingFilter struct {
	TenantID   string // Multi-tenant scoping — empty means no tenant filter
	Severity   *agent.FindingSeverity
	Category   *FindingCategory
	Status     *FindingStatus
	MinRisk    *float64
	MaxRisk    *float64
	AgentName  *string
	SearchText *string
}
