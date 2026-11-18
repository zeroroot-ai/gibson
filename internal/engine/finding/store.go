// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package finding

import (
	"context"
	"errors"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
)

// FindingStore provides persistence for EnhancedFindings
type FindingStore interface {
	// Store persists an enhanced finding in the database of the tenant.
	Store(ctx context.Context, tenantID string, finding EnhancedFinding) error
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

// ErrNotFound reports that the database of the tenant holds no finding with
// the requested ID.
var ErrNotFound = errors.New("finding: not found")

// Matches reports whether the finding passes the filter. A nil filter matches
// each finding.
func (f *FindingFilter) Matches(finding EnhancedFinding) bool {
	if f == nil {
		return true
	}
	if f.Severity != nil && finding.Severity != *f.Severity {
		return false
	}
	if f.Category != nil && finding.Category != string(*f.Category) {
		return false
	}
	if f.Status != nil && finding.Status != *f.Status {
		return false
	}
	if f.MinRisk != nil && finding.RiskScore < *f.MinRisk {
		return false
	}
	if f.MaxRisk != nil && finding.RiskScore > *f.MaxRisk {
		return false
	}
	if f.AgentName != nil && finding.AgentName != *f.AgentName {
		return false
	}
	if f.SearchText != nil {
		text := strings.ToLower(*f.SearchText)
		if !strings.Contains(strings.ToLower(finding.Title), text) &&
			!strings.Contains(strings.ToLower(finding.Description), text) {
			return false
		}
	}
	return true
}
