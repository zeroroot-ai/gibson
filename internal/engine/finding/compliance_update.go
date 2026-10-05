// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package finding provides the curator-side API for updating compliance
// mappings on existing findings. This is the backing code for the
// UpdateFindingComplianceMappings RPC described in
// audit-finding-compliance-mappings task 7.
//
// The RPC proto definition itself is deferred to a follow-up that also
// handles the dashboard binding regeneration; this package exposes the
// curator logic as pure Go so the handler file can stay thin.
//
// This survived the deletion of the compliance-signal pipeline (gibson#1299,
// ADR-0113) deliberately. That pipeline stamped control IDs automatically from
// rules, which makes it redundant with deriving the same mapping from retained
// audit events at query time. A curator's judgement — "this finding evidences
// this control" — is derivable from no rule, so query-time derivation cannot
// reconstruct it. This is the complement of what was deleted, not an instance
// of it.
package finding

import (
	"context"

	"github.com/zeroroot-ai/sdk/finding"
)

// UpdateMode controls how AddComplianceMappings combines the incoming
// mappings with any already on the finding.
type UpdateMode int

const (
	// UpdateModeAppend deduplicates then appends new mappings, preserving
	// any existing mappings (default, non-destructive).
	UpdateModeAppend UpdateMode = 0

	// UpdateModeReplace clears the existing mappings and replaces them
	// entirely with the incoming set (destructive).
	UpdateModeReplace UpdateMode = 1
)

// String returns the canonical name of the update mode.
func (m UpdateMode) String() string {
	switch m {
	case UpdateModeAppend:
		return "APPEND"
	case UpdateModeReplace:
		return "REPLACE"
	default:
		return "UNKNOWN"
	}
}

// ComplianceFindingStore is the narrow interface the curator logic needs
// from the daemon's finding store. Named with the Compliance prefix to
// avoid colliding with the existing FindingStore declared in store.go.
// Production passes an adapter over the real store; tests pass a fake.
type ComplianceFindingStore interface {
	GetFinding(ctx context.Context, tenantID, findingID string) (*finding.Finding, error)
	UpdateFinding(ctx context.Context, tenantID string, f *finding.Finding) error
}

// ComplianceAuditLogger is the narrow interface the curator logic needs
// for audit logging. Matches the subset of
// core/gibson/internal/audit.AuditLogger.
type ComplianceAuditLogger interface {
	Log(ctx context.Context, action, resource, resourceID string, details map[string]any)
}

// ComplianceUpdate is the request payload for
// UpdateComplianceMappings. Tenant is passed separately because the
// daemon extracts it from the auth context, not the request body.
type ComplianceUpdate struct {
	FindingID string
	Mode      UpdateMode
	Mappings  []finding.ComplianceMapping
}
