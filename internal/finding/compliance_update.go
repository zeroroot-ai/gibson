// Package finding provides the curator-side API for updating compliance
// mappings on existing findings. This is the backing code for the
// UpdateFindingComplianceMappings RPC described in
// audit-finding-compliance-mappings task 7.
//
// The RPC proto definition itself is deferred to a follow-up that also
// handles the dashboard binding regeneration; this package exposes the
// curator logic as pure Go so the handler file can stay thin.
package finding

import (
	"context"
	"fmt"

	"github.com/zero-day-ai/sdk/finding"
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
	Log(ctx context.Context, action, resource, resourceID string, details map[string]any) error
}

// ComplianceUpdate is the request payload for
// UpdateComplianceMappings. Tenant is passed separately because the
// daemon extracts it from the auth context, not the request body.
type ComplianceUpdate struct {
	FindingID string
	Mode      UpdateMode
	Mappings  []finding.ComplianceMapping
}

// UpdateComplianceMappings applies a curator update to the finding's
// compliance_mappings list and writes an audit log entry with the diff.
// Returns the updated finding or an error.
//
// Semantics:
//   - tenant scoping: the finding must exist under the calling tenant;
//     a cross-tenant lookup returns the same error as "not found" so
//     tenant boundaries cannot be probed.
//   - APPEND mode: dedupes via finding.HasMapping, invalid mappings fail
//     the whole update (atomic).
//   - REPLACE mode: wipes existing mappings first, then applies the
//     incoming set; invalid mappings still fail atomically.
//   - audit log: written AFTER the store commit succeeds; the entry
//     contains action="finding.compliance_mappings.update", with a
//     details map showing the diff.
func UpdateComplianceMappings(
	ctx context.Context,
	store ComplianceFindingStore,
	logger ComplianceAuditLogger,
	tenantID string,
	req ComplianceUpdate,
) (*finding.Finding, error) {
	if store == nil {
		return nil, fmt.Errorf("UpdateComplianceMappings: store is required")
	}
	if tenantID == "" {
		return nil, fmt.Errorf("UpdateComplianceMappings: tenantID is required")
	}
	if req.FindingID == "" {
		return nil, fmt.Errorf("UpdateComplianceMappings: FindingID is required")
	}

	// Validate every incoming mapping before touching the store, so an
	// atomic rejection happens on bad input.
	for i, m := range req.Mappings {
		if err := m.Validate(); err != nil {
			return nil, fmt.Errorf("mapping #%d: %w", i+1, err)
		}
	}

	f, err := store.GetFinding(ctx, tenantID, req.FindingID)
	if err != nil {
		return nil, fmt.Errorf("load finding: %w", err)
	}
	if f == nil {
		return nil, fmt.Errorf("finding not found: %s", req.FindingID)
	}

	// Capture the before-snapshot for the audit diff.
	before := append([]finding.ComplianceMapping{}, f.ComplianceMappings...)

	switch req.Mode {
	case UpdateModeReplace:
		f.ComplianceMappings = nil
		for _, m := range req.Mappings {
			if err := f.AddComplianceMapping(m); err != nil {
				return nil, err
			}
		}
	case UpdateModeAppend:
		for _, m := range req.Mappings {
			if err := f.AddComplianceMapping(m); err != nil {
				return nil, err
			}
		}
	default:
		return nil, fmt.Errorf("unsupported update mode: %v", req.Mode)
	}

	if err := store.UpdateFinding(ctx, tenantID, f); err != nil {
		return nil, fmt.Errorf("persist finding: %w", err)
	}

	if logger != nil {
		// Fire-and-log: audit log failures do not block the update.
		_ = logger.Log(ctx, "finding.compliance_mappings.update", "finding", req.FindingID, map[string]any{
			"mode":      req.Mode.String(),
			"before":    before,
			"after":     f.ComplianceMappings,
			"tenant_id": tenantID,
		})
	}

	return f, nil
}
