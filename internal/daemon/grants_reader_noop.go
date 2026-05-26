// Package daemon — grants_reader_noop.go provides a no-op
// CapabilityGrantsReader for the GrantsAdminServer's ListActiveGrants
// surface. The CG-JWT store has not yet been plumbed end-to-end;
// returning an empty slice keeps the dashboard's grants-inspector page
// rendering a clean "no active grants" state until the wiring lands.
//
// This is intentionally separate from the Write/DeleteAgentGrants
// surface (which IS plumbed in this spec) so that the inspector half
// can be wired later without touching the writer half.
//
// Spec: component-bootstrap-e2e Requirement 9 (the writer side).
package daemon

import (
	"context"

	"github.com/zeroroot-ai/gibson/internal/admin"
	"github.com/zeroroot-ai/sdk/auth"
)

// noopGrantsReader returns an empty active-grants list. Replace with a
// real reader once the daemon's CG-JWT store gains a public read API.
type noopGrantsReader struct{}

// ListActive returns an empty slice — no error. The dashboard renders a
// "no active grants" empty state.
func (noopGrantsReader) ListActive(_ context.Context, _ auth.TenantID) ([]admin.GrantInfo, error) {
	return nil, nil
}
