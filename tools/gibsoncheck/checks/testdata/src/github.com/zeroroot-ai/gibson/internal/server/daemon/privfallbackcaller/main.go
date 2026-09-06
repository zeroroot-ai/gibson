// Package privfallbackcaller proves G2 — the analysis.Fact propagation.
//
// Nothing in this package matches G1 by shape. The diagnostic below
// exists ONLY because the callee in the sibling package was stamped
// with privilegedFallbackFact. If FactTypes is not wired, this fixture
// goes silent and the guard quietly degrades to catching definitions
// only, which is the difference between guarding the CLASS and
// guarding one function.
package privfallbackcaller

import (
	"context"

	"github.com/zeroroot-ai/gibson/internal/server/daemon/privfallback"
)

// ListMissions resolves the tenant through a tainted helper.
func ListMissions(ctx context.Context) string {
	tenant := privfallback.TenantOrSystem(ctx) // want `privileged fallback`
	return tenant.String()
}
