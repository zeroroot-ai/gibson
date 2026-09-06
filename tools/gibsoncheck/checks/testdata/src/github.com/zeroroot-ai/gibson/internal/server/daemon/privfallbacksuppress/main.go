// Package privfallbacksuppress proves the privilegedfallback
// suppression is not `# nolint` with extra steps: a bare marker and a
// marker naming a symbol that does not resolve are each their OWN
// diagnostic, in addition to the finding they tried to silence.
package privfallbacksuppress

import (
	"context"

	"github.com/zeroroot-ai/sdk/auth"
)

// emitGrantAudit is the compensating guard the valid suppression names.
func emitGrantAudit(subject string) {}

// bareMarker carries no qualifier at all.
//
// gibsoncheck:allow privileged-fallback
func bareMarker(ctx context.Context) auth.TenantID { // want `must name a compensating guard or a tracking issue` bareMarker:"privilegedFallback"
	t, ok := auth.TenantFromContext(ctx)
	if !ok {
		return auth.SystemTenant // want `privileged fallback`
	}
	return t
}

// unresolvableGuard names a symbol that does not exist, so the
// suppression cannot survive the guard being deleted or renamed.
//
// gibsoncheck:allow privileged-fallback guard:noSuchFunction -- because reasons here
func unresolvableGuard(ctx context.Context) auth.TenantID { // want `does not resolve to a function or method in scope` unresolvableGuard:"privilegedFallback"
	t, ok := auth.TenantFromContext(ctx)
	if !ok {
		return auth.SystemTenant // want `privileged fallback`
	}
	return t
}

// validGuard names a real symbol with a real rationale, and is
// accepted. Audit provenance is the realistic legitimate use: an empty
// caller renders as unattributed and never widens access.
//
// gibsoncheck:allow privileged-fallback guard:emitGrantAudit -- audit provenance only; empty caller renders as unattributed
func validGuard(ctx context.Context) string {
	callerID, _ := auth.IdentityFromContext(ctx)
	emitGrantAudit(callerID.Subject)
	return callerID.Subject
}
