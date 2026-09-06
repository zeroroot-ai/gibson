// Package privfallback exercises the privilegedfallback guard.
//
// M4 (the fail-closed canary) is the fixture that matters most: it
// deliberately MENTIONS a privileged sentinel inside the failure
// branch, as an error-message argument, and must produce ZERO
// diagnostics. A guard that fires on correct code gets suppressed
// everywhere within a month and stops being a guard.
package privfallback

import (
	"context"
	"errors"
	"fmt"

	"github.com/zeroroot-ai/sdk/auth"
)

// M1 — the exact defect: privileged sentinel returned on the failure
// branch of a fallible security accessor.
func tenantFromCtxOrSystem(ctx context.Context) auth.TenantID { // want tenantFromCtxOrSystem:"privilegedFallback"
	t, ok := auth.TenantFromContext(ctx)
	if !ok {
		return auth.SystemTenant // want `privileged fallback`
	}
	return t
}

// M2 — literal evasion. Dodging the typed sentinel by rebuilding the
// slug from string concatenation. The match runs on the FOLDED
// CONSTANT, not on source text, so this is caught too. If this fixture
// ever passes clean, the `values:` half of privileged_sentinels.yaml is
// not wired and the guard is trivially bypassable.
func tenantOrConcat(ctx context.Context) auth.TenantID { // want tenantOrConcat:"privilegedFallback"
	t, ok := auth.TenantFromContext(ctx)
	if !ok {
		out, _ := auth.NewTenantID("_sys" + "tem") // want `privileged fallback` `privileged fallback`
		return out
	}
	return t
}

// M3 — rename evasion, with the INVERTED condition shape. An
// innocuous name and `if ok { … }` with the fallback on the
// fallthrough. A rule that only matches `if !ok {}` is defeated by
// this; a shape-based rule is not.
func resolveTenantSafely(ctx context.Context) auth.TenantID { // want resolveTenantSafely:"privilegedFallback"
	t, ok := auth.TenantFromContext(ctx)
	if ok {
		return t
	} else {
		return auth.SystemTenant // want `privileged fallback`
	}
}

// M4 — FAIL-CLOSED CANARY. Must stay silent. The sentinel appears
// inside the failure branch, but only as text in the denial message,
// and the branch terminates by returning a non-nil error.
func tenantOrDeny(ctx context.Context) (auth.TenantID, error) {
	t, ok := auth.TenantFromContext(ctx)
	if !ok {
		return auth.TenantID{}, fmt.Errorf("no tenant; refusing %s access", auth.SystemTenantString)
	}
	return t, nil
}

// Also silent: an err-shaped accessor that denies.
func identityOrDeny(ctx context.Context) (auth.Identity, error) {
	id, err := auth.IdentityFromContext(ctx)
	if err != nil {
		return auth.Identity{}, errors.New("no identity in context")
	}
	return id, nil
}

// Silent: a comparison against the sentinel in the CONDITION is not a
// fallback. Only value production in the branch BODY is matched.
func rejectSystemTenant(ctx context.Context) error {
	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" || tenant == auth.SystemTenantString {
		return errors.New("unauthenticated")
	}
	return nil
}

// G3 — the failure result discarded into `_`.
func auditProvenance(ctx context.Context) string {
	callerID, _ := auth.IdentityFromContext(ctx) // want `privileged fallback`
	return callerID.Subject
}

// TenantOrSystem is the exported twin of tenantFromCtxOrSystem. It
// exists so the sibling privfallbackcaller package can prove the
// analysis.Fact crosses a package boundary.
func TenantOrSystem(ctx context.Context) auth.TenantID { // want TenantOrSystem:"privilegedFallback"
	t, ok := auth.TenantFromContext(ctx)
	if !ok {
		return auth.SystemTenant // want `privileged fallback`
	}
	return t
}
