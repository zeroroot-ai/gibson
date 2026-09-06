// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

// Regression tests for identity-assertion-gaps finding 1:
//
//  1. Loose mode (looseModeForEntry / looseIdentityFromMD) must apply the
//     same structural validation and freshness check as every other
//     identity path (auth.IdentityFromMetadata), just without requiring a
//     tenant.
//  2. The SPIFFE direct-dial method-policy bypass must be evaluated BEFORE
//     the registry loose-mode check (resolveLooseOrBypassIdentity), so a
//     policy-constrained direct-dial peer cannot sidestep its method policy
//     merely because the target RPC happens to be registry-classified
//     Unauthenticated/Self.
//
// Both tests below FAIL against the pre-fix code (looseIdentityFromMD had
// no freshness check and no issuer/subject validation, was a `context.Context
// -> context.Context` closure with no error path; the loose-mode branch in
// registryAwareUnary/Stream ran unconditionally before the SPIFFE bypass)
// and PASS after.

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	grpcmetadata "google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/sdk/auth"
)

// selfModeMethod is a real Self-mode registry entry (sign-in bootstrap RPC,
// no tenant required) used across these tests. See
// internal/platform/authz/registry/registry.go.
const selfModeMethod = "/gibson.daemon.v1.DaemonService/GetMyPermissions"

func mdWithIdentity(t *testing.T, overrides map[string]string) grpcmetadata.MD {
	t.Helper()
	base := map[string]string{
		auth.HeaderSubject:        "user-123",
		auth.HeaderIssuer:         string(auth.IssuerOIDC),
		auth.HeaderCredentialType: string(auth.CredentialOIDCUser),
		auth.HeaderIssuedAt:       unixSeconds(time.Now()),
		// ext-authz always sets the tenant header, empty for self-mode
		// bootstrap calls (Emit() calls h.Set unconditionally).
		auth.HeaderTenant: "",
	}
	for k, v := range overrides {
		base[k] = v
	}
	md := grpcmetadata.MD{}
	for k, v := range base {
		md.Set(k, v)
	}
	return md
}

func unixSeconds(t time.Time) string {
	return strconv.FormatInt(t.Unix(), 10)
}

// --- looseIdentityFromMD: structural validation + freshness ---

func TestLooseIdentityFromMD_AcceptsValidNoTenantHeader(t *testing.T) {
	md := mdWithIdentity(t, nil)
	ctx := grpcmetadata.NewIncomingContext(context.Background(), md)

	newCtx, err := looseIdentityFromMD(ctx)
	require.NoError(t, err)

	id, err := auth.IdentityFromContext(newCtx)
	require.NoError(t, err)
	assert.Equal(t, "user-123", id.Subject)
	assert.True(t, id.Tenant.IsZero(), "self/unauthenticated identity must not carry a tenant")
}

func TestLooseIdentityFromMD_RejectsMissingSubject(t *testing.T) {
	md := mdWithIdentity(t, map[string]string{auth.HeaderSubject: ""})
	ctx := grpcmetadata.NewIncomingContext(context.Background(), md)

	_, err := looseIdentityFromMD(ctx)
	require.Error(t, err, "REGRESSION: a request with no subject header must be rejected, not silently forwarded")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestLooseIdentityFromMD_RejectsUnknownIssuer(t *testing.T) {
	md := mdWithIdentity(t, map[string]string{auth.HeaderIssuer: "not-a-real-issuer"})
	ctx := grpcmetadata.NewIncomingContext(context.Background(), md)

	_, err := looseIdentityFromMD(ctx)
	require.Error(t, err, "REGRESSION: loose mode must validate the issuer against the known enum, exactly like the strict path")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// TestLooseIdentityFromMD_RejectsStaleIssuedAt is the core regression test
// for the missing freshness/replay bound: before the fix, loose mode never
// checked x-gibson-identity-issued-at at all, so a captured/replayed header
// set was accepted forever. After the fix it must be rejected outside the
// same +/-60s skew window every other identity path enforces.
func TestLooseIdentityFromMD_RejectsStaleIssuedAt(t *testing.T) {
	stale := time.Now().Add(-10 * time.Minute)
	md := mdWithIdentity(t, map[string]string{auth.HeaderIssuedAt: unixSeconds(stale)})
	ctx := grpcmetadata.NewIncomingContext(context.Background(), md)

	_, err := looseIdentityFromMD(ctx)
	require.Error(t, err, "REGRESSION (identity-assertion-gaps finding 1): loose mode must apply the same "+
		"freshness/replay bound as every other identity path; a 10-minute-stale issued-at header was accepted")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestLooseIdentityFromMD_RejectsFutureIssuedAt(t *testing.T) {
	future := time.Now().Add(10 * time.Minute)
	md := mdWithIdentity(t, map[string]string{auth.HeaderIssuedAt: unixSeconds(future)})
	ctx := grpcmetadata.NewIncomingContext(context.Background(), md)

	_, err := looseIdentityFromMD(ctx)
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestLooseIdentityFromMD_RejectsNoMetadata(t *testing.T) {
	_, err := looseIdentityFromMD(context.Background())
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// TestLooseIdentityFromMD_AcceptsValidWithTenantHeader covers the branch
// where the tenant header IS supplied with a real, non-empty value (as
// opposed to every other test in this file, which exercises the
// self/unauthenticated bootstrap case with no tenant). This is a defensive
// path — ext-authz does not populate a real tenant for Self/Unauthenticated
// registry entries in practice — but looseIdentityFromMD must still handle
// it correctly if it ever occurs: the supplied tenant is validated and
// preserved on the resulting Identity, not overwritten by the internal
// looseModePlaceholderTenant.
func TestLooseIdentityFromMD_AcceptsValidWithTenantHeader(t *testing.T) {
	md := mdWithIdentity(t, map[string]string{auth.HeaderTenant: "acme"})
	ctx := grpcmetadata.NewIncomingContext(context.Background(), md)

	newCtx, err := looseIdentityFromMD(ctx)
	require.NoError(t, err)

	id, err := auth.IdentityFromContext(newCtx)
	require.NoError(t, err)
	assert.Equal(t, "acme", id.Tenant.String())
}

// --- resolveLooseOrBypassIdentity: ordering ---

// TestResolveLooseOrBypassIdentity_SPIFFEPolicyDenialPrecedesLooseMode is the
// core regression test for the ordering half of finding 1. It simulates a
// direct-dial SPIFFE peer that IS recognised (mTLS-allow-listed) but whose
// method policy denies the specific method being called — exactly the
// tenant-operator-calls-GetMyPermissions scenario in the finding. Before the
// fix, the loose-mode branch ran first and returned unconditionally for any
// Self/Unauthenticated-classified method, so this denial was never reached:
// the peer's raw headers were trusted instead. After the fix, the bypass's
// PermissionDenied must be authoritative.
func TestResolveLooseOrBypassIdentity_SPIFFEPolicyDenialPrecedesLooseMode(t *testing.T) {
	denyErr := status.Errorf(codes.PermissionDenied, "SPIFFE peer is not authorised to call this method")
	bypass := func(ctx context.Context, _ string) (context.Context, bool, error) {
		return ctx, false, denyErr
	}

	md := mdWithIdentity(t, nil)
	ctx := grpcmetadata.NewIncomingContext(context.Background(), md)

	_, handled, err := resolveLooseOrBypassIdentity(ctx, selfModeMethod, bypass)
	require.Error(t, err, "REGRESSION (identity-assertion-gaps finding 1): a policy-constrained direct-dial "+
		"peer must not be able to sidestep its method policy by calling a Self/Unauthenticated-mode RPC")
	assert.False(t, handled)
	assert.True(t, errors.Is(err, denyErr) || err.Error() == denyErr.Error())
}

// TestResolveLooseOrBypassIdentity_FallsThroughToLooseModeForNonDirectDialPeer
// confirms the legitimate path is preserved: when the caller is NOT a
// recognised direct-dial SPIFFE peer at all (e.g. Envoy, forwarding a
// browser-path sign-in bootstrap call), the bypass reports
// (ctx, false, nil) and the request correctly falls through to loose mode.
func TestResolveLooseOrBypassIdentity_FallsThroughToLooseModeForNonDirectDialPeer(t *testing.T) {
	bypass := func(ctx context.Context, _ string) (context.Context, bool, error) {
		return ctx, false, nil // not a recognised direct-dial peer
	}

	md := mdWithIdentity(t, nil)
	ctx := grpcmetadata.NewIncomingContext(context.Background(), md)

	newCtx, handled, err := resolveLooseOrBypassIdentity(ctx, selfModeMethod, bypass)
	require.NoError(t, err)
	require.True(t, handled)

	id, err := auth.IdentityFromContext(newCtx)
	require.NoError(t, err)
	assert.Equal(t, "user-123", id.Subject)
}

// TestResolveLooseOrBypassIdentity_LooseModeValidationFailurePropagates
// covers the third branch inside resolveLooseOrBypassIdentity: the peer is
// not a recognised direct-dial SPIFFE peer (bypass falls through), the
// method IS registry-classified loose-mode, but the loose-mode identity
// itself fails validation (here: a stale issued-at header). The resulting
// error must propagate up as the RPC's rejection, not be swallowed or
// treated as "not handled" (which would incorrectly fall through to the
// strict sdk/auth interceptor and produce a different, less specific
// error).
func TestResolveLooseOrBypassIdentity_LooseModeValidationFailurePropagates(t *testing.T) {
	bypass := func(ctx context.Context, _ string) (context.Context, bool, error) {
		return ctx, false, nil // not a recognised direct-dial peer
	}

	stale := time.Now().Add(-10 * time.Minute)
	md := mdWithIdentity(t, map[string]string{auth.HeaderIssuedAt: unixSeconds(stale)})
	ctx := grpcmetadata.NewIncomingContext(context.Background(), md)

	_, handled, err := resolveLooseOrBypassIdentity(ctx, selfModeMethod, bypass)
	require.Error(t, err, "a loose-mode identity that fails validation must reject the RPC")
	assert.False(t, handled)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// TestResolveLooseOrBypassIdentity_FallsThroughToStrictForNonLooseMethod
// confirms a method with no registry entry (or a strict, tenant-scoped
// entry) is left entirely alone — resolveLooseOrBypassIdentity reports
// handled=false so the caller runs the strict sdk/auth interceptor.
func TestResolveLooseOrBypassIdentity_FallsThroughToStrictForNonLooseMethod(t *testing.T) {
	bypass := func(ctx context.Context, _ string) (context.Context, bool, error) {
		return ctx, false, nil
	}

	ctx := context.Background()
	_, handled, err := resolveLooseOrBypassIdentity(ctx, "/gibson.daemon.v1.DaemonService/GetTarget", bypass)
	require.NoError(t, err)
	assert.False(t, handled)
}

// TestResolveLooseOrBypassIdentity_BypassGrantWins confirms the third branch:
// a recognised direct-dial peer whose method policy DOES authorise the call
// is served via the bypass identity, without ever consulting loose mode.
func TestResolveLooseOrBypassIdentity_BypassGrantWins(t *testing.T) {
	bypassCalled := false
	bypass := func(ctx context.Context, _ string) (context.Context, bool, error) {
		bypassCalled = true
		return auth.WithIdentity(ctx, auth.Identity{Subject: "spiffe://zeroroot.ai/platform/tenant-operator"}), true, nil
	}

	// Intentionally no metadata on ctx — if this fell through to loose mode
	// it would fail; it must not.
	ctx := context.Background()
	newCtx, handled, err := resolveLooseOrBypassIdentity(ctx, "/gibson.daemon.operator.v1.DaemonOperatorService/WriteAccessTuples", bypass)
	require.NoError(t, err)
	require.True(t, handled)
	assert.True(t, bypassCalled)

	id, err := auth.IdentityFromContext(newCtx)
	require.NoError(t, err)
	assert.Equal(t, "spiffe://zeroroot.ai/platform/tenant-operator", id.Subject)
}
