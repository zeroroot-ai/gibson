package datapool

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zero-day-ai/sdk/auth"
)

func TestSanitizeForPostgres_Valid(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"acme", "acme"},
		{"bigcorp", "bigcorp"},
		{"tenant1", "tenant1"},
		{"my-tenant", "my_tenant"}, // hyphens → underscores
		{"a-b-c", "a_b_c"},         // multiple hyphens
		{"abc123", "abc123"},
		{"a1b2c3", "a1b2c3"},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got, err := sanitizeForPostgres(tc.input)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestSanitizeForPostgres_Rejects(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"uppercase", "ACME"},
		{"space", "my tenant"},
		{"semicolon", "tenant;drop"},
		{"singlequote", "tenant'drop"},
		{"slash", "tenant/drop"},
		{"dot", "tenant.corp"},
		{"unicode", "tenanté"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := sanitizeForPostgres(tc.input)
			require.Error(t, err)
		})
	}
}

// TestDerivePostgresPassword_* removed in spec
// tenant-provisioning-unification-phase2 Phase 6.2 — daemon no longer
// derives the Postgres password locally; the DSN comes from Vault via
// the broker. Equivalent KEK-derivation tests live in
// gibson/pkg/platform/tenant/kek_test.go (used by the operator side).

func TestIsPostgresDBNotExist(t *testing.T) {
	tests := []struct {
		name     string
		errMsg   string
		dbName   string
		expected bool
	}{
		{"sqlstate 3D000", `pq: FATAL: database "tenant_acme" does not exist (SQLSTATE 3D000)`, "tenant_acme", true},
		{"message match", `database "tenant_acme" does not exist`, "tenant_acme", true},
		{"other error", "connection refused", "tenant_acme", false},
		{"nil", "", "tenant_acme", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			if tc.errMsg != "" {
				err = &testError{tc.errMsg}
			}
			got := isPostgresDBNotExist(err, tc.dbName)
			assert.Equal(t, tc.expected, got)
		})
	}
}

// testError is a simple error type for table-driven tests.
type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }

// ---------------------------------------------------------------------------
// resolveDSN contract (gibson#106)
//
// The datapool layer no longer knows about the secrets broker. It calls
// the constructor-injected PostgresDSNResolver to obtain a DSN. These
// tests pin that contract — including the "absent resolver returns a
// NotProvisionedError immediately, no recursion, no timeout" property
// that motivated the layer split.
// ---------------------------------------------------------------------------

// fakeDSNResolver counts calls and returns the canned response.
type fakeDSNResolver struct {
	calls atomic.Int32
	dsn   string
	db    string
	err   error
}

func (f *fakeDSNResolver) ResolveDSN(_ context.Context, _ auth.TenantID) (string, string, error) {
	f.calls.Add(1)
	return f.dsn, f.db, f.err
}

func TestResolveDSN_NoResolverWired_ReturnsNotProvisioned(t *testing.T) {
	// gibson#106: when no resolver is wired, ForTenant must surface a
	// *NotProvisionedError immediately so callers (the secrets broker
	// chain, in particular) never enter a retry-loop. The pre-#105
	// failure mode was a 60-second gRPC timeout; this test pins the
	// fast-fail contract at the datapool layer itself, independent of
	// the registry-level fast-fail added in gibson#105.
	p := newPgPerTenant(Config{})
	tenant := auth.MustNewTenantID("acme")

	_, _, err := p.resolveDSN(context.Background(), tenant, nil)

	var notProv *NotProvisionedError
	require.ErrorAs(t, err, &notProv)
	assert.Equal(t, "acme", notProv.Tenant)
	assert.Contains(t, notProv.Reason, "PostgresDSNResolver not wired")
}

func TestResolveDSN_DelegatesToResolver(t *testing.T) {
	// Happy path: resolver returns a DSN, resolveDSN appends pool sizing
	// and propagates the database name unchanged.
	resolver := &fakeDSNResolver{
		dsn: "postgres://u:p@h:5432/tenant_acme?sslmode=disable",
		db:  "tenant_acme",
	}
	p := newPgPerTenant(Config{
		PostgresDSNResolver: resolver,
		PoolMaxConns:        7,
	})
	tenant := auth.MustNewTenantID("acme")

	dsn, db, err := p.resolveDSN(context.Background(), tenant, nil)
	require.NoError(t, err)
	assert.Equal(t, int32(1), resolver.calls.Load(), "resolver must be called exactly once")
	assert.Equal(t, "tenant_acme", db)
	// pool_max_conns is appended as a query param, not baked in by the resolver.
	assert.Contains(t, dsn, "pool_max_conns=7")
	assert.True(t, strings.HasPrefix(dsn, resolver.dsn), "raw resolver DSN must be the prefix; got %q", dsn)
}

func TestResolveDSN_DSNWithoutQuery_GetsQuestionMarkSeparator(t *testing.T) {
	// When the resolver returns a DSN with no ?-query, the pool appends
	// the sizing param with `?`, not `&`.
	resolver := &fakeDSNResolver{
		dsn: "postgres://u:p@h:5432/tenant_acme",
		db:  "tenant_acme",
	}
	p := newPgPerTenant(Config{
		PostgresDSNResolver: resolver,
		PoolMaxConns:        3,
	})
	tenant := auth.MustNewTenantID("acme")

	dsn, _, err := p.resolveDSN(context.Background(), tenant, nil)
	require.NoError(t, err)
	assert.Equal(t, "postgres://u:p@h:5432/tenant_acme?pool_max_conns=3", dsn)
}

func TestResolveDSN_ResolverEmptyDSN_ReturnsNotProvisioned(t *testing.T) {
	resolver := &fakeDSNResolver{dsn: "", db: "tenant_acme"}
	p := newPgPerTenant(Config{PostgresDSNResolver: resolver, PoolMaxConns: 1})

	_, _, err := p.resolveDSN(context.Background(), auth.MustNewTenantID("acme"), nil)

	var notProv *NotProvisionedError
	require.ErrorAs(t, err, &notProv)
	assert.Contains(t, notProv.Reason, "empty DSN")
}

func TestResolveDSN_ResolverNotProvisioned_PropagatesUnwrapped(t *testing.T) {
	// Resolver-side NotProvisionedError must surface unchanged so the
	// daemon's gRPC handler can map it to a fast FailedPrecondition
	// without retry. Wrapping it in another NotProvisionedError would
	// destroy the original Tenant + Reason fields.
	want := &NotProvisionedError{Tenant: "acme", Reason: "vault path absent"}
	resolver := &fakeDSNResolver{err: want}
	p := newPgPerTenant(Config{PostgresDSNResolver: resolver, PoolMaxConns: 1})

	_, _, err := p.resolveDSN(context.Background(), auth.MustNewTenantID("acme"), nil)

	var got *NotProvisionedError
	require.ErrorAs(t, err, &got)
	assert.Same(t, want, got, "NotProvisionedError must surface unwrapped, not re-wrapped")
}

func TestResolveDSN_ResolverGenericError_WrappedAsNotProvisioned(t *testing.T) {
	// Any other resolver error is wrapped as NotProvisionedError — the
	// datapool layer refuses to leak the broker error taxonomy upward.
	// This preserves the existing gRPC NotFound mapping for handlers
	// while still telling SREs what broke.
	resolver := &fakeDSNResolver{err: errors.New("network unreachable")}
	p := newPgPerTenant(Config{PostgresDSNResolver: resolver, PoolMaxConns: 1})

	_, _, err := p.resolveDSN(context.Background(), auth.MustNewTenantID("acme"), nil)

	var notProv *NotProvisionedError
	require.ErrorAs(t, err, &notProv)
	assert.Contains(t, notProv.Reason, "DSN resolver failed")
	assert.Contains(t, notProv.Reason, "network unreachable")
}

// Compile-time proof that PostgresDSNResolverFunc satisfies the interface
// — keeps the daemon's bootstrap closure (which uses the func form) wired
// to the same contract the datapool consumes.
var _ PostgresDSNResolver = PostgresDSNResolverFunc(func(context.Context, auth.TenantID) (string, string, error) {
	return "", "", fmt.Errorf("compile-time placeholder")
})
