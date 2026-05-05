package datapool

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
