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

func TestDerivePostgresPassword_Length(t *testing.T) {
	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(i)
	}
	pw, err := derivePostgresPassword(kek)
	require.NoError(t, err)
	// hex of first 16 bytes = 32 hex chars
	assert.Len(t, pw, 32)
	assert.Equal(t, "000102030405060708090a0b0c0d0e0f", pw)
}

func TestDerivePostgresPassword_TooShortKEK(t *testing.T) {
	_, err := derivePostgresPassword([]byte{0x01, 0x02})
	require.Error(t, err)
}

func TestDerivePostgresPassword_Determinism(t *testing.T) {
	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = 0xAB
	}
	pw1, err := derivePostgresPassword(kek)
	require.NoError(t, err)
	pw2, err := derivePostgresPassword(kek)
	require.NoError(t, err)
	assert.Equal(t, pw1, pw2)
}

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
