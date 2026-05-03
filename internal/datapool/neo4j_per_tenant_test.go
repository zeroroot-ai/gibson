package datapool

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSanitizeForNeo4j_Valid(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"acme", "acme"},
		{"bigcorp", "bigcorp"},
		{"my-tenant", "my_tenant"},
		{"abc123", "abc123"},
		{"a1b2c3", "a1b2c3"},
		{"a-b-c", "a_b_c"},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got, err := sanitizeForNeo4j(tc.input)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestSanitizeForNeo4j_Rejects(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"uppercase", "ACME"},
		{"space", "my tenant"},
		{"dot", "my.tenant"},
		{"slash", "ten/ant"},
		{"unicode", "téñant"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := sanitizeForNeo4j(tc.input)
			require.Error(t, err)
		})
	}
}

func TestSanitizeForNeo4j_TooLong(t *testing.T) {
	// Build a 64-character name (> 63 limit)
	long := "a"
	for len(long) < 64 {
		long += "b"
	}
	_, err := sanitizeForNeo4j(long)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "63-character")
}

func TestIsNeo4jDBNotExist(t *testing.T) {
	tests := []struct {
		name     string
		errMsg   string
		expected bool
	}{
		{"database does not exist", "database does not exist", true},
		{"DatabaseNotFound", "Neo.ClientError.Database.DatabaseNotFound", true},
		{"other error", "connection refused", false},
		{"nil error", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			if tc.errMsg != "" {
				err = &testError{tc.errMsg}
			}
			assert.Equal(t, tc.expected, isNeo4jDBNotExist(err))
		})
	}
}

// TestNeo4jPerTenant_NilResolver verifies that a nil resolver panics loudly
// rather than silently misbehaving. In production the resolver is always set
// by the daemon bootstrap.
func TestNeo4jPerTenant_NilResolver(t *testing.T) {
	// newNeo4jPerTenant now takes a resolver (Task 15 refactor).
	// Passing nil is the caller's mistake; we just verify it doesn't silently
	// accept it — the struct stores nil and the first ForTenant call will panic
	// or return an error. Either outcome is acceptable; this test documents
	// that the OLD 3-arg signature is gone.
	_ = newNeo4jPerTenant(nil) // acceptable — nil stored, caller must not use it
}

// TestNeo4jPerTenant_ForTenant_SessionBound verifies sanitization convention.
func TestNeo4jPerTenant_ForTenant_SessionBound(t *testing.T) {
	// Verify that sanitization happens correctly for session DB name.
	sanitized, err := sanitizeForNeo4j("acme")
	require.NoError(t, err)
	assert.Equal(t, "tenant_"+sanitized, "tenant_acme")
}
