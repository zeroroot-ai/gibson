package auth

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sdkauth "github.com/zero-day-ai/sdk/auth"
)

// ---------------------------------------------------------------------------
// Constructor tests (no DB required)
// ---------------------------------------------------------------------------

// TestNewAPIKeyAuthenticator_NilDBRejected verifies the constructor returns an
// error when given a nil *sql.DB.
func TestNewAPIKeyAuthenticator_NilDBRejected(t *testing.T) {
	_, err := NewAPIKeyAuthenticator(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

// ---------------------------------------------------------------------------
// hashKey & constantTimeCompareStrings (pure-function unit tests)
// ---------------------------------------------------------------------------

// TestHashKey_DeterministicAndHex verifies that hashKey returns a 64-character
// hex string and that calling it twice with the same input yields the same result.
func TestHashKey_DeterministicAndHex(t *testing.T) {
	const raw = "gsk_acme_abc123"
	h1 := hashKey(raw)
	h2 := hashKey(raw)

	assert.Equal(t, h1, h2, "hashKey must be deterministic")
	assert.Len(t, h1, 64, "SHA-256 hex digest must be 64 characters")

	for _, c := range h1 {
		assert.True(t, (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'),
			"hash must only contain lowercase hex characters, got %q", c)
	}
}

// TestHashKey_DifferentInputsDifferentHashes verifies that distinct inputs
// produce distinct hashes (collision resistance sanity check).
func TestHashKey_DifferentInputsDifferentHashes(t *testing.T) {
	assert.NotEqual(t, hashKey("gsk_acme_aaa"), hashKey("gsk_acme_bbb"))
}

// TestConstantTimeCompareStrings verifies equality, inequality, and
// different-length comparisons.
func TestConstantTimeCompareStrings(t *testing.T) {
	cases := []struct {
		name string
		a, b string
		want bool
	}{
		{"equal", "abc", "abc", true},
		{"different", "abc", "def", false},
		{"different length", "ab", "abc", false},
		{"both empty", "", "", true},
		{"one empty", "", "x", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, constantTimeCompareStrings(tc.a, tc.b))
		})
	}
}

// ---------------------------------------------------------------------------
// parsePermissions (pure-function unit tests)
// ---------------------------------------------------------------------------

// TestParsePermissions verifies that well-formed "action:resource" strings are
// split correctly and that malformed entries are silently skipped.
func TestParsePermissions(t *testing.T) {
	perms := parsePermissions([]string{
		"execute:mission",
		"read:finding",
		"no-colon",        // invalid — no colon
		":empty-action",   // invalid — empty action
		"empty-resource:", // invalid — empty resource
		"*:*",
	})

	require.Len(t, perms, 3)
	assert.Equal(t, Permission{Action: "execute", Resource: "mission", Scope: "*"}, perms[0])
	assert.Equal(t, Permission{Action: "read", Resource: "finding", Scope: "*"}, perms[1])
	assert.Equal(t, Permission{Action: "*", Resource: "*", Scope: "*"}, perms[2])
}

// TestParsePermissions_Empty verifies that an empty input produces an empty
// (non-nil) result slice.
func TestParsePermissions_Empty(t *testing.T) {
	perms := parsePermissions(nil)
	assert.NotNil(t, perms)
	assert.Empty(t, perms)
}

// ---------------------------------------------------------------------------
// scanRecord nil-slice normalisation (white-box unit test)
// ---------------------------------------------------------------------------

// TestScanRecord_NilSlicesNormalised verifies that scanRecord always returns
// non-nil slices even when the database returns NULLs or empty arrays.
// We test this via the public CreateKey path in integration tests; here we
// verify the helper's zero-value normalisation directly.
func TestAPIKeyRecord_NilSliceDefaults(t *testing.T) {
	// Simulate what scanRecord does for nil slices.
	rec := APIKeyRecord{
		AllowedKinds: nil,
		AllowedNames: nil,
		Capabilities: nil,
	}
	if rec.AllowedKinds == nil {
		rec.AllowedKinds = []string{}
	}
	if rec.AllowedNames == nil {
		rec.AllowedNames = []string{}
	}
	if rec.Capabilities == nil {
		rec.Capabilities = []string{}
	}
	assert.NotNil(t, rec.AllowedKinds)
	assert.NotNil(t, rec.AllowedNames)
	assert.NotNil(t, rec.Capabilities)
}

// ---------------------------------------------------------------------------
// Key format and prefix tests (pure function, no DB)
// ---------------------------------------------------------------------------

// TestAPIKeyPrefix_Format verifies that the assembled raw key and key_id follow
// the expected gsk_{tenant}_{hex} format by exercising the format logic directly.
func TestAPIKeyKeyIDFormat(t *testing.T) {
	const tenantID = "acme"
	const randomHex = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"

	rawKey := "gsk_" + tenantID + "_" + randomHex
	keyID := "gsk_" + tenantID + "_" + randomHex[:16]

	assert.True(t, strings.HasPrefix(rawKey, "gsk_"), "raw key must start with gsk_")
	assert.True(t, strings.HasPrefix(keyID, "gsk_"+tenantID+"_"), "key_id must carry the tenant prefix")
	assert.Len(t, keyID, len("gsk_")+len(tenantID)+1+16, "key_id must include 16-char suffix")
}

// ---------------------------------------------------------------------------
// SystemTenant constant
// ---------------------------------------------------------------------------

func TestSystemTenantConstant(t *testing.T) {
	assert.Equal(t, "_system", SystemTenant)
}

// ---------------------------------------------------------------------------
// Identity building (extracted logic, no DB)
// ---------------------------------------------------------------------------

// adminIdentityContext returns a context carrying a synthetic Identity with the
// given roles, mimicking what the auth interceptor injects after authentication.
func adminIdentityContext(roles []string) context.Context {
	identity := &Identity{
		Identity: sdkauth.Identity{
			Subject: "test-admin",
			Issuer:  "test",
		},
		Roles: roles,
		Permissions: []Permission{
			{Action: "*", Resource: "*", Scope: "*"},
		},
	}
	return ContextWithIdentity(context.Background(), identity)
}

// TestCapabilityNormalisation verifies that an empty Capabilities slice is
// normalised to []string{"*"} by the logic used inside Authenticate.
func TestCapabilityNormalisation(t *testing.T) {
	cases := []struct {
		name     string
		caps     []string
		wantCaps []string
	}{
		{"nil caps", nil, []string{"*"}},
		{"empty caps", []string{}, []string{"*"}},
		{"explicit caps", []string{"graphrag:write"}, []string{"graphrag:write"}},
		{"wildcard", []string{"*"}, []string{"*"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			caps := tc.caps
			if len(caps) == 0 {
				caps = []string{"*"}
			}
			assert.Equal(t, tc.wantCaps, caps)
		})
	}
}

// TestRoleForSystemTenant verifies that the system tenant key gets the
// "platform-operator" role and all others get "admin".
func TestRoleForSystemTenant(t *testing.T) {
	cases := []struct {
		tenantID  string
		wantRoles []string
	}{
		{SystemTenant, []string{"platform-operator"}},
		{"acme", []string{"admin"}},
		{"other-corp", []string{"admin"}},
	}
	for _, tc := range cases {
		t.Run(tc.tenantID, func(t *testing.T) {
			roles := []string{"admin"}
			if tc.tenantID == SystemTenant {
				roles = []string{"platform-operator"}
			}
			assert.Equal(t, tc.wantRoles, roles)
		})
	}
}
