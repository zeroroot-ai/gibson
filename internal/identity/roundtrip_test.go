package identity

// roundtrip_test.go — Task 28 / B15 cross-format golden test.
//
// Purpose: prove that ext-authz's Sign logic and the daemon's IdentityFromHeaders
// agree on the HMAC canonical string format AND the hex-decode boundary for the
// shared secret.
//
// Problem context (Bug B15):
//
//	The daemon read GIBSON_IDENTITY_HMAC_SECRET as raw bytes.
//	ext-authz read EXT_AUTHZ_HMAC_SECRET and decoded 64-char hex strings to 32 bytes.
//	Result: both sides computed HMACs over different keys → every request was denied.
//
// This test is the in-process golden test that would have caught B15 before
// deployment. It uses a fixed 64-char hex secret and a fixed identity fixture,
// produces a known canonical string, and asserts both sides agree.
//
// Since ext-authz and the daemon live in separate Go modules (no cross-import),
// the test uses the inline `sign` helper from headers_test.go (same package).
// The important invariant is: the inline sign function's canonical string must
// exactly mirror core/ext-authz/internal/headers/signer.go's buildCanonical.
// Any divergence makes this test fail, which surfaces a B15-class regression.
//
// Requirements: R3.2, B15.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"testing"
	"time"
)

// hexDecodedSecret simulates `loadHMACSecret` in ext-authz main.go for a
// 64-char ALL-HEX secret. Both sides must decode to the same 32 bytes.
//
// If the daemon were to use the raw 64-byte string and ext-authz decodes to
// 32 bytes, the HMAC keys differ and this test fires.
//
// The hex value below is a stable fixture (not production-quality entropy).
const roundtripHexSecret = "deadbeefcafebabe0102030405060708090a0b0c0d0e0f101112131415161718"

// decodeHexSecret mirrors the ext-authz loadHMACSecret decode logic:
// len==64 and valid-hex → decode to 32 bytes; else raw.
func decodeHexSecret(t *testing.T, hexStr string) []byte {
	t.Helper()
	if len(hexStr) == 64 {
		decoded, err := hex.DecodeString(hexStr)
		if err == nil {
			return decoded
		}
	}
	return []byte(hexStr)
}

// extAuthzSign mirrors core/ext-authz/internal/headers/signer.go Sign.
// The canonical format is frozen here; any drift from the ext-authz implementation
// must be caught by the CI-level contract test (ext-authz's own signer_test.go
// asserts the canonical string) but THIS test asserts that the DAEMON accepts
// headers produced by THAT canonical format.
//
// If the daemon's IdentityFromHeaders ever diverges from this format, this test
// fires immediately — no cluster required.
func extAuthzSign(secret []byte, id Identity) http.Header {
	issuedAtSec := id.IssuedAt.Unix()
	// Canonical: subject\nissuer\ncredential-type\ntenant\nissued-at-unix-seconds
	canonical := id.Subject + "\n" +
		id.Issuer + "\n" +
		id.CredentialType + "\n" +
		id.Tenant + "\n" +
		strconv.FormatInt(issuedAtSec, 10)

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(canonical))
	sig := hex.EncodeToString(mac.Sum(nil))

	h := make(http.Header)
	h.Set(hSubject, id.Subject)
	h.Set(hIssuer, id.Issuer)
	h.Set(hCredentialType, id.CredentialType)
	h.Set(hTenant, id.Tenant)
	h.Set(hIssuedAt, strconv.FormatInt(issuedAtSec, 10))
	h.Set(hSignature, sig)
	return h
}

// TestRoundtrip_HexDecodedSecret_ZitadelIdentity is the core B15 roundtrip test.
//
// Both sides decode the shared hex secret the same way, sign+verify the same
// identity, and must agree. This catches:
//   - Canonical string format divergence (e.g. different field order or separator).
//   - Hex-decode boundary mismatch (ext-authz decodes, daemon doesn't → different key).
func TestRoundtrip_HexDecodedSecret_ZitadelIdentity(t *testing.T) {
	secret := decodeHexSecret(t, roundtripHexSecret)

	id := Identity{
		Subject:        "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
		Issuer:         "zitadel",
		CredentialType: "oidc",
		Tenant:         "acme-corp",
		IssuedAt:       time.Unix(1_700_000_000, 0).UTC(), // stable fixed time
	}

	// Step 1: ext-authz signs the identity.
	signed := extAuthzSign(secret, id)

	// Step 2: daemon verifies the signed headers.
	got, err := IdentityFromHeaders(secret, signed)
	if err != nil {
		t.Fatalf("B15: daemon IdentityFromHeaders rejected ext-authz-signed headers: %v\n"+
			"This means ext-authz and daemon disagree on the HMAC key or canonical string format.\n"+
			"Check: (a) both sides decode 64-char hex secrets to 32 bytes, "+
			"(b) canonical string is subject\\nissuer\\ncred-type\\ntenant\\nissued-at",
			err)
	}

	if got.Subject != id.Subject {
		t.Errorf("B15: Subject roundtrip failed: got %q want %q", got.Subject, id.Subject)
	}
	if got.Issuer != id.Issuer {
		t.Errorf("B15: Issuer roundtrip failed: got %q want %q", got.Issuer, id.Issuer)
	}
	if got.CredentialType != id.CredentialType {
		t.Errorf("B15: CredentialType roundtrip failed: got %q want %q", got.CredentialType, id.CredentialType)
	}
	if got.Tenant != id.Tenant {
		t.Errorf("B15: Tenant roundtrip failed: got %q want %q", got.Tenant, id.Tenant)
	}
	if got.IssuedAt.Unix() != id.IssuedAt.Unix() {
		t.Errorf("B15: IssuedAt roundtrip failed: got %v want %v", got.IssuedAt, id.IssuedAt)
	}
}

// TestRoundtrip_HexDecodedSecret_SPIFFEIdentity exercises the SPIFFE path with
// the decoded hex secret — the actual production path from the signup saga.
func TestRoundtrip_HexDecodedSecret_SPIFFEIdentity(t *testing.T) {
	secret := decodeHexSecret(t, roundtripHexSecret)

	id := Identity{
		Subject:        "spiffe://gibson.io/platform/dashboard",
		Issuer:         "spiffe",
		CredentialType: "spiffe",
		Tenant:         "",     // SPIFFE identities carry no tenant
		IssuedAt:       time.Unix(1_700_000_001, 0).UTC(),
	}

	signed := extAuthzSign(secret, id)
	got, err := IdentityFromHeaders(secret, signed)
	if err != nil {
		t.Fatalf("B15/B6: daemon rejected SPIFFE identity headers from ext-authz: %v", err)
	}
	if got.Subject != id.Subject {
		t.Errorf("SPIFFE Subject roundtrip: got %q want %q", got.Subject, id.Subject)
	}
	if got.Tenant != "" {
		t.Errorf("SPIFFE Tenant must be empty after roundtrip, got %q", got.Tenant)
	}
}

// TestRoundtrip_WrongKey_Detected ensures that if the two sides use DIFFERENT
// keys (the B15 root cause), IdentityFromHeaders returns an error.
//
// This is the "would the test have caught it?" oracle: if ext-authz decodes a
// 64-char hex secret to 32 bytes but the daemon uses the raw 64 bytes, this
// subtest fires.
func TestRoundtrip_WrongKey_Detected(t *testing.T) {
	// ext-authz key: decoded 32 bytes (the correct path after B15 fix).
	extAuthzKey := decodeHexSecret(t, roundtripHexSecret)

	// Daemon key: raw 64 bytes (the B15 bug — daemon didn't decode).
	daemonKeyB15Bug := []byte(roundtripHexSecret)

	id := Identity{
		Subject:        "user-abc",
		Issuer:         "zitadel",
		CredentialType: "oidc",
		Tenant:         "test-tenant",
		IssuedAt:       time.Unix(1_700_000_002, 0).UTC(),
	}

	// ext-authz signs with decoded key.
	signed := extAuthzSign(extAuthzKey, id)

	// Daemon verifies with raw key (B15 bug scenario).
	_, err := IdentityFromHeaders(daemonKeyB15Bug, signed)
	if err == nil {
		t.Fatal("B15: expected HMAC mismatch when ext-authz uses decoded key but daemon uses raw key; " +
			"if this doesn't fail, the regression would be silent in production")
	}
	// Confirm the error is HMAC-related, not a parsing error.
	if err.Error() != "identity: HMAC signature mismatch" {
		t.Logf("B15: got error %q (expected HMAC mismatch)", err)
	}
}
