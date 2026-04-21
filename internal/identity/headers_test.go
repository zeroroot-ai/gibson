package identity

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"testing"
	"time"
)

// sign mirrors the task-4 ext-authz signer exactly (canonical format must be identical).
func sign(secret []byte, id Identity) http.Header {
	issuedAtSec := id.IssuedAt.Unix()
	canonical := id.Subject + "\n" + id.Issuer + "\n" + id.CredentialType + "\n" + id.Tenant + "\n" + strconv.FormatInt(issuedAtSec, 10)
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

var (
	testSecret = []byte("test-hmac-secret")
	testID     = Identity{
		Subject:        "user:abc123",
		Issuer:         "zitadel",
		CredentialType: "oidc",
		Tenant:         "acme",
		IssuedAt:       time.Unix(1_700_000_000, 0).UTC(),
	}
)

func TestIdentityFromHeaders_HappyPath(t *testing.T) {
	h := sign(testSecret, testID)
	got, err := IdentityFromHeaders(testSecret, h)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Subject != testID.Subject {
		t.Errorf("Subject: got %q want %q", got.Subject, testID.Subject)
	}
	if got.Issuer != testID.Issuer {
		t.Errorf("Issuer: got %q want %q", got.Issuer, testID.Issuer)
	}
	if got.CredentialType != testID.CredentialType {
		t.Errorf("CredentialType: got %q want %q", got.CredentialType, testID.CredentialType)
	}
	if got.Tenant != testID.Tenant {
		t.Errorf("Tenant: got %q want %q", got.Tenant, testID.Tenant)
	}
	if !got.IssuedAt.Equal(testID.IssuedAt) {
		t.Errorf("IssuedAt: got %v want %v", got.IssuedAt, testID.IssuedAt)
	}
}

func TestIdentityFromHeaders_NonZitadelEmptyTenant(t *testing.T) {
	id := Identity{
		Subject:        "spiffe://cluster.local/ns/default/sa/agent",
		Issuer:         "spire",
		CredentialType: "mtls",
		Tenant:         "",
		IssuedAt:       time.Unix(1_700_000_000, 0).UTC(),
	}
	h := sign(testSecret, id)
	got, err := IdentityFromHeaders(testSecret, h)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Tenant != "" {
		t.Errorf("expected empty tenant, got %q", got.Tenant)
	}
}

func TestIdentityFromHeaders_MissingHeaders(t *testing.T) {
	missingCases := []struct {
		name   string
		remove string
	}{
		{"missing subject", hSubject},
		{"missing issuer", hIssuer},
		{"missing credential-type", hCredentialType},
		{"missing issued-at", hIssuedAt},
		{"missing signature", hSignature},
	}
	for _, tc := range missingCases {
		t.Run(tc.name, func(t *testing.T) {
			h := sign(testSecret, testID)
			h.Del(tc.remove)
			_, err := IdentityFromHeaders(testSecret, h)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestIdentityFromHeaders_TamperedFields(t *testing.T) {
	tamperCases := []struct {
		name   string
		header string
		value  string
	}{
		{"tamper subject", hSubject, "user:EVIL"},
		{"tamper issuer", hIssuer, "evil-issuer"},
		{"tamper credential-type", hCredentialType, "evil-type"},
		{"tamper tenant", hTenant, "evil-tenant"},
		{"tamper issued-at", hIssuedAt, "0"},
		{"tamper signature", hSignature, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	}
	for _, tc := range tamperCases {
		t.Run(tc.name, func(t *testing.T) {
			h := sign(testSecret, testID)
			h.Set(tc.header, tc.value)
			_, err := IdentityFromHeaders(testSecret, h)
			if err == nil {
				t.Error("expected error after tampering, got nil")
			}
		})
	}
}

func TestIdentityFromHeaders_WrongSecret(t *testing.T) {
	h := sign(testSecret, testID)
	_, err := IdentityFromHeaders([]byte("wrong-secret"), h)
	if err == nil {
		t.Error("expected HMAC error with wrong secret")
	}
}

func TestIdentityFromHeaders_MalformedIssuedAt(t *testing.T) {
	h := sign(testSecret, testID)
	// Replace issued-at with non-numeric value and recompute signature so the
	// parse failure is hit before the HMAC check can short-circuit.
	// Actually we want to test the parse path — just set a non-numeric value.
	h.Set(hIssuedAt, "not-a-number")
	_, err := IdentityFromHeaders(testSecret, h)
	if err == nil {
		t.Error("expected parse error for malformed issued-at")
	}
}

func TestIdentityFromHeaders_ZitadelRequiresTenant(t *testing.T) {
	id := Identity{
		Subject:        "user:abc",
		Issuer:         "zitadel",
		CredentialType: "oidc",
		Tenant:         "",
		IssuedAt:       time.Unix(1_700_000_000, 0).UTC(),
	}
	h := sign(testSecret, id)
	_, err := IdentityFromHeaders(testSecret, h)
	if err == nil {
		t.Error("expected error: zitadel issuer with empty tenant")
	}
}

func TestWithIdentity_RoundTrip(t *testing.T) {
	ctx := WithIdentity(t.Context(), testID)
	got, err := IdentityFromContext(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Subject != testID.Subject {
		t.Errorf("Subject: got %q want %q", got.Subject, testID.Subject)
	}
}

func TestIdentityFromContext_Missing(t *testing.T) {
	_, err := IdentityFromContext(t.Context())
	if err == nil {
		t.Error("expected error when identity not in context")
	}
}
