// Package brokercodec tests — codec round-trip guards.
//
// These mirror operators/tenant/internal/saga/flows/write_broker_config_test.go
// in intent: they assert the wire CandidateConfig round-trips to a valid
// vault.Config with the auth method + namespace/path-prefix intact — the exact
// field-name drift (H2, gibson#1105 / tenant-operator#144) that left BYO Vault
// deserialising with an empty auth block.
package brokercodec

import (
	"bytes"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/infra/secrets/vault"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

func mustTenant(t *testing.T, s string) auth.TenantID {
	t.Helper()
	id, err := auth.NewTenantID(s)
	if err != nil {
		t.Fatalf("NewTenantID(%q): %v", s, err)
	}
	return id
}

// TestEncodeCandidate_Hosted_RoundTrip verifies a Hosted candidate maps to
// namespace mode with the nested auth block intact.
func TestEncodeCandidate_Hosted_RoundTrip(t *testing.T) {
	tenant := mustTenant(t, "acme")
	provider, blob, err := EncodeCandidate(&tenantv1.CandidateConfig{
		Provider:        tenantv1.BrokerProvider_BROKER_PROVIDER_VAULT_HOSTED,
		Address:         "https://vault.internal:8200",
		NamespaceOrPath: "tenant/acme",
		Mount:           "secret",
		AuthMethod:      "token",
		VaultToken:      []byte("hvs.rootish"),
	}, tenant)
	if err != nil {
		t.Fatalf("EncodeCandidate: %v", err)
	}
	if provider != ProviderName {
		t.Errorf("provider = %q, want %q", provider, ProviderName)
	}

	cfg, err := Decode(blob)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if cfg.Namespace != "tenant/acme" {
		t.Errorf("Namespace = %q, want tenant/acme (namespace mode)", cfg.Namespace)
	}
	if cfg.PathPrefix != "" {
		t.Errorf("PathPrefix = %q, want empty in namespace mode", cfg.PathPrefix)
	}
	if cfg.Address != "https://vault.internal:8200" {
		t.Errorf("Address = %q", cfg.Address)
	}
	if cfg.KVMount != "secret" {
		t.Errorf("KVMount = %q", cfg.KVMount)
	}
	// The exact H2 assertion: auth method + token survive into the NESTED
	// auth object (not dropped as flat keys the provider ignores).
	if cfg.Auth.Method != vault.AuthMethodToken {
		t.Errorf("Auth.Method = %q, want token", cfg.Auth.Method)
	}
	if cfg.Auth.Token != "hvs.rootish" {
		t.Errorf("Auth.Token = %q, want it to survive the round-trip", cfg.Auth.Token)
	}
}

// TestEncodeCandidate_BYO_RoundTrip verifies a BYO candidate maps to
// path-prefix mode with AppRole auth intact.
func TestEncodeCandidate_BYO_RoundTrip(t *testing.T) {
	tenant := mustTenant(t, "acme")
	_, blob, err := EncodeCandidate(&tenantv1.CandidateConfig{
		Provider:        tenantv1.BrokerProvider_BROKER_PROVIDER_VAULT_BYO,
		Address:         "https://byo.example:8200",
		NamespaceOrPath: "team/acme-secrets",
		Mount:           "kv",
		AuthMethod:      "approle",
		ApproleRoleId:   "role-123",
		ApproleSecretId: []byte("secret-456"),
	}, tenant)
	if err != nil {
		t.Fatalf("EncodeCandidate: %v", err)
	}

	cfg, err := Decode(blob)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if cfg.Namespace != "" {
		t.Errorf("Namespace = %q, want empty in path-prefix mode", cfg.Namespace)
	}
	if cfg.PathPrefix != "team/acme-secrets" {
		t.Errorf("PathPrefix = %q, want the supplied path", cfg.PathPrefix)
	}
	if cfg.Auth.Method != vault.AuthMethodAppRole {
		t.Errorf("Auth.Method = %q, want approle", cfg.Auth.Method)
	}
	if cfg.Auth.AppRoleID != "role-123" {
		t.Errorf("Auth.AppRoleID = %q", cfg.Auth.AppRoleID)
	}
	if cfg.Auth.AppRoleSecretID != "secret-456" {
		t.Errorf("Auth.AppRoleSecretID = %q, want it to survive", cfg.Auth.AppRoleSecretID)
	}
}

// TestEncodeCandidate_BYO_DefaultPathPrefix verifies BYO with no supplied
// path defaults to the tenant-scoped prefix tenant/<tenant-id>.
func TestEncodeCandidate_BYO_DefaultPathPrefix(t *testing.T) {
	tenant := mustTenant(t, "wonka")
	_, blob, err := EncodeCandidate(&tenantv1.CandidateConfig{
		Provider:   tenantv1.BrokerProvider_BROKER_PROVIDER_VAULT_BYO,
		Address:    "https://byo.example:8200",
		AuthMethod: "token",
		VaultToken: []byte("hvs.byo"),
	}, tenant)
	if err != nil {
		t.Fatalf("EncodeCandidate: %v", err)
	}
	cfg, err := Decode(blob)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if want := "tenant/wonka"; cfg.PathPrefix != want {
		t.Errorf("PathPrefix = %q, want default %q", cfg.PathPrefix, want)
	}
	if cfg.Namespace != "" {
		t.Errorf("Namespace = %q, want empty (path-prefix mode)", cfg.Namespace)
	}
}

// TestEncodeCandidate_UnsupportedProvider rejects UNSPECIFIED / retired enums.
func TestEncodeCandidate_UnsupportedProvider(t *testing.T) {
	tenant := mustTenant(t, "acme")
	if _, _, err := EncodeCandidate(&tenantv1.CandidateConfig{
		Provider: tenantv1.BrokerProvider_BROKER_PROVIDER_UNSPECIFIED,
	}, tenant); err == nil {
		t.Fatal("expected error for UNSPECIFIED provider, got nil")
	}
	if _, _, err := EncodeCandidate(nil, tenant); err == nil {
		t.Fatal("expected error for nil candidate, got nil")
	}
}

// TestSingleSourceOfTruth_DaemonAndOperatorAgree is the single-source-of-truth
// guard: the daemon path (EncodeCandidate) and the operator path (Encode of the
// equivalent Fields) MUST produce byte-identical blobs for the same logical
// config, so writer/reader shapes can never drift again (PRD gibson#1105 M2).
func TestSingleSourceOfTruth_DaemonAndOperatorAgree(t *testing.T) {
	tenant := mustTenant(t, "acme")

	// Daemon path: a dashboard-shaped Hosted candidate.
	_, daemonBlob, err := EncodeCandidate(&tenantv1.CandidateConfig{
		Provider:        tenantv1.BrokerProvider_BROKER_PROVIDER_VAULT_HOSTED,
		Address:         "https://vault.internal:8200",
		NamespaceOrPath: "tenant/acme",
		Mount:           "secret",
		AuthMethod:      "token",
		VaultToken:      []byte("hvs.same"),
	}, tenant)
	if err != nil {
		t.Fatalf("EncodeCandidate: %v", err)
	}

	// Operator path: the same logical config expressed as Fields.
	_, operatorBlob, err := Encode(Fields{
		Hosted:          true,
		Address:         "https://vault.internal:8200",
		NamespaceOrPath: "tenant/acme",
		KVMount:         "secret",
		Auth: vault.AuthConfig{
			Method: vault.AuthMethodToken,
			Token:  "hvs.same",
		},
		Tenant: tenant,
	})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	if !bytes.Equal(daemonBlob, operatorBlob) {
		t.Errorf("daemon and operator blobs differ (single-source-of-truth violated):\n daemon=  %s\n operator=%s",
			daemonBlob, operatorBlob)
	}
}

// TestRedact_Hosted verifies the redacted view of a Hosted blob: provider,
// namespace, auth method, and the presence (not value) of sensitive fields.
func TestRedact_Hosted(t *testing.T) {
	blob := []byte(`{"address":"https://vault","namespace":"tenant/acme","kv_mount":"secret","auth":{"method":"token","token":"hvs.secret"}}`)
	out, err := Redact(blob)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if out.GetProvider() != tenantv1.BrokerProvider_BROKER_PROVIDER_VAULT_HOSTED {
		t.Errorf("Provider = %v, want VAULT_HOSTED", out.GetProvider())
	}
	if out.GetNamespaceOrPath() != "tenant/acme" {
		t.Errorf("NamespaceOrPath = %q", out.GetNamespaceOrPath())
	}
	if out.GetAuthMethod() != "token" {
		t.Errorf("AuthMethod = %q", out.GetAuthMethod())
	}
	// SECURITY: the token value must never surface anywhere in the redacted
	// message — only its presence is reported.
	found := false
	for _, k := range out.GetSensitiveFieldsSet() {
		if k == sensitiveVaultToken {
			found = true
		}
	}
	if !found {
		t.Errorf("expected %q in sensitive_fields_set, got %v", sensitiveVaultToken, out.GetSensitiveFieldsSet())
	}
}

// TestRedact_BYO verifies a path_prefix blob redacts as BYO with the path
// surfaced as namespace_or_path and AppRole secret flagged sensitive.
func TestRedact_BYO(t *testing.T) {
	blob := []byte(`{"address":"https://byo","path_prefix":"tenant/acme","auth":{"method":"approle","app_role_id":"r","app_role_secret_id":"s"}}`)
	out, err := Redact(blob)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if out.GetProvider() != tenantv1.BrokerProvider_BROKER_PROVIDER_VAULT_BYO {
		t.Errorf("Provider = %v, want VAULT_BYO", out.GetProvider())
	}
	if out.GetNamespaceOrPath() != "tenant/acme" {
		t.Errorf("NamespaceOrPath = %q, want the path prefix", out.GetNamespaceOrPath())
	}
	found := false
	for _, k := range out.GetSensitiveFieldsSet() {
		if k == sensitiveAppRoleSecretID {
			found = true
		}
	}
	if !found {
		t.Errorf("expected %q in sensitive_fields_set, got %v", sensitiveAppRoleSecretID, out.GetSensitiveFieldsSet())
	}
}

// TestRedact_EmptyBlob treats an empty blob as an empty (Hosted) config
// rather than an error, so "no row" and "empty row" behave uniformly.
func TestRedact_EmptyBlob(t *testing.T) {
	out, err := Redact(nil)
	if err != nil {
		t.Fatalf("Redact(nil): %v", err)
	}
	if out.GetProvider() != tenantv1.BrokerProvider_BROKER_PROVIDER_VAULT_HOSTED {
		t.Errorf("empty blob Provider = %v, want VAULT_HOSTED default", out.GetProvider())
	}
}
