// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package flows

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/infra/secrets/vault/brokercodec"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// TestRenderVaultConfig_SubstitutesTenantID verifies the namespace
// template's {tenant_id} placeholder is replaced with the resolved
// auth.TenantID string form before encryption.
func TestRenderVaultConfig_SubstitutesTenantID(t *testing.T) {
	id, err := auth.NewTenantID("acme")
	if err != nil {
		t.Fatalf("NewTenantID: %v", err)
	}
	rendered := renderVaultConfig(VaultBrokerConfig{
		Address:           "https://vault.example:8200",
		NamespaceTemplate: "tenant/{tenant_id}/secrets",
		KVMount:           "secret",
		Auth: VaultAuthConfig{
			Method: "kubernetes",
			Role:   "gibson-plugin-acme",
		},
		TransitKey: "tenant-kek",
	}, id)
	want := "tenant/acme/secrets"
	if rendered.Namespace != want {
		t.Errorf("Namespace after render: got %q, want %q", rendered.Namespace, want)
	}
	// Non-templated fields pass through unchanged.
	if rendered.Address != "https://vault.example:8200" {
		t.Errorf("Address mutated: got %q", rendered.Address)
	}
	if rendered.Auth.Method != "kubernetes" {
		t.Errorf("Auth.Method mutated: got %q", rendered.Auth.Method)
	}
	if rendered.Auth.Role != "gibson-plugin-acme" {
		t.Errorf("Auth.Role mutated: got %q", rendered.Auth.Role)
	}
}

// TestRenderVaultConfig_MultipleSubstitutions verifies that more than
// one occurrence of the placeholder is replaced (defensive against a
// future template like "tenant/{tenant_id}/secrets/{tenant_id}.json").
func TestRenderVaultConfig_MultipleSubstitutions(t *testing.T) {
	id, _ := auth.NewTenantID("acme")
	rendered := renderVaultConfig(VaultBrokerConfig{
		NamespaceTemplate: "{tenant_id}/inner/{tenant_id}",
	}, id)
	if rendered.Namespace != "acme/inner/acme" {
		t.Errorf("expected two substitutions, got %q", rendered.Namespace)
	}
}

// TestRenderVaultConfig_EmptyTemplatePassthrough verifies that an empty
// NamespaceTemplate (zero value) survives the render unchanged so the
// daemon's default-namespace-rendering path fires instead.
func TestRenderVaultConfig_EmptyTemplatePassthrough(t *testing.T) {
	id, _ := auth.NewTenantID("acme")
	rendered := renderVaultConfig(VaultBrokerConfig{}, id)
	if rendered.Namespace != "" {
		t.Errorf("empty template must produce empty Namespace, got %q", rendered.Namespace)
	}
}

// TestVaultBrokerConfig_RoundTripJSON_MatchesSDKShape verifies that the
// JSON the operator emits deserialises cleanly into the SDK's
// sdkvault.Config shape. This guards against the schema-drift bug from
// tenant-operator#144 — silently divergent writer/reader shapes that
// compile clean but produce empty fields at runtime.
//
// Asserts the contract from sdk#79 (vault Config + AuthConfig json tags):
//   - {"address": ..., "namespace": ..., "kv_mount": ...,
//     "auth": {"method": ..., "role": ...}}
//
// Extended for ADR-0009 / tenant-operator#147: when Auth.Method == "jwt",
// renderVaultConfig auto-templates auth.role to "gibson-plugin-<tenant>"
// so the broker config row carries the role the daemon dials at runtime.
// The operator-internal Audience field must NOT appear in the JSON
// (it surfaces at the Vault role level via bound_audiences, NOT in
// the daemon's broker config).
func TestVaultBrokerConfig_RoundTripJSON_MatchesSDKShape(t *testing.T) {
	id, _ := auth.NewTenantID("acme")
	rendered := renderVaultConfig(VaultBrokerConfig{
		Address:           "https://vault.example:8200",
		NamespaceTemplate: "tenant/{tenant_id}",
		KVMount:           "secret",
		Auth: VaultAuthConfig{
			Method:   "jwt",
			Audience: "gibson-saas", // operator-internal, must NOT appear in JSON
		},
		TransitKey: "tenant-kek", // operator-internal, must NOT appear in JSON
	}, id)
	body, err := json.Marshal(rendered)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	// Unmarshal into a generic map so we can assert the key shape
	// without taking a hard dep on the SDK type here.
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("Unmarshal back into map: %v", err)
	}
	// Required top-level keys, snake_case.
	for _, k := range []string{"address", "namespace", "kv_mount", "auth"} {
		if _, ok := got[k]; !ok {
			t.Errorf("missing key %q in serialised JSON; got %v", k, got)
		}
	}
	// Operator-internal fields must NOT appear in JSON.
	for _, k := range []string{"namespace_template", "transit_key", "auth_method", "mount_path", "audience"} {
		if _, ok := got[k]; ok {
			t.Errorf("operator-internal key %q leaked into serialised JSON; got %v", k, got)
		}
	}
	// Auth must be a nested object with snake_case keys.
	authObj, ok := got["auth"].(map[string]any)
	if !ok {
		t.Fatalf("auth must be a nested object, got %T: %v", got["auth"], got["auth"])
	}
	if authObj["method"] != "jwt" {
		t.Errorf("auth.method: got %q, want %q", authObj["method"], "jwt")
	}
	// ADR-0009 / tenant-operator#147: jwt method auto-templates the
	// role to "gibson-plugin-<tenant_id>" so the row matches what
	// namespace.go writeJWTRole provisions per tenant.
	if authObj["role"] != "gibson-plugin-acme" {
		t.Errorf("auth.role (jwt auto-template): got %q, want %q", authObj["role"], "gibson-plugin-acme")
	}
	// And the operator-internal Audience MUST NOT leak into auth either.
	if _, leaked := authObj["audience"]; leaked {
		t.Errorf("auth.audience leaked into serialised JSON; got %v", authObj)
	}
}

// TestRenderVaultConfig_NonJWTAuthRolePassThrough verifies the negative
// path: non-jwt auth methods (token, approle, kubernetes — historical;
// see ADR-0009 deny-list) must NOT have Auth.Role auto-templated. The
// caller's Role passes through unchanged. This guards against a future
// change that accidentally rewrites Role for every method.
func TestRenderVaultConfig_NonJWTAuthRolePassThrough(t *testing.T) {
	id, _ := auth.NewTenantID("acme")

	t.Run("token method preserves empty Role", func(t *testing.T) {
		rendered := renderVaultConfig(VaultBrokerConfig{
			Address: "https://vault.example:8200",
			Auth: VaultAuthConfig{
				Method: "token",
				// Role intentionally empty — token auth doesn't use a role.
			},
		}, id)
		if rendered.Auth.Role != "" {
			t.Errorf("token method must not auto-template Role; got %q", rendered.Auth.Role)
		}
	})

	t.Run("token method preserves caller-supplied Role", func(t *testing.T) {
		rendered := renderVaultConfig(VaultBrokerConfig{
			Address: "https://vault.example:8200",
			Auth: VaultAuthConfig{
				Method: "token",
				Role:   "operator-supplied-role",
			},
		}, id)
		if rendered.Auth.Role != "operator-supplied-role" {
			t.Errorf("non-jwt method must pass Role through; got %q, want %q",
				rendered.Auth.Role, "operator-supplied-role")
		}
	})

	t.Run("approle method preserves caller-supplied Role", func(t *testing.T) {
		rendered := renderVaultConfig(VaultBrokerConfig{
			Auth: VaultAuthConfig{
				Method: "approle",
				Role:   "approle-name",
			},
		}, id)
		if rendered.Auth.Role != "approle-name" {
			t.Errorf("approle method must pass Role through; got %q", rendered.Auth.Role)
		}
	})
}

// TestEncodeHostedBrokerConfig_SeedsVaultHosted asserts that the operator's
// provisioning seed encodes a Hosted (namespace-mode) broker-config row that
// the daemon's read side reports as VAULT_HOSTED (gibson#1107). This is the
// seed that keeps a freshly-provisioned tenant off the "configure backend"
// deadlock: GetBrokerConfig sees this row and returns configured:true +
// VAULT_HOSTED with no explicit SetBrokerConfig call.
func TestEncodeHostedBrokerConfig_SeedsVaultHosted(t *testing.T) {
	id, err := auth.NewTenantID("acme")
	if err != nil {
		t.Fatalf("NewTenantID: %v", err)
	}
	vc := VaultBrokerConfig{
		Address:           "https://vault.example:8200",
		NamespaceTemplate: "tenant/{tenant_id}",
		KVMount:           "secret",
		Auth:              VaultAuthConfig{Method: "jwt"},
	}

	provider, blob, err := encodeHostedBrokerConfig(vc, id)
	if err != nil {
		t.Fatalf("encodeHostedBrokerConfig: %v", err)
	}
	if provider != brokercodec.ProviderName {
		t.Errorf("provider: got %q, want %q", provider, brokercodec.ProviderName)
	}

	// The daemon reads this exact blob back through brokercodec.Redact; the
	// active-backend enum it derives MUST be VAULT_HOSTED (namespace mode).
	redacted, err := brokercodec.Redact(blob)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if redacted.GetProvider() != tenantv1.BrokerProvider_BROKER_PROVIDER_VAULT_HOSTED {
		t.Errorf("seed provider enum: got %v, want VAULT_HOSTED", redacted.GetProvider())
	}
	// Namespace mode: the tenant-scoped namespace is carried, not a path prefix.
	if got := redacted.GetNamespaceOrPath(); got != "tenant/acme" {
		t.Errorf("seed namespace: got %q, want %q", got, "tenant/acme")
	}
}

// TestEncodeHostedBrokerConfig_Idempotent asserts the seed encoding is
// deterministic: re-encoding the same (config, tenant) yields the identical
// provider name and byte-identical blob. This is what makes the saga's SetRaw
// upsert (ON CONFLICT DO UPDATE) converge on re-reconcile without churn — the
// idempotency the provisioning seed relies on (gibson#1107).
func TestEncodeHostedBrokerConfig_Idempotent(t *testing.T) {
	id, _ := auth.NewTenantID("acme")
	vc := VaultBrokerConfig{
		Address:           "https://vault.example:8200",
		NamespaceTemplate: "tenant/{tenant_id}",
		KVMount:           "secret",
		Auth:              VaultAuthConfig{Method: "jwt"},
	}

	p1, b1, err := encodeHostedBrokerConfig(vc, id)
	if err != nil {
		t.Fatalf("encode #1: %v", err)
	}
	p2, b2, err := encodeHostedBrokerConfig(vc, id)
	if err != nil {
		t.Fatalf("encode #2: %v", err)
	}
	if p1 != p2 {
		t.Errorf("provider not stable: %q vs %q", p1, p2)
	}
	if !bytes.Equal(b1, b2) {
		t.Errorf("blob not byte-identical across re-encode:\n #1 %s\n #2 %s", b1, b2)
	}
}

// TestSubstituteTenantID covers the helper directly, including edge
// cases that callers might trip on (empty template, no placeholder
// present, placeholder at start/end/middle).
func TestSubstituteTenantID(t *testing.T) {
	cases := []struct {
		name, tmpl, id, want string
	}{
		{"empty-template", "", "acme", ""},
		{"no-placeholder", "tenant/static", "acme", "tenant/static"},
		{"placeholder-at-start", "{tenant_id}/x", "acme", "acme/x"},
		{"placeholder-at-end", "x/{tenant_id}", "acme", "x/acme"},
		{"placeholder-in-middle", "x/{tenant_id}/y", "acme", "x/acme/y"},
		{"two-placeholders", "{tenant_id}/{tenant_id}", "acme", "acme/acme"},
		{"id-with-dashes", "p/{tenant_id}", "tenant-abc-001", "p/tenant-abc-001"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := substituteTenantID(tc.tmpl, tc.id); got != tc.want {
				t.Errorf("substituteTenantID(%q, %q) = %q, want %q", tc.tmpl, tc.id, got, tc.want)
			}
		})
	}
}

// The previous TestWriteTenantBrokerConfig_ProvisionFailsLoudOnEmptyVaultConfig
// was removed in deploy#194: VaultConfig completeness is now enforced at
// operator boot in cmd/main.go buildWriteTenantBrokerConfigDeps, not in
// the saga step. By the time Provision runs in any environment, the
// VaultConfig fields are guaranteed non-empty (or the process exited 1
// at startup). See ADR-0003 (one-code-path).
