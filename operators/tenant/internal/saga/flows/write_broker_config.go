/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package flows

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zeroroot-ai/sdk/auth"

	"github.com/zeroroot-ai/gibson/internal/infra/tenantconfig"
)

// WriteTenantBrokerConfigDeps is the dependency bundle consumed by the
// WriteTenantBrokerConfig saga step. The step writes a row into the
// platform `tenant_secrets_broker_config` table so the gibson daemon's
// secrets.Registry can route per-tenant credential lookups after
// data-plane provisioning completes.
//
// Spec issue #45.
//
// Without this row, every authenticated ListMissions / ListAgents call
// hits gibson's "FailedPrecondition: tenant has no broker config row"
// guard and the dashboard renders the empty-state error page.
type WriteTenantBrokerConfigDeps struct {
	// PlatformPG is the connection pool to the OPERATOR-SHARED Postgres
	// database that hosts the tenant_secrets_broker_config table. This
	// is the same DB the daemon's TenantConfigStore connects to. May be
	// nil; when nil the step is a no-op (validation should fail-loud at
	// startup in saas/selfhost modes via ValidateAtStartup).
	PlatformPG *pgxpool.Pool

	// SystemTenantKEK lazily provides the 32-byte system-tenant KEK used to
	// envelope-encrypt the broker config JSON. Must match what the daemon's
	// configstore.NewStore was constructed with so the daemon can decrypt the
	// row this step writes.
	//
	// It is a provider (read at reconcile time), NOT a value captured once at
	// startup: on a from-zero bringup the backing Secret (gibson-master-key) is
	// produced later by PlatformBootstrap, so the operator must start without it
	// and this step requeues until it's available — mirroring the daemon's
	// runtime key_provider read of the same Secret (deploy#971). May be nil or
	// return empty; resolveKEK turns that into a retryable error.
	SystemTenantKEK func() []byte

	// VaultConfig is the JSON config blob the step writes for every new
	// tenant. It points the daemon's vault broker at the tenant's Vault
	// namespace. Path / transit_key / auth_method values come from the
	// operator's Vault configuration; the saga step writes them per
	// tenant with no per-tenant overrides today.
	//
	// When zero, the step falls back to a minimal "address-only" config
	// that the daemon's vault broker treats as "use the default address
	// + namespace=tenant/<id>". This matches the kind-dev path where
	// the Vault transit key is shared and the namespace pattern is
	// templated server-side.
	VaultConfig VaultBrokerConfig
}

// VaultBrokerConfig is the Vault-provider config the operator writes to
// the platform's tenant_secrets_broker_config table. The shape MUST
// match `github.com/zeroroot-ai/gibson/internal/infra/secrets/vault.Config` so
// the daemon can deserialise it on read. The platform-clients type gained
// explicit JSON tags in sdk#79 (when it still lived in the OSS SDK) and
// was migrated to platform-clients as part of the secrets purge; we mirror
// the structure here so the operator can populate it without taking a hard
// platform-clients dependency in the saga code path.
//
// Schema invariants (asserted by a round-trip test in
// write_broker_config_test.go):
//
//   - The output of json.Marshal on this struct MUST deserialise cleanly
//     into sdkvault.Config with every field present.
//   - JSON keys are snake_case (matches sdk#79).
//   - Auth is a NESTED object — the daemon's sdkvault.Config has
//     `Auth AuthConfig json:"auth"`, NOT a flat `auth_method` field.
//     A previous flat-mirror version of this struct silently broke
//     every signed-up tenant (tenant-operator#144).
type VaultBrokerConfig struct {
	// Address is the Vault API URL the daemon dials. Required.
	Address string `json:"address"`
	// NamespaceTemplate is the OPERATOR-SIDE template for the per-tenant
	// Vault namespace. The literal "{tenant_id}" substring is replaced
	// with the tenant's auth.TenantID string form at write time, and
	// the rendered value lands in `Namespace` below. Default
	// "tenant/{tenant_id}". This field is operator-internal and never
	// appears in the serialised JSON written to the platform table.
	NamespaceTemplate string `json:"-"`
	// Namespace is the rendered per-tenant Vault namespace
	// ("tenant/<tenant_id>"). Serialised as the SDK Config's `namespace`
	// field.
	Namespace string `json:"namespace,omitempty"`
	// KVMount is the Vault KV v2 mount that holds the tenant's secrets.
	// Defaults to "secret" when empty. Maps to sdkvault.Config.KVMount.
	KVMount string `json:"kv_mount,omitempty"`
	// Auth holds the Vault authentication configuration. Mirrors
	// sdkvault.AuthConfig — a nested object, NOT flat fields.
	Auth VaultAuthConfig `json:"auth"`

	// TransitKey is operator-internal config — names the Vault transit
	// key used for envelope-DEK wrap on per-tenant secrets. Daemon does
	// NOT need to know this directly; it's consumed by the operator's
	// data-plane provisioner. Not serialised.
	TransitKey string `json:"-"`
}

// VaultAuthConfig mirrors sdkvault.AuthConfig (subset — only fields the
// operator populates today). JSON keys snake_case to match sdk#79.
type VaultAuthConfig struct {
	// Method is one of "token", "approle", "kubernetes", "jwt".
	// Required.
	Method string `json:"method"`
	// Role is the Vault role name. Required for kubernetes / jwt /
	// approle. When Method == "jwt", renderVaultConfig auto-templates
	// this to "gibson-plugin-<tenant_id>" so the per-tenant broker
	// config row carries the role name the daemon's vault broker
	// needs at runtime (ADR-0009, tenant-operator#147). For other
	// methods, the value passes through unchanged.
	Role string `json:"role,omitempty"`
	// Audience is operator-internal config (NOT serialised). The
	// expected `aud` claim on plugin JWTs surfaces at the Vault role
	// level via `bound_audiences`, NOT in the broker config JSON the
	// daemon reads. Holding the value here keeps the saga + writeJWTRole
	// in sync from the same configuration source (ADR-0009,
	// tenant-operator#147).
	Audience string `json:"-"`
}

// WriteBrokerConfig renders and upserts the per-tenant broker-config row. It is
// the single codepath shared by the saga's TenantBrokerConfigWritten step and
// the declarative TenantSecretsBackend controller (via secrets.Provisioner), so
// both callers write byte-identical rows (ADR-0027). tenantName is the Tenant
// CR name.
//
// one-code-path (deploy#194): VaultConfig completeness is enforced at boot in
// cmd/main.go buildWriteTenantBrokerConfigDeps. By the time this runs,
// NamespaceTemplate / AuthMethod / MountPath are all guaranteed non-empty.
func (d WriteTenantBrokerConfigDeps) WriteBrokerConfig(ctx context.Context, tenantName string) error {
	tenantID, err := auth.NewTenantID(tenantName)
	if err != nil {
		return fmt.Errorf("writeTenantBrokerConfig: invalid tenant id %q: %w", tenantName, err)
	}

	// Resolve the per-tenant namespace from the template. The daemon's vault
	// broker re-resolves the same template; keep them in sync.
	rendered := renderVaultConfig(d.VaultConfig, tenantID)

	configJSON, err := json.Marshal(rendered)
	if err != nil {
		return fmt.Errorf("writeTenantBrokerConfig: marshal config: %w", err)
	}

	kek, err := d.resolveKEK()
	if err != nil {
		return fmt.Errorf("writeTenantBrokerConfig: %w", err)
	}
	store, err := tenantconfig.NewStore(d.PlatformPG, kek)
	if err != nil {
		return fmt.Errorf("writeTenantBrokerConfig: build config store: %w", err)
	}

	// SetRaw is an upsert (ON CONFLICT (tenant_id) DO UPDATE) per the daemon's
	// schema, so retries / re-reconciles converge on the latest config without
	// manual cleanup.
	const actor = "tenant-operator-saga"
	if err := store.SetRaw(ctx, tenantID, "vault", configJSON, actor); err != nil {
		return fmt.Errorf("writeTenantBrokerConfig: upsert: %w", err)
	}
	return nil
}

// DeleteBrokerConfig removes the per-tenant broker-config row. Shared by the
// saga's TenantBrokerConfigWritten teardown step and the TenantSecretsBackend
// controller's Deprovision path (ADR-0027). tenantName is the Tenant CR name.
func (d WriteTenantBrokerConfigDeps) DeleteBrokerConfig(ctx context.Context, tenantName string) error {
	tenantID, err := auth.NewTenantID(tenantName)
	if err != nil {
		// Best-effort on teardown: a malformed tenant ID at this stage is
		// unusual; surface but don't block teardown.
		return fmt.Errorf("writeTenantBrokerConfig: invalid tenant id %q: %w", tenantName, err)
	}
	kek, err := d.resolveKEK()
	if err != nil {
		return fmt.Errorf("writeTenantBrokerConfig: %w", err)
	}
	store, err := tenantconfig.NewStore(d.PlatformPG, kek)
	if err != nil {
		return fmt.Errorf("writeTenantBrokerConfig: build config store on teardown: %w", err)
	}
	if err := store.DeleteRaw(ctx, tenantID); err != nil {
		return fmt.Errorf("writeTenantBrokerConfig: delete: %w", err)
	}
	return nil
}

// resolveKEK reads the system-tenant KEK via the lazy provider at call time. A
// nil provider or an empty KEK becomes a retryable error so the saga requeues
// until gibson-master-key is populated (deploy#971) — rather than the operator
// crash-looping at startup and deadlocking the from-zero bringup.
func (d WriteTenantBrokerConfigDeps) resolveKEK() ([]byte, error) {
	if d.SystemTenantKEK == nil {
		return nil, errors.New("system-tenant KEK provider not configured")
	}
	kek := d.SystemTenantKEK()
	if len(kek) == 0 {
		return nil, errors.New("system-tenant KEK not yet available (gibson-master-key Secret not populated); requeue")
	}
	return kek, nil
}

// renderVaultConfig substitutes the literal "{tenant_id}" placeholder in
// the NamespaceTemplate (operator-internal) and stores the result in
// Namespace (serialised). When Auth.Method == "jwt", it also auto-
// templates Auth.Role to "gibson-plugin-<tenant_id>" so the row matches
// the role name the namespace.go provisioner writes via writeJWTRole
// (ADR-0009, tenant-operator#147). Other methods pass Auth.Role through
// unchanged. After rendering, json.Marshal(out) produces a payload that
// deserialises cleanly into sdkvault.Config.
func renderVaultConfig(cfg VaultBrokerConfig, tenantID auth.TenantID) VaultBrokerConfig {
	out := cfg
	if out.NamespaceTemplate != "" {
		out.Namespace = substituteTenantID(out.NamespaceTemplate, tenantID.String())
	}
	if out.Auth.Method == "jwt" {
		out.Auth.Role = "gibson-plugin-" + tenantID.String()
	}
	return out
}

// substituteTenantID replaces every literal "{tenant_id}" with the
// supplied ID. Implemented inline (rather than text/template) so the
// rendered string is byte-stable and trivially auditable.
func substituteTenantID(template, id string) string {
	const placeholder = "{tenant_id}"
	if template == "" {
		return ""
	}
	out := template
	for {
		i := indexOf(out, placeholder)
		if i < 0 {
			return out
		}
		out = out[:i] + id + out[i+len(placeholder):]
	}
}

// indexOf is the stdlib strings.Index, repeated here so this file
// doesn't pull a strings import for one call.
func indexOf(s, sub string) int {
	if sub == "" || len(sub) > len(s) {
		return -1
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
