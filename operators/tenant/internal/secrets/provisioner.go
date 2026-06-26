// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

// Package secrets composes the per-tenant secrets backend: the OpenBao/Vault
// namespace + JWT-auth role (auth/jwt), the per-tenant auth/jwt/config
// document, and the platform-side broker config row the gibson daemon reads to
// route per-tenant credential lookups.
//
// It is a THIN orchestrator over the SAME clients the Tenant provisioning saga
// uses today — vault.AdminClient (EnsureTenantNamespace / DeleteTenantNamespace
// / ConfigureTenantJWTAuth) and the tenantconfig broker-config writer. It does
// NOT reinvent the Vault or broker clients; it exposes a single
// Provision/Deprovision surface (mirroring dataplane.Provisioner) so the
// declarative TenantSecretsBackend controller and the imperative saga steps are
// two callers of one codepath (ADR-0027), not parallel reimplementations.
package secrets

import (
	"context"
	"errors"
	"fmt"
)

// Provisioner is the narrow Provision/Deprovision surface the
// TenantSecretsBackend controller delegates to. It mirrors
// dataplane.Provisioner so the controller pattern established by #801 carries
// over unchanged. Both methods are idempotent: re-running for an already
// provisioned tenant is a no-op, and Deprovision treats already-gone resources
// as success.
type Provisioner interface {
	// Provision ensures the per-tenant Vault namespace + JWT-auth role exist,
	// writes the auth/jwt/config document inside that namespace, and upserts
	// the platform broker-config row that points the daemon at the namespace.
	// Idempotent.
	Provision(ctx context.Context, tenantID string) error

	// Deprovision tears down the per-tenant secrets backend: it deletes the
	// platform broker-config row and the Vault namespace. Idempotent: a
	// not-found at any stage is treated as success.
	Deprovision(ctx context.Context, tenantID string) error
}

// VaultAdmin is the subset of the operator's vault.AdminClient the secrets
// provisioner needs. Declared as a local interface (rather than importing the
// concrete client type) so the controller's unit tests can stub it without a
// live Vault, and so the dependency direction stays one-way.
//
// Note: the operator's vault.AdminClient.EnsureTenantNamespace returns
// (Edition, error). The cmd/main.go adapter discards the Edition (saga
// record-keeping only) so this interface stays error-only and focused on the
// provisioning effect.
type VaultAdmin interface {
	// EnsureTenantNamespace provisions the per-tenant Vault namespace, mounts
	// KV v2 at secret/, writes the tenant ACL policy, and configures the
	// gibson-plugin-<id> JWT-auth role. Idempotent.
	EnsureTenantNamespace(ctx context.Context, tenantID string) error
	// ConfigureTenantJWTAuth writes auth/jwt/config inside the per-tenant
	// namespace. Idempotent.
	ConfigureTenantJWTAuth(ctx context.Context, tenantID string) error
	// DeleteTenantNamespace tears down the per-tenant Vault namespace.
	// Idempotent: already-gone is success.
	DeleteTenantNamespace(ctx context.Context, tenantID string) error
}

// BrokerConfigWriter is the subset of the broker-config write surface the
// secrets provisioner needs. It upserts / deletes the per-tenant row in the
// platform tenant_secrets_broker_config table the daemon's secrets.Registry
// reads. Declared as a local interface so the controller's tests can stub the
// platform-Postgres write without a live DB.
type BrokerConfigWriter interface {
	// WriteBrokerConfig upserts the per-tenant broker-config row. Idempotent
	// (ON CONFLICT (tenant_id) DO UPDATE).
	WriteBrokerConfig(ctx context.Context, tenantID string) error
	// DeleteBrokerConfig removes the per-tenant broker-config row. Idempotent:
	// already-gone is success.
	DeleteBrokerConfig(ctx context.Context, tenantID string) error
}

// NotFoundError reports whether err means a resource was already gone. The
// provisioner classifies a not-found from any sub-step as success on the
// Deprovision path. Supplied by the caller (cmd/main.go binds the operator's
// clients.ErrNotFound matcher) so this package takes no dependency on the
// operator's clients package.
type NotFoundError func(error) bool

// New returns the production Provisioner composing the supplied Vault admin
// client and broker-config writer. Both must be non-nil — a nil here is
// operator misconfiguration and New panics so a misconfigured operator
// crash-loops at boot rather than silently no-op'ing secrets provisioning
// (one-code-path).
func New(vault VaultAdmin, broker BrokerConfigWriter, isNotFound NotFoundError) Provisioner {
	if vault == nil {
		panic("secrets.New: vault admin client is nil (operator misconfigured)")
	}
	if broker == nil {
		panic("secrets.New: broker config writer is nil (operator misconfigured)")
	}
	if isNotFound == nil {
		isNotFound = func(error) bool { return false }
	}
	return &provisioner{vault: vault, broker: broker, isNotFound: isNotFound}
}

type provisioner struct {
	vault      VaultAdmin
	broker     BrokerConfigWriter
	isNotFound NotFoundError
}

// Provision runs the three secrets-backend sub-steps in the SAME order the
// Tenant saga does: ensure the namespace + JWT role, write auth/jwt/config,
// then upsert the broker-config row. The broker row is last because it points
// the daemon at a namespace that must already exist (the saga enforces the same
// ordering: WriteTenantBrokerConfig requires ProvisionSecretsBackend).
func (p *provisioner) Provision(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		return errors.New("secrets.Provision: empty tenant id")
	}
	if err := p.vault.EnsureTenantNamespace(ctx, tenantID); err != nil {
		return fmt.Errorf("secrets.Provision: ensure namespace tenant=%s: %w", tenantID, err)
	}
	if err := p.vault.ConfigureTenantJWTAuth(ctx, tenantID); err != nil {
		return fmt.Errorf("secrets.Provision: configure jwt auth tenant=%s: %w", tenantID, err)
	}
	if err := p.broker.WriteBrokerConfig(ctx, tenantID); err != nil {
		return fmt.Errorf("secrets.Provision: write broker config tenant=%s: %w", tenantID, err)
	}
	return nil
}

// Deprovision removes the platform broker-config row first (so the daemon stops
// routing to a namespace about to vanish), then deletes the Vault namespace
// (which carries auth/jwt/config and the per-tenant role wholesale). A
// not-found at either stage is treated as success so teardown is idempotent.
func (p *provisioner) Deprovision(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		return errors.New("secrets.Deprovision: empty tenant id")
	}
	if err := p.broker.DeleteBrokerConfig(ctx, tenantID); err != nil && !p.isNotFound(err) {
		return fmt.Errorf("secrets.Deprovision: delete broker config tenant=%s: %w", tenantID, err)
	}
	if err := p.vault.DeleteTenantNamespace(ctx, tenantID); err != nil && !p.isNotFound(err) {
		return fmt.Errorf("secrets.Deprovision: delete namespace tenant=%s: %w", tenantID, err)
	}
	return nil
}
