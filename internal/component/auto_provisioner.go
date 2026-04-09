package component

// auto_provisioner.go implements TenantAutoProvisioner, which handles automatic
// tenant creation on first OIDC login.
//
// When a token arrives whose tenant claim value does not match any existing
// tenant, EnsureTenant creates the tenant record in Redis.  A distributed lock
// (Redis SETNX) prevents duplicate creation under concurrent login storms.
//
// The Langfuse project creation step is always best-effort: a failure is logged
// as a warning and does not prevent the tenant from being usable.
//
// Keycloak realm creation runs before the tenant record is written.  On-prem
// deployments set skipRealmCreation=true (the realm is pre-configured by the
// operator); SaaS deployments create a dedicated realm per tenant.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/zero-day-ai/gibson/internal/keycloak"
)

// LangfuseProvisioner creates Langfuse projects for tenants.
// Implemented by the dashboard/provisioner layer.
type LangfuseProvisioner interface {
	CreateProject(ctx context.Context, tenantID string) error
}

// AutoProvisionerOption is a functional option for TenantAutoProvisioner.
type AutoProvisionerOption func(*TenantAutoProvisioner)

// WithSkipRealmCreation disables Keycloak realm creation during auto-provisioning.
// Use this for on-prem deployments where the realm is pre-configured by the operator.
func WithSkipRealmCreation(skip bool) AutoProvisionerOption {
	return func(p *TenantAutoProvisioner) { p.skipRealmCreation = skip }
}

// WithDefaultRealmName sets a fixed realm name for all tenants.
// For on-prem deployments this is typically "gibson"; for SaaS it is left empty
// so that each tenant gets a realm named after its tenant ID.
func WithDefaultRealmName(name string) AutoProvisionerOption {
	return func(p *TenantAutoProvisioner) { p.defaultRealmName = name }
}

// TenantAutoProvisioner handles automatic tenant creation on first login.
type TenantAutoProvisioner struct {
	tenants  *TenantService
	keycloak *keycloak.Client    // optional, can be nil
	langfuse LangfuseProvisioner // optional, can be nil
	plugins  PluginAccessStore   // optional, can be nil
	logger   *slog.Logger

	// Configuration
	skipRealmCreation bool   // true for on-prem (realm already exists)
	defaultRealmName  string // on-prem: "gibson"; SaaS: "" (derived from tenant ID)
}

// NewTenantAutoProvisioner creates a new auto-provisioner.
// kc, langfuse, and plugins are optional — pass nil when not needed.
// Use AutoProvisionerOption values to configure on-prem vs SaaS behaviour.
func NewTenantAutoProvisioner(
	tenants *TenantService,
	kc *keycloak.Client,
	langfuse LangfuseProvisioner,
	plugins PluginAccessStore,
	logger *slog.Logger,
	opts ...AutoProvisionerOption,
) *TenantAutoProvisioner {
	if logger == nil {
		logger = slog.Default()
	}
	p := &TenantAutoProvisioner{
		tenants:  tenants,
		keycloak: kc,
		langfuse: langfuse,
		plugins:  plugins,
		logger:   logger,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// EnsureTenant checks whether a tenant exists and creates it if not.
//
// Uses Redis SETNX for distributed locking so that concurrent requests racing
// to provision the same tenant ID produce exactly one record.  Returns nil if
// the tenant already exists or was successfully created.
func (p *TenantAutoProvisioner) EnsureTenant(ctx context.Context, tenantID string) error {
	// Fast path: tenant already exists.
	_, err := p.tenants.fetchTenant(ctx, tenantID)
	if err == nil {
		return nil
	}
	if !isErrTenantNotFound(err) {
		return fmt.Errorf("checking tenant existence: %w", err)
	}

	// Tenant doesn't exist — try to acquire provisioning lock.
	lockKey := fmt.Sprintf("tenant:%s:provisioning_lock", tenantID)
	acquired, err := p.tenants.client.SetNX(ctx, lockKey, "1", 30*time.Second).Result()
	if err != nil {
		return fmt.Errorf("acquiring provisioning lock: %w", err)
	}

	if !acquired {
		// Another request is provisioning this tenant — wait for completion.
		return p.waitForProvisioning(ctx, tenantID, 10*time.Second)
	}
	defer p.tenants.client.Del(ctx, lockKey) //nolint:errcheck

	// Double-check after acquiring the lock: another goroutine may have just
	// finished creating the tenant before we held the lock.
	_, err = p.tenants.fetchTenant(ctx, tenantID)
	if err == nil {
		return nil
	}

	// Create the tenant.  Display name defaults to the claim value.
	p.logger.Info("auto-provisioning new tenant", "tenant_id", tenantID)

	// Determine which Keycloak realm this tenant maps to.  SaaS: one realm per
	// tenant (realm name == tenant ID).  On-prem: a single shared realm whose
	// name is set by the operator via WithDefaultRealmName.
	realmName := tenantID
	if p.defaultRealmName != "" {
		realmName = p.defaultRealmName
	}

	// Create the Keycloak realm before writing the tenant record so that the
	// realm is ready by the time the first user token arrives.
	if !p.skipRealmCreation && p.keycloak != nil {
		if err := p.createKeycloakRealm(ctx, tenantID, realmName); err != nil {
			return fmt.Errorf("creating Keycloak realm: %w", err)
		}
	}

	config := map[string]string{
		"auto_provisioned":    "true",
		"keycloak_realm_name": realmName,
	}

	_, err = p.tenants.createTenantInternal(ctx, tenantID, tenantID, config)
	if err != nil && !isErrTenantAlreadyExists(err) {
		return fmt.Errorf("creating tenant: %w", err)
	}

	// Best-effort: create Langfuse project.  Failure is non-fatal — the tenant
	// is fully usable without a dedicated Langfuse project.
	if p.langfuse != nil {
		if lfErr := p.langfuse.CreateProject(ctx, tenantID); lfErr != nil {
			p.logger.Warn("failed to create Langfuse project during auto-provisioning",
				"tenant_id", tenantID,
				"error", lfErr,
			)
		}
	}

	p.logger.Info("tenant auto-provisioned successfully", "tenant_id", tenantID)
	return nil
}

// waitForProvisioning polls until another process finishes creating the tenant
// or the timeout expires.
func (p *TenantAutoProvisioner) waitForProvisioning(ctx context.Context, tenantID string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		_, err := p.tenants.fetchTenant(ctx, tenantID)
		if err == nil {
			return nil // tenant now exists
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
			// poll again
		}
	}
	return fmt.Errorf("timeout waiting for tenant %q provisioning", tenantID)
}

// createKeycloakRealm provisions a Keycloak realm for the given tenant.
//
// Steps performed (all idempotent — 409 responses are treated as success by the
// Keycloak client):
//  1. Create the realm.
//  2. Create the "gibson-dashboard" OIDC client.
//  3. Create default realm roles: owner, admin, operator, viewer.
//  4. Add a hardcoded tenant_id claim mapper so every token carries the tenant ID.
//
// Role and mapper failures are non-fatal: they are logged as warnings and do not
// block tenant creation, since the realm itself is the critical resource.
func (p *TenantAutoProvisioner) createKeycloakRealm(ctx context.Context, tenantID, realmName string) error {
	// Step 1: create the realm (409 = already exists = OK, handled by client).
	if err := p.keycloak.CreateRealm(ctx, keycloak.RealmConfig{
		Name:        realmName,
		DisplayName: tenantID,
		Enabled:     true,
	}); err != nil {
		return fmt.Errorf("creating realm %q: %w", realmName, err)
	}

	// Step 2: create the dashboard OIDC client.
	clientUUID, err := p.keycloak.CreateOIDCClient(ctx, realmName, keycloak.OIDCClientConfig{
		ClientID:     "gibson-dashboard",
		RedirectURIs: []string{"*"}, // Narrowed at deploy time via Helm values.
	})
	if err != nil {
		// Non-fatal — client may already exist or will be configured separately.
		p.logger.Warn("failed to create OIDC client during auto-provisioning",
			"realm", realmName,
			"error", err,
		)
	}

	// Step 3: create standard Gibson realm roles.
	for _, role := range []string{"owner", "admin", "operator", "viewer"} {
		if err := p.keycloak.CreateRealmRole(ctx, realmName, role, "Gibson "+role+" role"); err != nil {
			p.logger.Warn("failed to create realm role during auto-provisioning",
				"realm", realmName,
				"role", role,
				"error", err,
			)
		}
	}

	// Step 4: attach a hardcoded tenant_id claim to the dashboard client so every
	// JWT issued by this realm carries the tenant identity.
	if clientUUID != "" {
		mapper := keycloak.ProtocolMapperConfig{
			Name:           "tenant_id",
			Protocol:       "openid-connect",
			ProtocolMapper: "oidc-hardcoded-claim-mapper",
			Config: map[string]string{
				"claim.name":           "tenant_id",
				"claim.value":          tenantID,
				"jsonType.label":       "String",
				"id.token.claim":       "true",
				"access.token.claim":   "true",
				"userinfo.token.claim": "true",
			},
		}
		if err := p.keycloak.AddProtocolMapper(ctx, realmName, clientUUID, mapper); err != nil {
			p.logger.Warn("failed to add tenant_id protocol mapper during auto-provisioning",
				"realm", realmName,
				"error", err,
			)
		}
	}

	return nil
}

// isErrTenantNotFound reports whether err wraps ErrTenantNotFound.
func isErrTenantNotFound(err error) bool {
	return errors.Is(err, ErrTenantNotFound)
}

// isErrTenantAlreadyExists reports whether err wraps ErrTenantAlreadyExists.
func isErrTenantAlreadyExists(err error) bool {
	return errors.Is(err, ErrTenantAlreadyExists)
}
