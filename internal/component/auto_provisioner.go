package component

// auto_provisioner.go implements TenantAutoProvisioner, which handles automatic
// tenant creation on first login.
//
// When a token arrives whose tenant claim value does not match any existing
// tenant, EnsureTenant creates the tenant record in Redis.  A distributed lock
// (Redis SETNX) prevents duplicate creation under concurrent login storms.
//
// The Langfuse project creation step is always best-effort: a failure is logged
// as a warning and does not prevent the tenant from being usable.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// LangfuseProvisioner creates Langfuse projects for tenants.
// Implemented by the dashboard/provisioner layer.
type LangfuseProvisioner interface {
	CreateProject(ctx context.Context, tenantID string) error
}

// AutoProvisionerOption is a functional option for TenantAutoProvisioner.
type AutoProvisionerOption func(*TenantAutoProvisioner)

// TenantAutoProvisioner handles automatic tenant creation on first login.
type TenantAutoProvisioner struct {
	tenants  *TenantService
	langfuse LangfuseProvisioner // optional, can be nil
	plugins  PluginAccessStore   // optional, can be nil
	logger   *slog.Logger
}

// NewTenantAutoProvisioner creates a new auto-provisioner.
// langfuse and plugins are optional — pass nil when not needed.
// The kc parameter is accepted but ignored; it is retained for call-site
// compatibility during the Better Auth migration and will be removed in a
// follow-up cleanup.
func NewTenantAutoProvisioner(
	tenants *TenantService,
	kc interface{}, // deprecated: ignored; was *keycloak.Client
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

	config := map[string]string{
		"auto_provisioned": "true",
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

// isErrTenantNotFound reports whether err wraps ErrTenantNotFound.
func isErrTenantNotFound(err error) bool {
	return errors.Is(err, ErrTenantNotFound)
}

// isErrTenantAlreadyExists reports whether err wraps ErrTenantAlreadyExists.
func isErrTenantAlreadyExists(err error) bool {
	return errors.Is(err, ErrTenantAlreadyExists)
}
