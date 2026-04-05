package component

// tenant_service.go implements TenantService, which manages the lifecycle of
// tenants stored in Redis.
//
// Storage layout:
//   - tenant:{tenant_id}:meta   JSON-serialized TenantRecord
//   - tenants:all               Redis SET of all active tenant IDs (for list/index)
//
// Soft deletes mark a record's status as "deleted" and remove the tenant ID
// from the index SET.  The meta key is kept so audit history is preserved.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"time"

	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zero-day-ai/gibson/internal/audit"
	"github.com/zero-day-ai/gibson/internal/auth"
)

// ---------------------------------------------------------------------------
// Sentinel errors
// ---------------------------------------------------------------------------

var (
	// ErrTenantNotFound is returned when a tenant record does not exist in Redis.
	ErrTenantNotFound = errors.New("tenant not found")

	// ErrTenantAlreadyExists is returned when CreateTenant is called with a
	// tenant_id that is already registered.
	ErrTenantAlreadyExists = errors.New("tenant already exists")

	// ErrInvalidTenantID is returned when the provided tenant_id contains
	// characters that are not URL-safe (alphanumeric and hyphens only).
	ErrInvalidTenantID = errors.New("tenant_id must contain only alphanumeric characters and hyphens")
)

// ---------------------------------------------------------------------------
// TenantRecord
// ---------------------------------------------------------------------------

// TenantRecord is the canonical representation of a Gibson tenant.
// It is serialised to JSON and stored at tenant:{tenant_id}:meta.
type TenantRecord struct {
	TenantID    string            `json:"tenant_id"`
	DisplayName string            `json:"display_name"`
	// Status is one of "active", "suspended", "deleted", "provisioning", or "provisioning_failed".
	Status           string            `json:"status"`
	// Tier is the billing tier: "free", "team", "business", or "enterprise".
	Tier             string            `json:"tier"`
	// OwnerEmail is the email address of the tenant owner (set during signup).
	OwnerEmail       string            `json:"owner_email"`
	// StripeCustomerID is the Stripe customer ID (empty for free tier).
	StripeCustomerID string            `json:"stripe_customer_id"`
	// StripeSubID is the Stripe subscription ID.
	StripeSubID      string            `json:"stripe_sub_id"`
	// BillingAlert is true when the tenant has a payment failure that requires attention.
	BillingAlert     bool              `json:"billing_alert"`
	// KeycloakRealmName is the Keycloak realm for this tenant.
	KeycloakRealmName string            `json:"keycloak_realm_name"` // Keycloak realm for this tenant
	Config           map[string]string `json:"config"`
	CreatedAt        time.Time         `json:"created_at"`
	UpdatedAt        time.Time         `json:"updated_at"`
}

// ---------------------------------------------------------------------------
// Redis key helpers
// ---------------------------------------------------------------------------

const (
	// tenantIndexKey is the Redis SET that holds all non-deleted tenant IDs.
	tenantIndexKey = "tenants:all"
)

// tenantMetaKey returns the Redis key for the JSON-serialised TenantRecord.
//
// Format: tenant:{tenant_id}:meta
func tenantMetaKey(tenantID string) string {
	return fmt.Sprintf("tenant:%s:meta", tenantID)
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

// tenantIDPattern accepts only lowercase/uppercase alphanumeric characters and
// hyphens, matching common URL-slug conventions.
var tenantIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9]$|^[a-zA-Z0-9]$`)

// validateTenantID returns ErrInvalidTenantID when tenantID contains characters
// outside the allowed set or is empty.
func validateTenantID(tenantID string) error {
	if tenantID == "" || !tenantIDPattern.MatchString(tenantID) {
		return fmt.Errorf("%w: %q", ErrInvalidTenantID, tenantID)
	}
	return nil
}

// ---------------------------------------------------------------------------
// TenantService
// ---------------------------------------------------------------------------

// TenantService provides CRUD operations for Gibson tenants.  All records are
// stored in Redis using the layout described at the top of this file.
//
// Cross-tenant operations (CreateTenant, DeleteTenant, SetTenantQuota) require
// the "platform-operator" role.  Within-tenant mutations require "owner" or
// "admin" scoped to the caller's own tenant.  Read methods apply scoped
// visibility rules: only "platform-operator" callers may access other tenants;
// all other authenticated callers are restricted to their own tenant.
type TenantService struct {
	client       *redis.Client
	logger       *slog.Logger
	auditLog     *audit.AuditLogger
	quotaManager *QuotaManager
}

// NewTenantService constructs a TenantService backed by the provided Redis
// client.  Both client and logger must be non-nil; if logger is nil slog.Default()
// is used as a safe fallback.  auditLog may be nil — when nil, audit events are
// silently skipped and operations continue normally.
func NewTenantService(client *redis.Client, logger *slog.Logger, auditLog *audit.AuditLogger) *TenantService {
	if client == nil {
		panic("component.NewTenantService: client must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &TenantService{
		client:   client,
		logger:   logger,
		auditLog: auditLog,
	}
}

// WithQuotaManager attaches a QuotaManager so that GetTenantQuota and
// SetTenantQuota are backed by durable Redis quota storage.  Without it,
// both methods return codes.Unimplemented.
func (s *TenantService) WithQuotaManager(qm *QuotaManager) *TenantService {
	s.quotaManager = qm
	return s
}

// ---------------------------------------------------------------------------
// CreateTenant
// ---------------------------------------------------------------------------

// CreateTenant registers a new tenant with the given ID and display name.
//
// The tenantID must be URL-safe: only alphanumeric characters and hyphens are
// allowed.  Returns ErrTenantAlreadyExists if the ID is already taken.
func (s *TenantService) CreateTenant(ctx context.Context, tenantID, displayName string, config map[string]string) (*TenantRecord, error) {
	if err := auth.RequireRole(ctx, "platform-operator"); err != nil {
		return nil, err
	}

	if err := validateTenantID(tenantID); err != nil {
		return nil, err
	}

	metaKey := tenantMetaKey(tenantID)

	// Conflict check: reject if the meta key already exists in Redis.
	exists, err := s.client.Exists(ctx, metaKey).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to check tenant existence for %q: %w", tenantID, err)
	}
	if exists > 0 {
		return nil, fmt.Errorf("%w: %q", ErrTenantAlreadyExists, tenantID)
	}

	now := time.Now().UTC()
	if config == nil {
		config = make(map[string]string)
	}

	record := &TenantRecord{
		TenantID:    tenantID,
		DisplayName: displayName,
		Status:      "active",
		Config:      config,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if realmName, ok := config["keycloak_realm_name"]; ok {
		record.KeycloakRealmName = realmName
	}

	data, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("failed to serialise tenant record for %q: %w", tenantID, err)
	}

	// Persist record and add to the index atomically via a pipeline.
	pipe := s.client.Pipeline()
	pipe.Set(ctx, metaKey, data, 0)
	pipe.SAdd(ctx, tenantIndexKey, tenantID)
	if _, err = pipe.Exec(ctx); err != nil {
		return nil, fmt.Errorf("failed to store tenant %q: %w", tenantID, err)
	}

	// Write Stripe reverse mapping if customer ID is set.
	if cid, ok := config["stripe_customer_id"]; ok && cid != "" {
		if err := s.writeStripeReverseMapping(ctx, cid, tenantID); err != nil {
			s.logger.WarnContext(ctx, "failed to write stripe reverse mapping on create", "error", err)
		}
	}

	s.logger.InfoContext(ctx, "tenant created",
		slog.String("tenant_id", tenantID),
		slog.String("display_name", displayName),
	)

	if s.auditLog != nil {
		if err := s.auditLog.Log(ctx, "tenant.create", "tenant", tenantID, map[string]any{
			"display_name": displayName,
		}); err != nil {
			s.logger.WarnContext(ctx, "audit log failed", "error", err)
		}
	}

	return record, nil
}

// ---------------------------------------------------------------------------
// createTenantInternal
// ---------------------------------------------------------------------------

// createTenantInternal registers a new tenant without performing any RBAC
// checks.  It is intentionally unexported and exists solely to support
// TenantAutoProvisioner, which creates tenants during OIDC token validation
// before a full auth identity is established.
//
// Callers are responsible for ensuring this code path is only reachable after
// all other safety checks (e.g. distributed lock, existence check) have passed.
func (s *TenantService) createTenantInternal(ctx context.Context, tenantID, displayName string, config map[string]string) (*TenantRecord, error) {
	if err := validateTenantID(tenantID); err != nil {
		return nil, err
	}

	metaKey := tenantMetaKey(tenantID)

	exists, err := s.client.Exists(ctx, metaKey).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to check tenant existence for %q: %w", tenantID, err)
	}
	if exists > 0 {
		return nil, fmt.Errorf("%w: %q", ErrTenantAlreadyExists, tenantID)
	}

	now := time.Now().UTC()
	if config == nil {
		config = make(map[string]string)
	}

	record := &TenantRecord{
		TenantID:    tenantID,
		DisplayName: displayName,
		Status:      "active",
		Config:      config,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if realmName, ok := config["keycloak_realm_name"]; ok {
		record.KeycloakRealmName = realmName
	}

	data, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("failed to serialise tenant record for %q: %w", tenantID, err)
	}

	pipe := s.client.Pipeline()
	pipe.Set(ctx, metaKey, data, 0)
	pipe.SAdd(ctx, tenantIndexKey, tenantID)
	if _, err = pipe.Exec(ctx); err != nil {
		return nil, fmt.Errorf("failed to store tenant %q: %w", tenantID, err)
	}

	s.logger.InfoContext(ctx, "tenant created (auto-provisioned)",
		slog.String("tenant_id", tenantID),
		slog.String("display_name", displayName),
	)

	if s.auditLog != nil {
		if err := s.auditLog.Log(ctx, "tenant.create", "tenant", tenantID, map[string]any{
			"display_name":     displayName,
			"auto_provisioned": true,
		}); err != nil {
			s.logger.WarnContext(ctx, "audit log failed", "error", err)
		}
	}

	return record, nil
}

// ---------------------------------------------------------------------------
// GetTenant
// ---------------------------------------------------------------------------

// GetTenant retrieves a tenant record by ID.
//
// Returns ErrTenantNotFound when no record exists for the given ID.
func (s *TenantService) GetTenant(ctx context.Context, tenantID string) (*TenantRecord, error) {
	identity, ok := auth.GibsonIdentityFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "not authenticated")
	}
	if !identity.HasRole("platform-operator") && auth.TenantFromContext(ctx) != tenantID {
		return nil, status.Errorf(codes.PermissionDenied, "access denied: can only view own tenant")
	}

	return s.fetchTenant(ctx, tenantID)
}

// fetchTenant reads a tenant record directly from Redis without performing any
// authorization checks.  It is an internal helper used by GetTenant and
// ListTenants after the caller's access has already been verified.
func (s *TenantService) fetchTenant(ctx context.Context, tenantID string) (*TenantRecord, error) {
	data, err := s.client.Get(ctx, tenantMetaKey(tenantID)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, fmt.Errorf("%w: %q", ErrTenantNotFound, tenantID)
		}
		return nil, fmt.Errorf("failed to get tenant %q: %w", tenantID, err)
	}

	var record TenantRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("failed to deserialise tenant record for %q: %w", tenantID, err)
	}

	return &record, nil
}

// ---------------------------------------------------------------------------
// ListTenants
// ---------------------------------------------------------------------------

// ListTenants returns tenants visible to the caller.
//
// Only callers with the "platform-operator" role receive the full list
// from the index SET (tenants:all).  All other authenticated callers receive
// only the record for their own tenant (extracted from the request context).
//
// Soft-deleted tenants are removed from the index on deletion and therefore do
// not appear in this list.  If a tenant ID appears in the index but its meta
// key is missing (e.g. due to data inconsistency), it is skipped and a warning
// is logged.
func (s *TenantService) ListTenants(ctx context.Context) ([]TenantRecord, error) {
	identity, ok := auth.GibsonIdentityFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "not authenticated")
	}

	if identity.HasRole("platform-operator") {
		// Platform-operators see every tenant in the index.
		ids, err := s.client.SMembers(ctx, tenantIndexKey).Result()
		if err != nil {
			return nil, fmt.Errorf("failed to list tenant IDs from index: %w", err)
		}

		records := make([]TenantRecord, 0, len(ids))
		for _, id := range ids {
			record, err := s.fetchTenant(ctx, id)
			if err != nil {
				if errors.Is(err, ErrTenantNotFound) {
					s.logger.WarnContext(ctx, "tenant index references missing meta key, skipping",
						slog.String("tenant_id", id),
					)
					continue
				}
				return nil, fmt.Errorf("failed to fetch tenant %q during list: %w", id, err)
			}
			records = append(records, *record)
		}
		return records, nil
	}

	// Non-admin, non-platform-operators see only their own tenant.
	callerTenant := auth.TenantFromContext(ctx)
	if callerTenant == "" {
		return nil, status.Error(codes.PermissionDenied, "no tenant context")
	}
	record, err := s.fetchTenant(ctx, callerTenant)
	if err != nil {
		if errors.Is(err, ErrTenantNotFound) {
			return []TenantRecord{}, nil
		}
		return nil, fmt.Errorf("failed to fetch tenant %q during list: %w", callerTenant, err)
	}
	return []TenantRecord{*record}, nil
}

// ---------------------------------------------------------------------------
// UpdateTenant
// ---------------------------------------------------------------------------

// UpdateTenant merges the provided updates map into the tenant's Config and
// DisplayName fields.
//
// Supported update keys:
//   - "display_name": replaces the display name
//   - "status":       updates the status (allowed values: "active", "suspended")
//   - any other key:  merged into the Config map
//
// Returns ErrTenantNotFound when no record exists for tenantID.
func (s *TenantService) UpdateTenant(ctx context.Context, tenantID string, updates map[string]string) (*TenantRecord, error) {
	if err := auth.RequireRole(ctx, "platform-operator"); err != nil {
		return nil, err
	}

	record, err := s.fetchTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	// Merge updates into the record.
	for k, v := range updates {
		switch k {
		case "display_name":
			record.DisplayName = v
		case "status":
			// Guard against accidentally re-activating a deleted tenant via
			// UpdateTenant; hard-deleted status changes go through DeleteTenant.
			if v == "deleted" {
				return nil, fmt.Errorf("use DeleteTenant to set status to %q", v)
			}
			record.Status = v
		case "tier":
			record.Tier = v
		case "owner_email":
			record.OwnerEmail = v
		case "stripe_customer_id":
			record.StripeCustomerID = v
		case "stripe_sub_id":
			record.StripeSubID = v
		case "billing_alert":
			record.BillingAlert = v == "true"
		default:
			if record.Config == nil {
				record.Config = make(map[string]string)
			}
			record.Config[k] = v
		}
	}

	// Write Stripe reverse mapping when stripe_customer_id is set or changed.
	if newCID, ok := updates["stripe_customer_id"]; ok && newCID != "" {
		if err := s.writeStripeReverseMapping(ctx, newCID, tenantID); err != nil {
			s.logger.WarnContext(ctx, "failed to write stripe reverse mapping", "error", err)
		}
	}

	record.UpdatedAt = time.Now().UTC()

	data, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("failed to serialise updated tenant record for %q: %w", tenantID, err)
	}

	if err := s.client.Set(ctx, tenantMetaKey(tenantID), data, 0).Err(); err != nil {
		return nil, fmt.Errorf("failed to persist updated tenant %q: %w", tenantID, err)
	}

	s.logger.InfoContext(ctx, "tenant updated",
		slog.String("tenant_id", tenantID),
	)

	if s.auditLog != nil {
		if err := s.auditLog.Log(ctx, "tenant.update", "tenant", tenantID, nil); err != nil {
			s.logger.WarnContext(ctx, "audit log failed", "error", err)
		}
	}

	return record, nil
}

// ---------------------------------------------------------------------------
// DeleteTenant
// ---------------------------------------------------------------------------

// DeleteTenant soft-deletes a tenant by setting its status to "deleted" and
// removing it from the active index SET.
//
// The meta key (tenant:{tenant_id}:meta) is intentionally retained so that
// audit history is preserved.  Soft-deleted tenants will no longer appear in
// ListTenants results.
//
// Returns ErrTenantNotFound when no record exists for tenantID.
func (s *TenantService) DeleteTenant(ctx context.Context, tenantID string) error {
	if err := auth.RequireRole(ctx, "platform-operator"); err != nil {
		return err
	}

	record, err := s.fetchTenant(ctx, tenantID)
	if err != nil {
		return err
	}

	// Clean up Stripe reverse mapping before soft-deleting.
	if record.StripeCustomerID != "" {
		s.deleteStripeReverseMapping(ctx, record.StripeCustomerID)
	}

	record.Status = "deleted"
	record.UpdatedAt = time.Now().UTC()

	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to serialise deleted tenant record for %q: %w", tenantID, err)
	}

	// Update the meta key and remove from the active index atomically.
	pipe := s.client.Pipeline()
	pipe.Set(ctx, tenantMetaKey(tenantID), data, 0)
	pipe.SRem(ctx, tenantIndexKey, tenantID)
	if _, err = pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to soft-delete tenant %q: %w", tenantID, err)
	}

	s.logger.InfoContext(ctx, "tenant soft-deleted",
		slog.String("tenant_id", tenantID),
	)

	if s.auditLog != nil {
		if err := s.auditLog.Log(ctx, "tenant.delete", "tenant", tenantID, nil); err != nil {
			s.logger.WarnContext(ctx, "audit log failed", "error", err)
		}
	}

	return nil
}

// ---------------------------------------------------------------------------
// GetTenantQuota
// ---------------------------------------------------------------------------

// GetTenantQuota returns the configured resource quota for a tenant.
//
// Callers with the "platform-operator" role may read any tenant's quota.
// All other authenticated callers may only read their own tenant's quota.
//
// Returns nil quota (and no error) when no quota record has been configured
// for the tenant, which should be interpreted as "unlimited on all dimensions".
//
// Returns codes.Unimplemented when no QuotaManager has been attached via
// WithQuotaManager.
func (s *TenantService) GetTenantQuota(ctx context.Context, tenantID string) (*TenantQuota, error) {
	if s.quotaManager == nil {
		return nil, status.Error(codes.Unimplemented, "quota management not configured")
	}

	// Access control: platform-operator can read any tenant; others only their own.
	identity, ok := auth.GibsonIdentityFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "not authenticated")
	}
	if !identity.HasRole("platform-operator") && auth.TenantFromContext(ctx) != tenantID {
		return nil, status.Errorf(codes.PermissionDenied, "missing required role: platform-operator")
	}

	quota, err := s.quotaManager.GetQuota(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("get quota for tenant %q: %w", tenantID, err)
	}

	return quota, nil
}

// ---------------------------------------------------------------------------
// SetTenantQuota
// ---------------------------------------------------------------------------

// SetTenantQuota stores or replaces the resource quota for a tenant.
//
// Requires the "platform-operator" role.  The quota.TenantID field is always
// overwritten with the tenantID parameter to prevent mismatches.
//
// Returns codes.Unimplemented when no QuotaManager has been attached via
// WithQuotaManager.
func (s *TenantService) SetTenantQuota(ctx context.Context, tenantID string, quota *TenantQuota) error {
	if s.quotaManager == nil {
		return status.Error(codes.Unimplemented, "quota management not configured")
	}

	if err := auth.RequireRole(ctx, "platform-operator"); err != nil {
		return err
	}

	if err := s.quotaManager.SetQuota(ctx, tenantID, quota); err != nil {
		return fmt.Errorf("set quota for tenant %q: %w", tenantID, err)
	}

	s.logger.InfoContext(ctx, "tenant quota updated",
		slog.String("tenant_id", tenantID),
	)

	if s.auditLog != nil {
		if err := s.auditLog.Log(ctx, "tenant.quota.set", "tenant", tenantID, nil); err != nil {
			s.logger.WarnContext(ctx, "audit log failed for quota set", "error", err)
		}
	}

	return nil
}

// ---------------------------------------------------------------------------
// Stripe Customer Reverse Lookup
// ---------------------------------------------------------------------------

// stripeCustomerKey returns the Redis key for the Stripe customer → tenant
// reverse mapping.
func stripeCustomerKey(customerID string) string {
	return fmt.Sprintf("stripe_customer:%s", customerID)
}

// writeStripeReverseMapping writes a Redis STRING mapping a Stripe customer ID
// to a tenant ID, enabling O(1) tenant lookups from Stripe webhooks.
func (s *TenantService) writeStripeReverseMapping(ctx context.Context, customerID, tenantID string) error {
	if customerID == "" {
		return nil
	}
	if err := s.client.Set(ctx, stripeCustomerKey(customerID), tenantID, 0).Err(); err != nil {
		return fmt.Errorf("failed to write stripe reverse mapping for %q: %w", customerID, err)
	}
	return nil
}

// deleteStripeReverseMapping removes the reverse mapping for a Stripe customer ID.
func (s *TenantService) deleteStripeReverseMapping(ctx context.Context, customerID string) {
	if customerID == "" {
		return
	}
	if err := s.client.Del(ctx, stripeCustomerKey(customerID)).Err(); err != nil {
		s.logger.WarnContext(ctx, "failed to delete stripe reverse mapping",
			slog.String("customer_id", customerID),
			slog.String("error", err.Error()),
		)
	}
}

// GetTenantByStripeCustomer looks up a tenant by Stripe customer ID using the
// reverse mapping index.  Returns ErrTenantNotFound if no mapping exists.
func (s *TenantService) GetTenantByStripeCustomer(ctx context.Context, customerID string) (*TenantRecord, error) {
	if customerID == "" {
		return nil, fmt.Errorf("%w: empty stripe customer ID", ErrTenantNotFound)
	}

	tenantID, err := s.client.Get(ctx, stripeCustomerKey(customerID)).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, fmt.Errorf("%w: no tenant for stripe customer %q", ErrTenantNotFound, customerID)
		}
		return nil, fmt.Errorf("failed to lookup stripe customer %q: %w", customerID, err)
	}

	return s.fetchTenant(ctx, tenantID)
}

