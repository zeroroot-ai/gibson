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
	// Status is one of "active", "suspended", or "deleted".
	Status      string            `json:"status"`
	Config      map[string]string `json:"config"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
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
// Role checking is stubbed with TODO comments — actual enforcement will be
// added once the authorization layer (roles + context) is wired in.
type TenantService struct {
	client *redis.Client
	logger *slog.Logger
}

// NewTenantService constructs a TenantService backed by the provided Redis
// client.  Both parameters must be non-nil; if logger is nil slog.Default()
// is used as a safe fallback.
func NewTenantService(client *redis.Client, logger *slog.Logger) *TenantService {
	if client == nil {
		panic("component.NewTenantService: client must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &TenantService{
		client: client,
		logger: logger,
	}
}

// ---------------------------------------------------------------------------
// CreateTenant
// ---------------------------------------------------------------------------

// CreateTenant registers a new tenant with the given ID and display name.
//
// The tenantID must be URL-safe: only alphanumeric characters and hyphens are
// allowed.  Returns ErrTenantAlreadyExists if the ID is already taken.
//
// TODO: enforce admin role — check caller roles from context before proceeding.
func (s *TenantService) CreateTenant(ctx context.Context, tenantID, displayName string, config map[string]string) (*TenantRecord, error) {
	// TODO: role check — verify ctx carries an admin role before continuing.

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

	s.logger.InfoContext(ctx, "tenant created",
		slog.String("tenant_id", tenantID),
		slog.String("display_name", displayName),
	)

	return record, nil
}

// ---------------------------------------------------------------------------
// GetTenant
// ---------------------------------------------------------------------------

// GetTenant retrieves a tenant record by ID.
//
// Returns ErrTenantNotFound when no record exists for the given ID.
//
// TODO: role check — verify ctx carries an admin role before continuing.
func (s *TenantService) GetTenant(ctx context.Context, tenantID string) (*TenantRecord, error) {
	// TODO: role check — verify ctx carries an admin role before continuing.

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

// ListTenants returns all tenants present in the index SET (tenants:all).
//
// Soft-deleted tenants are removed from the index on deletion and therefore do
// not appear in this list.  If a tenant ID appears in the index but its meta
// key is missing (e.g. due to data inconsistency), it is skipped and a warning
// is logged.
//
// TODO: role check — verify ctx carries an admin role before continuing.
func (s *TenantService) ListTenants(ctx context.Context) ([]TenantRecord, error) {
	// TODO: role check — verify ctx carries an admin role before continuing.

	ids, err := s.client.SMembers(ctx, tenantIndexKey).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to list tenant IDs from index: %w", err)
	}

	records := make([]TenantRecord, 0, len(ids))
	for _, id := range ids {
		record, err := s.GetTenant(ctx, id)
		if err != nil {
			if errors.Is(err, ErrTenantNotFound) {
				// Index entry exists but meta key is missing — data inconsistency;
				// log a warning and skip rather than failing the entire list.
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
//
// TODO: role check — verify ctx carries an admin role before continuing.
func (s *TenantService) UpdateTenant(ctx context.Context, tenantID string, updates map[string]string) (*TenantRecord, error) {
	// TODO: role check — verify ctx carries an admin role before continuing.

	record, err := s.GetTenant(ctx, tenantID)
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
		default:
			if record.Config == nil {
				record.Config = make(map[string]string)
			}
			record.Config[k] = v
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
//
// TODO: role check — verify ctx carries an admin role before continuing.
func (s *TenantService) DeleteTenant(ctx context.Context, tenantID string) error {
	// TODO: role check — verify ctx carries an admin role before continuing.

	record, err := s.GetTenant(ctx, tenantID)
	if err != nil {
		return err
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

	return nil
}
