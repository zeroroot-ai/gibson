// Package target provides the tenant-scoped, UUID-canonical target service.
//
// A Target is identified solely by its UUID; the name and all other fields are
// metadata. Nothing resolves targets by name. The service mints the UUID on
// create and enforces tenant isolation on every read and mutation.
//
// Tenant scoping is applied in this service layer rather than via per-tenant
// storage because the target RediSearch index lives on the global state client
// (per-tenant Redis DBs deliberately avoid FT search). Each target carries its
// owning TenantID; reads filter on it and cross-tenant access is reported as
// not-found.
package target

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/zeroroot-ai/gibson/internal/types"
)

// fetchLimit bounds how many targets the service pulls from the global store
// before applying tenant filtering and caller pagination in memory. Target
// counts per deployment are small; this is a safety ceiling, not a page size.
const fetchLimit = 10000

var (
	// ErrNotFound is returned when no target with the given id exists for the
	// caller's tenant (including cross-tenant access attempts).
	ErrNotFound = errors.New("target not found")
	// ErrInvalidID is returned when the supplied id is not a valid UUID.
	ErrInvalidID = errors.New("invalid target id")
	// ErrTenantRequired is returned when no tenant is present in the call.
	ErrTenantRequired = errors.New("tenant is required")
	// ErrTargetRequired is returned when a nil target is supplied.
	ErrTargetRequired = errors.New("target is required")
)

// Store is the persistence surface the Service drives. It is satisfied by
// *dbredis.RedisTargetDAO. Kept narrow so the Service is unit-testable with a
// fake.
type Store interface {
	Create(ctx context.Context, t *types.Target) error
	Get(ctx context.Context, id types.ID) (*types.Target, error)
	List(ctx context.Context, filter *types.TargetFilter) ([]*types.Target, error)
	Update(ctx context.Context, t *types.Target) error
	Delete(ctx context.Context, id types.ID) error
}

// Service enforces UUID-canonical identity and tenant isolation over a target
// Store.
type Service struct {
	store Store
}

// NewService builds a target Service over the given store.
func NewService(store Store) *Service { return &Service{store: store} }

// Create mints a fresh UUID for the target, stamps it with the caller's tenant,
// persists it, and returns the stored target. Any id supplied on the input is
// ignored — the UUID is server-assigned.
func (s *Service) Create(ctx context.Context, tenantID string, t *types.Target) (*types.Target, error) {
	if tenantID == "" {
		return nil, ErrTenantRequired
	}
	if t == nil {
		return nil, ErrTargetRequired
	}
	t.ID = types.NewID()
	t.TenantID = tenantID
	applyTargetDefaults(t)
	now := time.Now()
	if t.CreatedAt.IsZero() {
		t.CreatedAt = now
	}
	t.UpdatedAt = now
	if err := s.store.Create(ctx, t); err != nil {
		return nil, fmt.Errorf("create target: %w", err)
	}
	return t, nil
}

// applyTargetDefaults fills the fields the daemon's Target.Validate requires but
// that a metadata-only caller (dashboard form, CLI, mission pre-step) may omit:
// a non-empty type, an active status, and a Connection populated from a bare URL.
// Without these, validation rejects every create with a cryptic error.
func applyTargetDefaults(t *types.Target) {
	if strings.TrimSpace(t.Type) == "" {
		t.Type = string(types.TargetTypeCustom)
	}
	if t.Status == "" {
		t.Status = types.TargetStatusActive
	}
	if len(t.Connection) == 0 && strings.TrimSpace(t.URL) != "" {
		t.Connection = map[string]any{"url": t.URL}
	}
}

// Get returns the target with the given UUID, provided it belongs to the
// caller's tenant. A non-UUID id yields ErrInvalidID; a missing or
// cross-tenant target yields ErrNotFound.
func (s *Service) Get(ctx context.Context, tenantID, id string) (*types.Target, error) {
	if tenantID == "" {
		return nil, ErrTenantRequired
	}
	parsed, err := types.ParseID(id)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidID, err)
	}
	t, err := s.store.Get(ctx, parsed)
	if err != nil {
		return nil, fmt.Errorf("get target: %w", err)
	}
	if t == nil || t.TenantID != tenantID {
		return nil, ErrNotFound
	}
	return t, nil
}

// List returns the caller's tenant's targets matching the filter. Tenant
// filtering is applied before the caller's limit/offset so pagination never
// drops a tenant's targets behind another tenant's.
func (s *Service) List(ctx context.Context, tenantID string, filter *types.TargetFilter) ([]*types.Target, error) {
	if tenantID == "" {
		return nil, ErrTenantRequired
	}

	limit, offset := 0, 0
	daoFilter := &types.TargetFilter{Limit: fetchLimit}
	if filter != nil {
		daoFilter.Provider = filter.Provider
		daoFilter.Type = filter.Type
		daoFilter.Status = filter.Status
		daoFilter.Tags = filter.Tags
		limit, offset = filter.Limit, filter.Offset
	}

	all, err := s.store.List(ctx, daoFilter)
	if err != nil {
		return nil, fmt.Errorf("list targets: %w", err)
	}

	scoped := make([]*types.Target, 0, len(all))
	for _, t := range all {
		if t != nil && t.TenantID == tenantID {
			scoped = append(scoped, t)
		}
	}

	if offset > 0 {
		if offset >= len(scoped) {
			return []*types.Target{}, nil
		}
		scoped = scoped[offset:]
	}
	if limit > 0 && limit < len(scoped) {
		scoped = scoped[:limit]
	}
	return scoped, nil
}

// Update replaces a target's metadata. The UUID is the lookup key and is never
// changed; ownership (TenantID) and creation time are preserved. A missing or
// cross-tenant target yields ErrNotFound.
func (s *Service) Update(ctx context.Context, tenantID string, t *types.Target) (*types.Target, error) {
	if tenantID == "" {
		return nil, ErrTenantRequired
	}
	if t == nil {
		return nil, ErrTargetRequired
	}
	existing, err := s.Get(ctx, tenantID, t.ID.String())
	if err != nil {
		return nil, err
	}
	t.ID = existing.ID
	t.TenantID = existing.TenantID
	t.CreatedAt = existing.CreatedAt
	applyTargetDefaults(t)
	t.UpdatedAt = time.Now()
	if err := s.store.Update(ctx, t); err != nil {
		return nil, fmt.Errorf("update target: %w", err)
	}
	return t, nil
}

// Delete removes the target with the given UUID, provided it belongs to the
// caller's tenant. A missing or cross-tenant target yields ErrNotFound.
func (s *Service) Delete(ctx context.Context, tenantID, id string) error {
	if tenantID == "" {
		return ErrTenantRequired
	}
	existing, err := s.Get(ctx, tenantID, id)
	if err != nil {
		return err
	}
	if err := s.store.Delete(ctx, existing.ID); err != nil {
		return fmt.Errorf("delete target: %w", err)
	}
	return nil
}
