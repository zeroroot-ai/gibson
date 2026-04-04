// Package membership manages user-to-tenant membership records with role hierarchy
// and optional Casbin policy synchronization.
//
// Redis key layout:
//
//	membership:{tenantID}:{userID}  →  JSON-encoded Membership
//	user-tenants:{userID}           →  Redis SET of tenant IDs (reverse index)
//
// Casbin sync is best-effort: errors are logged but do not cause mutating
// operations to fail, because Redis is the source of truth for membership state.
package membership

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/redis/go-redis/v9"
)

// Sentinel errors returned by RedisMembershipStore operations.
var (
	ErrMemberNotFound    = errors.New("member not found in tenant")
	ErrAlreadyMember     = errors.New("user is already a member of this tenant")
	ErrInvalidRole       = errors.New("invalid role")
	ErrRoleHierarchy     = errors.New("cannot assign role higher than your own")
	ErrNotOwner          = errors.New("only the owner can perform this action")
	ErrCannotRemoveOwner = errors.New("cannot remove the tenant owner")
)

// Membership records a single user's membership in a tenant, including the role
// they hold and audit fields that capture who added them and when.
type Membership struct {
	TenantID string    `json:"tenant_id"`
	UserID   string    `json:"user_id"`
	Email    string    `json:"email"`
	Role     string    `json:"role"`    // one of: owner, admin, operator, viewer
	AddedAt  time.Time `json:"added_at"`
	AddedBy  string    `json:"added_by"`
}

// roleLevels maps each role name to a numeric privilege level.
// Lower numbers represent higher privilege — owner(0) outranks admin(1), and so on.
var roleLevels = map[string]int{
	"owner":    0,
	"admin":    1,
	"operator": 2,
	"viewer":   3,
}

// RoleLevel returns the numeric privilege level for a role name.
// Returns -1 for any unrecognised role name.
func RoleLevel(role string) int {
	if level, ok := roleLevels[role]; ok {
		return level
	}
	return -1
}

// IsValidRole reports whether role is one of the four recognised role names.
func IsValidRole(role string) bool {
	return RoleLevel(role) >= 0
}

// CanAssignRole reports whether a user holding assignerRole is permitted to
// grant targetRole to another user.
//
// The rule is: an assigner may only assign roles at an equal or lower privilege
// level than their own (i.e. equal or larger numeric level).
//
//	owner(0)    can assign owner, admin, operator, viewer
//	admin(1)    can assign admin, operator, viewer
//	operator(2) can assign operator, viewer
//	viewer(3)   can assign viewer only
func CanAssignRole(assignerRole, targetRole string) bool {
	a, t := RoleLevel(assignerRole), RoleLevel(targetRole)
	if a < 0 || t < 0 {
		return false
	}
	return a <= t
}

// MembershipStore is the domain interface for managing user-to-tenant membership.
type MembershipStore interface {
	// AddMember adds a user to a tenant with the given role.
	// Returns ErrAlreadyMember if the user is already a member.
	// Returns ErrInvalidRole if role is not a recognised role name.
	AddMember(ctx context.Context, tenantID, userID, email, role, addedBy string) error

	// RemoveMember removes a user from a tenant.
	// Returns ErrMemberNotFound if the user is not a member.
	// Returns ErrCannotRemoveOwner if the user holds the owner role.
	RemoveMember(ctx context.Context, tenantID, userID string) error

	// UpdateRole changes an existing member's role.
	// Returns ErrMemberNotFound if the user is not a member.
	// Returns ErrInvalidRole if newRole is not a recognised role name.
	UpdateRole(ctx context.Context, tenantID, userID, newRole, changedBy string) error

	// GetMember returns the membership record for a specific user in a tenant.
	// Returns ErrMemberNotFound if no membership record exists.
	GetMember(ctx context.Context, tenantID, userID string) (*Membership, error)

	// ListTenantMembers returns all membership records for a tenant.
	ListTenantMembers(ctx context.Context, tenantID string) ([]Membership, error)

	// ListUserTenants returns all tenants the user belongs to.
	ListUserTenants(ctx context.Context, userID string) ([]Membership, error)

	// TransferOwnership atomically demotes fromUserID to admin and promotes
	// toUserID to owner within the same tenant.
	// Returns ErrNotOwner if fromUserID is not the current owner.
	// Returns ErrMemberNotFound if toUserID is not a member of the tenant.
	TransferOwnership(ctx context.Context, tenantID, fromUserID, toUserID, changedBy string) error
}

// RedisMembershipStore is the Redis-backed implementation of MembershipStore.
//
// All membership records are stored as JSON blobs keyed by
// "membership:{tenantID}:{userID}". A reverse index at
// "user-tenants:{userID}" (a Redis SET) allows efficient lookup of all
// tenants a user belongs to without a full SCAN.
//
// An optional Casbin enforcer may be registered via SetEnforcer; when present
// every mutating operation syncs the corresponding grouping policies.
// Casbin sync failures are logged but do not propagate as errors.
type RedisMembershipStore struct {
	client   *redis.Client
	logger   *slog.Logger
	enforcer *casbin.Enforcer // optional; nil disables sync
}

// NewRedisMembershipStore constructs a RedisMembershipStore.
// Both parameters are required.
func NewRedisMembershipStore(client *redis.Client, logger *slog.Logger) *RedisMembershipStore {
	return &RedisMembershipStore{
		client: client,
		logger: logger,
	}
}

// SetEnforcer wires an optional Casbin enforcer for policy synchronization.
// Call this after construction if Casbin is available in the runtime environment.
func (s *RedisMembershipStore) SetEnforcer(e *casbin.Enforcer) {
	s.enforcer = e
}

// GetEnforcer returns the Casbin enforcer attached to this store, or nil if
// none has been set. Used by callers that need to run Casbin operations
// (e.g. BootstrapTenantRoles) without taking a separate enforcer dependency.
func (s *RedisMembershipStore) GetEnforcer() *casbin.Enforcer {
	return s.enforcer
}

// membershipKey returns the Redis key for a specific membership record.
func membershipKey(tenantID, userID string) string {
	return fmt.Sprintf("membership:%s:%s", tenantID, userID)
}

// userTenantsKey returns the Redis key for the reverse-index SET for a user.
func userTenantsKey(userID string) string {
	return fmt.Sprintf("user-tenants:%s", userID)
}

// membershipScanPattern returns the SCAN pattern for all members of a tenant.
func membershipScanPattern(tenantID string) string {
	return fmt.Sprintf("membership:%s:*", tenantID)
}

// marshal encodes a Membership to JSON.
func marshal(m *Membership) (string, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("membership: failed to marshal record: %w", err)
	}
	return string(b), nil
}

// unmarshal decodes a Membership from a JSON string.
func unmarshal(data string) (*Membership, error) {
	var m Membership
	if err := json.Unmarshal([]byte(data), &m); err != nil {
		return nil, fmt.Errorf("membership: failed to unmarshal record: %w", err)
	}
	return &m, nil
}

// AddMember adds a user to a tenant with the specified role.
//
// The operation is atomic at the Redis level via a pipeline. Casbin sync
// runs after the pipeline succeeds; a sync error is logged but not returned.
func (s *RedisMembershipStore) AddMember(ctx context.Context, tenantID, userID, email, role, addedBy string) error {
	if !IsValidRole(role) {
		return fmt.Errorf("%w: %q", ErrInvalidRole, role)
	}

	mKey := membershipKey(tenantID, userID)

	// Check for existing membership.
	existing, err := s.client.Get(ctx, mKey).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return fmt.Errorf("membership: failed to check existing member: %w", err)
	}
	if existing != "" {
		return ErrAlreadyMember
	}

	m := &Membership{
		TenantID: tenantID,
		UserID:   userID,
		Email:    email,
		Role:     role,
		AddedAt:  time.Now().UTC(),
		AddedBy:  addedBy,
	}

	payload, err := marshal(m)
	if err != nil {
		return err
	}

	pipe := s.client.Pipeline()
	pipe.Set(ctx, mKey, payload, 0)
	pipe.SAdd(ctx, userTenantsKey(userID), tenantID)

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("membership: failed to persist member: %w", err)
	}

	s.logger.Info("membership: added member",
		"tenant_id", tenantID,
		"user_id", userID,
		"role", role,
		"added_by", addedBy,
	)

	s.casbinAddGrouping(userID, role, tenantID)
	return nil
}

// RemoveMember removes a user from a tenant.
//
// The owner cannot be removed — callers must first transfer ownership before
// removing the current owner.
func (s *RedisMembershipStore) RemoveMember(ctx context.Context, tenantID, userID string) error {
	mKey := membershipKey(tenantID, userID)

	data, err := s.client.Get(ctx, mKey).Result()
	if errors.Is(err, redis.Nil) {
		return ErrMemberNotFound
	}
	if err != nil {
		return fmt.Errorf("membership: failed to fetch member: %w", err)
	}

	m, err := unmarshal(data)
	if err != nil {
		return err
	}

	if m.Role == "owner" {
		return ErrCannotRemoveOwner
	}

	pipe := s.client.Pipeline()
	pipe.Del(ctx, mKey)
	pipe.SRem(ctx, userTenantsKey(userID), tenantID)

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("membership: failed to remove member: %w", err)
	}

	s.logger.Info("membership: removed member",
		"tenant_id", tenantID,
		"user_id", userID,
	)

	s.casbinRemoveGrouping(userID, tenantID)
	return nil
}

// UpdateRole changes the role of an existing member within a tenant.
func (s *RedisMembershipStore) UpdateRole(ctx context.Context, tenantID, userID, newRole, changedBy string) error {
	if !IsValidRole(newRole) {
		return fmt.Errorf("%w: %q", ErrInvalidRole, newRole)
	}

	mKey := membershipKey(tenantID, userID)

	data, err := s.client.Get(ctx, mKey).Result()
	if errors.Is(err, redis.Nil) {
		return ErrMemberNotFound
	}
	if err != nil {
		return fmt.Errorf("membership: failed to fetch member: %w", err)
	}

	m, err := unmarshal(data)
	if err != nil {
		return err
	}

	oldRole := m.Role
	m.Role = newRole

	payload, err := marshal(m)
	if err != nil {
		return err
	}

	if err := s.client.Set(ctx, mKey, payload, 0).Err(); err != nil {
		return fmt.Errorf("membership: failed to update role: %w", err)
	}

	s.logger.Info("membership: updated role",
		"tenant_id", tenantID,
		"user_id", userID,
		"old_role", oldRole,
		"new_role", newRole,
		"changed_by", changedBy,
	)

	// Sync Casbin: remove old grouping, add new one.
	s.casbinRemoveGrouping(userID, tenantID)
	s.casbinAddGrouping(userID, newRole, tenantID)
	return nil
}

// GetMember retrieves the membership record for a single user within a tenant.
func (s *RedisMembershipStore) GetMember(ctx context.Context, tenantID, userID string) (*Membership, error) {
	data, err := s.client.Get(ctx, membershipKey(tenantID, userID)).Result()
	if errors.Is(err, redis.Nil) {
		return nil, ErrMemberNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("membership: failed to fetch member: %w", err)
	}

	return unmarshal(data)
}

// ListTenantMembers returns all membership records for a tenant by scanning
// the "membership:{tenantID}:*" key space and fetching each record.
func (s *RedisMembershipStore) ListTenantMembers(ctx context.Context, tenantID string) ([]Membership, error) {
	var members []Membership
	var cursor uint64

	for {
		keys, nextCursor, err := s.client.Scan(ctx, cursor, membershipScanPattern(tenantID), 100).Result()
		if err != nil {
			return nil, fmt.Errorf("membership: scan failed for tenant %q: %w", tenantID, err)
		}

		for _, key := range keys {
			data, err := s.client.Get(ctx, key).Result()
			if errors.Is(err, redis.Nil) {
				// Key disappeared between SCAN and GET — skip.
				continue
			}
			if err != nil {
				return nil, fmt.Errorf("membership: failed to fetch record %q: %w", key, err)
			}

			m, err := unmarshal(data)
			if err != nil {
				s.logger.Warn("membership: skipping unparseable record",
					"key", key,
					"error", err,
				)
				continue
			}
			members = append(members, *m)
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	return members, nil
}

// ListUserTenants returns all tenants a user belongs to by reading the
// "user-tenants:{userID}" reverse-index SET, then fetching each membership record.
func (s *RedisMembershipStore) ListUserTenants(ctx context.Context, userID string) ([]Membership, error) {
	tenantIDs, err := s.client.SMembers(ctx, userTenantsKey(userID)).Result()
	if err != nil {
		return nil, fmt.Errorf("membership: failed to list tenants for user %q: %w", userID, err)
	}

	members := make([]Membership, 0, len(tenantIDs))

	for _, tenantID := range tenantIDs {
		data, err := s.client.Get(ctx, membershipKey(tenantID, userID)).Result()
		if errors.Is(err, redis.Nil) {
			// Index is stale — membership was deleted without cleaning the index.
			s.logger.Warn("membership: stale user-tenants index entry",
				"user_id", userID,
				"tenant_id", tenantID,
			)
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("membership: failed to fetch record for tenant %q: %w", tenantID, err)
		}

		m, err := unmarshal(data)
		if err != nil {
			s.logger.Warn("membership: skipping unparseable record",
				"user_id", userID,
				"tenant_id", tenantID,
				"error", err,
			)
			continue
		}
		members = append(members, *m)
	}

	return members, nil
}

// TransferOwnership atomically demotes fromUserID to admin and promotes toUserID
// to owner within a tenant.
//
// The operation uses a Redis pipeline so both role updates succeed or fail
// together. Casbin groupings for both users are updated after the pipeline
// completes successfully.
func (s *RedisMembershipStore) TransferOwnership(ctx context.Context, tenantID, fromUserID, toUserID, changedBy string) error {
	// Validate fromUser is current owner.
	fromData, err := s.client.Get(ctx, membershipKey(tenantID, fromUserID)).Result()
	if errors.Is(err, redis.Nil) {
		return ErrMemberNotFound
	}
	if err != nil {
		return fmt.Errorf("membership: failed to fetch from-user record: %w", err)
	}

	fromMember, err := unmarshal(fromData)
	if err != nil {
		return err
	}
	if fromMember.Role != "owner" {
		return ErrNotOwner
	}

	// Validate toUser is an existing member.
	toData, err := s.client.Get(ctx, membershipKey(tenantID, toUserID)).Result()
	if errors.Is(err, redis.Nil) {
		return ErrMemberNotFound
	}
	if err != nil {
		return fmt.Errorf("membership: failed to fetch to-user record: %w", err)
	}

	toMember, err := unmarshal(toData)
	if err != nil {
		return err
	}

	// Prepare updated records.
	fromMember.Role = "admin"
	toMember.Role = "owner"

	fromPayload, err := marshal(fromMember)
	if err != nil {
		return err
	}
	toPayload, err := marshal(toMember)
	if err != nil {
		return err
	}

	pipe := s.client.Pipeline()
	pipe.Set(ctx, membershipKey(tenantID, fromUserID), fromPayload, 0)
	pipe.Set(ctx, membershipKey(tenantID, toUserID), toPayload, 0)

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("membership: failed to transfer ownership: %w", err)
	}

	s.logger.Info("membership: ownership transferred",
		"tenant_id", tenantID,
		"from_user_id", fromUserID,
		"to_user_id", toUserID,
		"changed_by", changedBy,
	)

	// Sync Casbin for both users.
	s.casbinRemoveGrouping(fromUserID, tenantID)
	s.casbinAddGrouping(fromUserID, "admin", tenantID)
	s.casbinRemoveGrouping(toUserID, tenantID)
	s.casbinAddGrouping(toUserID, "owner", tenantID)

	return nil
}

// casbinAddGrouping adds a user-to-role grouping policy in Casbin.
// Errors are logged but not propagated — Redis is the source of truth.
func (s *RedisMembershipStore) casbinAddGrouping(userID, role, tenantID string) {
	if s.enforcer == nil {
		return
	}
	if _, err := s.enforcer.AddGroupingPolicy(userID, role, tenantID); err != nil {
		s.logger.Warn("membership: casbin AddGroupingPolicy failed (non-fatal)",
			"user_id", userID,
			"role", role,
			"tenant_id", tenantID,
			"error", err,
		)
	}
}

// casbinRemoveGrouping removes all grouping policies for a user in a tenant.
// Field index 0 is the subject (userID), field index 2 is the domain (tenantID).
// Errors are logged but not propagated.
func (s *RedisMembershipStore) casbinRemoveGrouping(userID, tenantID string) {
	if s.enforcer == nil {
		return
	}
	// RemoveFilteredGroupingPolicy(fieldIndex, fieldValues...)
	// We match on field 0 (userID) and field 2 (tenantID), leaving field 1 (role) as wildcard.
	if _, err := s.enforcer.RemoveFilteredGroupingPolicy(0, userID, "", tenantID); err != nil {
		s.logger.Warn("membership: casbin RemoveFilteredGroupingPolicy failed (non-fatal)",
			"user_id", userID,
			"tenant_id", tenantID,
			"error", err,
		)
	}
}
