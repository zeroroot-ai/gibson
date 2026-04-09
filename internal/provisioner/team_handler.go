// Package provisioner — team_handler.go
//
// TeamHandler manages team CRUD within a tenant. Teams are an optional
// subdivision of a tenant for grouping users and controlling data crosstalk.
//
// Storage split:
//   - Team metadata (name, description, created_at, created_by) is stored in
//     Redis under key "team:{tenant_id}:{team_id}" as JSON.
//   - A Redis SET at "team-list:{tenant_id}" indexes all team IDs for fast listing.
//   - Team relationships (parent tenant, memberships, crosstalk) are stored in FGA.
//
// FGA tuple shapes written by this handler:
//
//	team:{team_id}   parent    tenant:{tenant_id}   (on Create)
//	user:{user_id}   member    team:{team_id}        (on AddMember)
//	team:{a}         can_view_data_from team:{b}      (on SetCrosstalk enabled=true)
//
// All mutations emit structured audit log entries with event_type fields.
package provisioner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/zero-day-ai/gibson/internal/authz"
)

// ---------------------------------------------------------------------------
// Sentinel errors
// ---------------------------------------------------------------------------

var (
	// ErrTeamNotFound is returned when the specified team does not exist.
	ErrTeamNotFound = errors.New("team: not found")

	// ErrUserNotTenantMember is returned when AddMember is called for a user
	// who is not yet a member of the parent tenant.
	ErrUserNotTenantMember = errors.New("team: user must be a tenant member before joining a team")
)

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// TeamRecord is the JSON payload stored in Redis for team metadata.
type TeamRecord struct {
	TeamID      string    `json:"team_id"`
	TenantID    string    `json:"tenant_id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   string    `json:"created_by"`
}

// ---------------------------------------------------------------------------
// TeamHandler
// ---------------------------------------------------------------------------

// TeamHandler manages team lifecycle within a tenant.
// It is safe for concurrent use.
type TeamHandler struct {
	authz  authz.Authorizer
	redis  *redis.Client
	logger *slog.Logger
}

// NewTeamHandler constructs a TeamHandler.
func NewTeamHandler(az authz.Authorizer, redisClient *redis.Client, logger *slog.Logger) (*TeamHandler, error) {
	if az == nil {
		return nil, fmt.Errorf("team_handler: Authorizer is required")
	}
	if redisClient == nil {
		return nil, fmt.Errorf("team_handler: Redis client is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &TeamHandler{
		authz:  az,
		redis:  redisClient,
		logger: logger.With("component", "provisioner.team_handler"),
	}, nil
}

// Create creates a new team within a tenant.
// It generates a team ID (slugified name + timestamp suffix), stores metadata
// in Redis, and writes the FGA parent tuple.
func (h *TeamHandler) Create(ctx context.Context, tenantID, name, description, createdBy string) (*TeamRecord, error) {
	if tenantID == "" || name == "" {
		return nil, fmt.Errorf("%w: tenant_id and name are required", ErrInvalidSignupInput)
	}

	teamID := slugifyTeamName(name) + "-" + fmt.Sprintf("%x", time.Now().UnixNano()&0xFFFFFF)

	rec := &TeamRecord{
		TeamID:      teamID,
		TenantID:    tenantID,
		Name:        name,
		Description: description,
		CreatedAt:   time.Now().UTC(),
		CreatedBy:   createdBy,
	}

	// Store metadata in Redis.
	recJSON, err := json.Marshal(rec)
	if err != nil {
		return nil, fmt.Errorf("team create: marshal record: %w", err)
	}
	metaKey := teamMetaKey(tenantID, teamID)
	if err := h.redis.Set(ctx, metaKey, recJSON, 0).Err(); err != nil {
		return nil, fmt.Errorf("team create: store metadata: %w", err)
	}

	// Add to the tenant's team-list index.
	listKey := teamListKey(tenantID)
	if err := h.redis.SAdd(ctx, listKey, teamID).Err(); err != nil {
		// Non-fatal for the create but log it.
		h.logger.WarnContext(ctx, "team create: failed to update team-list index",
			slog.String("tenant_id", tenantID), slog.String("team_id", teamID), slog.String("error", err.Error()))
	}

	// Write FGA parent tuple: team:{team_id} parent tenant:{tenant_id}
	tuple := authz.Tuple{
		User:     fmt.Sprintf("team:%s", teamID),
		Relation: "parent",
		Object:   fmt.Sprintf("tenant:%s", tenantID),
	}
	if err := h.authz.Write(ctx, []authz.Tuple{tuple}); err != nil {
		// Rollback Redis entries on FGA failure.
		_ = h.redis.Del(ctx, metaKey).Err()
		_ = h.redis.SRem(ctx, listKey, teamID).Err()
		return nil, fmt.Errorf("team create: write FGA parent tuple: %w", err)
	}

	h.logger.InfoContext(ctx, "team created",
		slog.String("tenant_id", tenantID),
		slog.String("team_id", teamID),
		slog.String("name", name),
		slog.String("created_by", createdBy),
		slog.String("event_type", "team_created"),
	)

	return rec, nil
}

// List returns all teams within a tenant by reading the team-list Redis index.
func (h *TeamHandler) List(ctx context.Context, tenantID string) ([]TeamRecord, error) {
	listKey := teamListKey(tenantID)
	teamIDs, err := h.redis.SMembers(ctx, listKey).Result()
	if err != nil {
		return nil, fmt.Errorf("team list: read index: %w", err)
	}

	teams := make([]TeamRecord, 0, len(teamIDs))
	for _, teamID := range teamIDs {
		metaKey := teamMetaKey(tenantID, teamID)
		raw, err := h.redis.Get(ctx, metaKey).Bytes()
		if err != nil {
			if errors.Is(err, redis.Nil) {
				// Index entry exists but metadata is gone — skip.
				continue
			}
			return nil, fmt.Errorf("team list: read metadata for %s: %w", teamID, err)
		}
		var rec TeamRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			return nil, fmt.Errorf("team list: unmarshal metadata for %s: %w", teamID, err)
		}
		teams = append(teams, rec)
	}
	return teams, nil
}

// Delete removes a team: deletes FGA tuples, Redis metadata, and the index entry.
func (h *TeamHandler) Delete(ctx context.Context, tenantID, teamID string) error {
	if tenantID == "" || teamID == "" {
		return fmt.Errorf("%w: tenant_id and team_id are required", ErrInvalidSignupInput)
	}

	// Delete the FGA parent tuple.
	tuple := authz.Tuple{
		User:     fmt.Sprintf("team:%s", teamID),
		Relation: "parent",
		Object:   fmt.Sprintf("tenant:%s", tenantID),
	}
	if err := h.authz.Delete(ctx, []authz.Tuple{tuple}); err != nil {
		return fmt.Errorf("team delete: delete FGA parent tuple: %w", err)
	}

	// Remove Redis metadata and index entry.
	_ = h.redis.Del(ctx, teamMetaKey(tenantID, teamID)).Err()
	_ = h.redis.SRem(ctx, teamListKey(tenantID), teamID).Err()

	h.logger.InfoContext(ctx, "team deleted",
		slog.String("tenant_id", tenantID),
		slog.String("team_id", teamID),
		slog.String("event_type", "team_deleted"),
	)
	return nil
}

// AddMember adds a user to a team.
// The user must already be a member of the parent tenant (verified via FGA Check).
func (h *TeamHandler) AddMember(ctx context.Context, tenantID, teamID, userID string) error {
	if tenantID == "" || teamID == "" || userID == "" {
		return fmt.Errorf("%w: tenant_id, team_id, and user_id are required", ErrInvalidSignupInput)
	}

	// Verify the user is a member of the parent tenant first.
	isMember, err := h.authz.Check(ctx,
		fmt.Sprintf("user:%s", userID),
		"member",
		fmt.Sprintf("tenant:%s", tenantID),
	)
	if err != nil {
		return fmt.Errorf("team add_member: check tenant membership: %w", err)
	}
	if !isMember {
		return fmt.Errorf("%w: user %s is not a member of tenant %s", ErrUserNotTenantMember, userID, tenantID)
	}

	tuple := authz.Tuple{
		User:     fmt.Sprintf("user:%s", userID),
		Relation: "member",
		Object:   fmt.Sprintf("team:%s", teamID),
	}
	if err := h.authz.Write(ctx, []authz.Tuple{tuple}); err != nil {
		return fmt.Errorf("team add_member: write FGA tuple: %w", err)
	}

	h.logger.InfoContext(ctx, "team member added",
		slog.String("tenant_id", tenantID),
		slog.String("team_id", teamID),
		slog.String("user_id", userID),
		slog.String("event_type", "team_member_added"),
	)
	return nil
}

// RemoveMember removes a user from a team.
func (h *TeamHandler) RemoveMember(ctx context.Context, tenantID, teamID, userID string) error {
	if tenantID == "" || teamID == "" || userID == "" {
		return fmt.Errorf("%w: tenant_id, team_id, and user_id are required", ErrInvalidSignupInput)
	}

	tuple := authz.Tuple{
		User:     fmt.Sprintf("user:%s", userID),
		Relation: "member",
		Object:   fmt.Sprintf("team:%s", teamID),
	}
	if err := h.authz.Delete(ctx, []authz.Tuple{tuple}); err != nil {
		return fmt.Errorf("team remove_member: delete FGA tuple: %w", err)
	}

	h.logger.InfoContext(ctx, "team member removed",
		slog.String("tenant_id", tenantID),
		slog.String("team_id", teamID),
		slog.String("user_id", userID),
		slog.String("event_type", "team_member_removed"),
	)
	return nil
}

// SetCrosstalk sets or clears the can_view_data_from relationship from fromTeamID to toTeamID.
// When enabled=true, writes the tuple; when enabled=false, deletes it.
func (h *TeamHandler) SetCrosstalk(ctx context.Context, tenantID, fromTeamID, toTeamID string, enabled bool) error {
	if tenantID == "" || fromTeamID == "" || toTeamID == "" {
		return fmt.Errorf("%w: tenant_id, from_team_id, and to_team_id are required", ErrInvalidSignupInput)
	}

	tuple := authz.Tuple{
		User:     fmt.Sprintf("team:%s", fromTeamID),
		Relation: "can_view_data_from",
		Object:   fmt.Sprintf("team:%s", toTeamID),
	}

	if enabled {
		if err := h.authz.Write(ctx, []authz.Tuple{tuple}); err != nil {
			return fmt.Errorf("team set_crosstalk: write FGA tuple: %w", err)
		}
	} else {
		if err := h.authz.Delete(ctx, []authz.Tuple{tuple}); err != nil {
			return fmt.Errorf("team set_crosstalk: delete FGA tuple: %w", err)
		}
	}

	h.logger.InfoContext(ctx, "team crosstalk updated",
		slog.String("tenant_id", tenantID),
		slog.String("from_team_id", fromTeamID),
		slog.String("to_team_id", toTeamID),
		slog.Bool("enabled", enabled),
		slog.String("event_type", "team_crosstalk_set"),
	)
	return nil
}

// ---------------------------------------------------------------------------
// Redis key helpers
// ---------------------------------------------------------------------------

func teamMetaKey(tenantID, teamID string) string {
	return fmt.Sprintf("team:%s:%s", tenantID, teamID)
}

func teamListKey(tenantID string) string {
	return fmt.Sprintf("team-list:%s", tenantID)
}

// slugifyTeamName converts a team name to a URL-safe lowercase slug.
func slugifyTeamName(name string) string {
	s := strings.ToLower(name)
	var out []rune
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			out = append(out, r)
		} else if len(out) > 0 && out[len(out)-1] != '-' {
			out = append(out, '-')
		}
	}
	// Trim trailing dash.
	result := strings.TrimRight(string(out), "-")
	if result == "" {
		return "team"
	}
	return result
}
