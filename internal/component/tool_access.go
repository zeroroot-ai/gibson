package component

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

// Sentinel errors for tool access operations.
var (
	ErrToolNotEnabled   = errors.New("tool not enabled for tenant")
	ErrToolAccessDenied = errors.New("tool access not granted for tenant")
)

// ToolAccess represents a tenant's opt-in record for a tool.
type ToolAccess struct {
	TenantID       string `json:"tenant_id"`
	ToolName       string `json:"tool_name"`
	Enabled        bool   `json:"enabled"`
	ExecuteEnabled bool   `json:"execute_enabled"`
	ConfiguredAt   string `json:"configured_at,omitempty"`
	ConfiguredBy   string `json:"configured_by,omitempty"`
}

// ToolAccessStore manages tenant opt-in for tools.
type ToolAccessStore interface {
	Enable(ctx context.Context, tenant, toolName, configuredBy string) error
	Disable(ctx context.Context, tenant, toolName string) error
	CheckAccess(ctx context.Context, tenant, toolName string) error
	GetAccess(ctx context.Context, tenant, toolName string) (*ToolAccess, error)
	ListTenantTools(ctx context.Context, tenant string) ([]ToolAccess, error)
}

// RedisToolAccessStore implements ToolAccessStore using Redis for storage.
type RedisToolAccessStore struct {
	client   *redis.Client
	logger   *slog.Logger
	enforcer *casbin.Enforcer
}

// SetEnforcer attaches a Casbin enforcer. When non-nil, Enable and Disable
// sync Casbin policies so "tenant-admin" subjects gain or lose execute
// capabilities for each tool in real time.
func (s *RedisToolAccessStore) SetEnforcer(e *casbin.Enforcer) {
	s.enforcer = e
}

// NewRedisToolAccessStore creates a new store.
func NewRedisToolAccessStore(client *redis.Client, logger *slog.Logger) *RedisToolAccessStore {
	return &RedisToolAccessStore{
		client: client,
		logger: logger.With("component", "tool_access_store"),
	}
}

func toolAccessKey(tenant, toolName string) string {
	return fmt.Sprintf("tool-access:%s:%s", tenant, toolName)
}

func toolAccessPattern(tenant string) string {
	return fmt.Sprintf("tool-access:%s:*", tenant)
}

// Enable grants a tenant access to a tool.
func (s *RedisToolAccessStore) Enable(ctx context.Context, tenant, toolName, configuredBy string) error {
	s.logger.InfoContext(ctx, "enabling tool for tenant",
		slog.String("tenant", tenant),
		slog.String("tool", toolName))

	access := ToolAccess{
		TenantID:       tenant,
		ToolName:       toolName,
		Enabled:        true,
		ExecuteEnabled: true,
		ConfiguredAt:   time.Now().UTC().Format(time.RFC3339),
		ConfiguredBy:   configuredBy,
	}

	accessJSON, err := json.Marshal(access)
	if err != nil {
		return fmt.Errorf("marshal tool access record: %w", err)
	}

	if err := s.client.Set(ctx, toolAccessKey(tenant, toolName), accessJSON, 0).Err(); err != nil {
		return fmt.Errorf("store tool access record: %w", err)
	}

	s.syncCasbinEnable(ctx, tenant, toolName)

	return nil
}

// Disable removes a tenant's access to a tool.
func (s *RedisToolAccessStore) Disable(ctx context.Context, tenant, toolName string) error {
	s.logger.InfoContext(ctx, "disabling tool for tenant",
		slog.String("tenant", tenant),
		slog.String("tool", toolName))

	if err := s.client.Del(ctx, toolAccessKey(tenant, toolName)).Err(); err != nil {
		return fmt.Errorf("disable tool: %w", err)
	}

	s.syncCasbinDisable(ctx, tenant, toolName)

	return nil
}

// GetAccess returns the access record for a tenant+tool.
func (s *RedisToolAccessStore) GetAccess(ctx context.Context, tenant, toolName string) (*ToolAccess, error) {
	data, err := s.client.Get(ctx, toolAccessKey(tenant, toolName)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrToolNotEnabled
		}
		return nil, fmt.Errorf("get tool access record: %w", err)
	}

	var access ToolAccess
	if err := json.Unmarshal(data, &access); err != nil {
		return nil, fmt.Errorf("unmarshal tool access record: %w", err)
	}

	return &access, nil
}

// CheckAccess returns nil if the tenant has execute access to the tool.
func (s *RedisToolAccessStore) CheckAccess(ctx context.Context, tenant, toolName string) error {
	access, err := s.GetAccess(ctx, tenant, toolName)
	if err != nil {
		return err
	}
	if !access.Enabled || !access.ExecuteEnabled {
		return ErrToolAccessDenied
	}
	return nil
}

// ListTenantTools returns all tools the tenant has access to.
func (s *RedisToolAccessStore) ListTenantTools(ctx context.Context, tenant string) ([]ToolAccess, error) {
	var results []ToolAccess
	var cursor uint64

	for {
		keys, next, err := s.client.Scan(ctx, cursor, toolAccessPattern(tenant), 100).Result()
		if err != nil {
			return nil, fmt.Errorf("scan tenant tools: %w", err)
		}

		for _, key := range keys {
			data, err := s.client.Get(ctx, key).Bytes()
			if err != nil {
				if errors.Is(err, redis.Nil) {
					continue
				}
				return nil, fmt.Errorf("get tool access record %s: %w", key, err)
			}

			var access ToolAccess
			if err := json.Unmarshal(data, &access); err != nil {
				continue
			}
			results = append(results, access)
		}

		cursor = next
		if cursor == 0 {
			break
		}
	}

	return results, nil
}

// syncCasbinEnable adds a Casbin execute policy for "tenant-admin" on the tool.
func (s *RedisToolAccessStore) syncCasbinEnable(ctx context.Context, tenant, toolName string) {
	if s.enforcer == nil {
		return
	}

	resource := fmt.Sprintf("tool:%s", toolName)

	if _, err := s.enforcer.AddPolicy("tenant-admin", tenant, resource, "execute"); err != nil {
		s.logger.WarnContext(ctx, "casbin: failed to add execute policy for tool",
			slog.String("tenant", tenant),
			slog.String("tool", toolName),
			slog.String("error", err.Error()),
		)
	}
}

// syncCasbinDisable removes all Casbin policies for "tenant-admin" on this tool.
func (s *RedisToolAccessStore) syncCasbinDisable(ctx context.Context, tenant, toolName string) {
	if s.enforcer == nil {
		return
	}

	resource := fmt.Sprintf("tool:%s", toolName)

	if _, err := s.enforcer.RemoveFilteredPolicy(1, tenant, resource); err != nil {
		s.logger.WarnContext(ctx, "casbin: failed to remove policies for tool",
			slog.String("tenant", tenant),
			slog.String("tool", toolName),
			slog.String("error", err.Error()),
		)
	}
}
