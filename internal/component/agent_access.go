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

// Sentinel errors for agent access operations.
var (
	ErrAgentNotEnabled   = errors.New("agent not enabled for tenant")
	ErrAgentAccessDenied = errors.New("agent access not granted for tenant")
)

// AgentAccess represents a tenant's opt-in record for an agent.
type AgentAccess struct {
	TenantID       string `json:"tenant_id"`
	AgentName      string `json:"agent_name"`
	Enabled        bool   `json:"enabled"`
	ExecuteEnabled bool   `json:"execute_enabled"`
	DelegateEnabled bool  `json:"delegate_enabled"`
	ConfiguredAt   string `json:"configured_at,omitempty"`
	ConfiguredBy   string `json:"configured_by,omitempty"`
}

// AgentAccessStore manages tenant opt-in for agents.
type AgentAccessStore interface {
	Enable(ctx context.Context, tenant, agentName, configuredBy string) error
	Disable(ctx context.Context, tenant, agentName string) error
	CheckAccess(ctx context.Context, tenant, agentName string) error
	GetAccess(ctx context.Context, tenant, agentName string) (*AgentAccess, error)
	ListTenantAgents(ctx context.Context, tenant string) ([]AgentAccess, error)
}

// RedisAgentAccessStore implements AgentAccessStore using Redis for storage.
type RedisAgentAccessStore struct {
	client   *redis.Client
	logger   *slog.Logger
	enforcer *casbin.Enforcer
}

// SetEnforcer attaches a Casbin enforcer. When non-nil, Enable and Disable
// sync Casbin policies so "tenant-admin" subjects gain or lose execute and
// delegate capabilities for each agent in real time.
func (s *RedisAgentAccessStore) SetEnforcer(e *casbin.Enforcer) {
	s.enforcer = e
}

// NewRedisAgentAccessStore creates a new store.
func NewRedisAgentAccessStore(client *redis.Client, logger *slog.Logger) *RedisAgentAccessStore {
	return &RedisAgentAccessStore{
		client: client,
		logger: logger.With("component", "agent_access_store"),
	}
}

func agentAccessKey(tenant, agentName string) string {
	return fmt.Sprintf("agent-access:%s:%s", tenant, agentName)
}

func agentAccessPattern(tenant string) string {
	return fmt.Sprintf("agent-access:%s:*", tenant)
}

// Enable grants a tenant access to an agent.
func (s *RedisAgentAccessStore) Enable(ctx context.Context, tenant, agentName, configuredBy string) error {
	s.logger.InfoContext(ctx, "enabling agent for tenant",
		slog.String("tenant", tenant),
		slog.String("agent", agentName))

	access := AgentAccess{
		TenantID:        tenant,
		AgentName:       agentName,
		Enabled:         true,
		ExecuteEnabled:  true,
		DelegateEnabled: true,
		ConfiguredAt:    time.Now().UTC().Format(time.RFC3339),
		ConfiguredBy:    configuredBy,
	}

	accessJSON, err := json.Marshal(access)
	if err != nil {
		return fmt.Errorf("marshal agent access record: %w", err)
	}

	if err := s.client.Set(ctx, agentAccessKey(tenant, agentName), accessJSON, 0).Err(); err != nil {
		return fmt.Errorf("store agent access record: %w", err)
	}

	s.syncCasbinEnable(ctx, tenant, agentName)

	return nil
}

// Disable removes a tenant's access to an agent.
func (s *RedisAgentAccessStore) Disable(ctx context.Context, tenant, agentName string) error {
	s.logger.InfoContext(ctx, "disabling agent for tenant",
		slog.String("tenant", tenant),
		slog.String("agent", agentName))

	if err := s.client.Del(ctx, agentAccessKey(tenant, agentName)).Err(); err != nil {
		return fmt.Errorf("disable agent: %w", err)
	}

	s.syncCasbinDisable(ctx, tenant, agentName)

	return nil
}

// GetAccess returns the access record for a tenant+agent.
func (s *RedisAgentAccessStore) GetAccess(ctx context.Context, tenant, agentName string) (*AgentAccess, error) {
	data, err := s.client.Get(ctx, agentAccessKey(tenant, agentName)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrAgentNotEnabled
		}
		return nil, fmt.Errorf("get agent access record: %w", err)
	}

	var access AgentAccess
	if err := json.Unmarshal(data, &access); err != nil {
		return nil, fmt.Errorf("unmarshal agent access record: %w", err)
	}

	return &access, nil
}

// CheckAccess returns nil if the tenant has execute access to the agent.
func (s *RedisAgentAccessStore) CheckAccess(ctx context.Context, tenant, agentName string) error {
	access, err := s.GetAccess(ctx, tenant, agentName)
	if err != nil {
		return err
	}
	if !access.Enabled || !access.ExecuteEnabled {
		return ErrAgentAccessDenied
	}
	return nil
}

// ListTenantAgents returns all agents the tenant has access to.
func (s *RedisAgentAccessStore) ListTenantAgents(ctx context.Context, tenant string) ([]AgentAccess, error) {
	var results []AgentAccess
	var cursor uint64

	for {
		keys, next, err := s.client.Scan(ctx, cursor, agentAccessPattern(tenant), 100).Result()
		if err != nil {
			return nil, fmt.Errorf("scan tenant agents: %w", err)
		}

		for _, key := range keys {
			data, err := s.client.Get(ctx, key).Bytes()
			if err != nil {
				if errors.Is(err, redis.Nil) {
					continue
				}
				return nil, fmt.Errorf("get agent access record %s: %w", key, err)
			}

			var access AgentAccess
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

// syncCasbinEnable adds Casbin execute and delegate policies for "tenant-admin".
func (s *RedisAgentAccessStore) syncCasbinEnable(ctx context.Context, tenant, agentName string) {
	if s.enforcer == nil {
		return
	}

	resource := fmt.Sprintf("agent:%s", agentName)

	if _, err := s.enforcer.AddPolicy("tenant-admin", tenant, resource, "execute"); err != nil {
		s.logger.WarnContext(ctx, "casbin: failed to add execute policy for agent",
			slog.String("tenant", tenant),
			slog.String("agent", agentName),
			slog.String("error", err.Error()),
		)
	}

	if _, err := s.enforcer.AddPolicy("tenant-admin", tenant, resource, "delegate"); err != nil {
		s.logger.WarnContext(ctx, "casbin: failed to add delegate policy for agent",
			slog.String("tenant", tenant),
			slog.String("agent", agentName),
			slog.String("error", err.Error()),
		)
	}
}

// syncCasbinDisable removes all Casbin policies for "tenant-admin" on this agent.
func (s *RedisAgentAccessStore) syncCasbinDisable(ctx context.Context, tenant, agentName string) {
	if s.enforcer == nil {
		return
	}

	resource := fmt.Sprintf("agent:%s", agentName)

	if _, err := s.enforcer.RemoveFilteredPolicy(1, tenant, resource); err != nil {
		s.logger.WarnContext(ctx, "casbin: failed to remove policies for agent",
			slog.String("tenant", tenant),
			slog.String("agent", agentName),
			slog.String("error", err.Error()),
		)
	}
}
