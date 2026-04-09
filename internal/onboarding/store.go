package onboarding

// store.go implements a Redis-backed onboarding state store.
//
// The store persists tenant onboarding progress as a Redis hash under the key
// pattern:  onboarding:{tenantID}
//
// Fields:
//   current_step     — current onboarding step name
//   completed_steps  — JSON array of completed step names
//   setup_tasks      — JSON object mapping task name → status string
//   completed_at     — RFC 3339 completion timestamp (empty until all tasks done)

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

const keyPrefix = "onboarding:"

// RedisOnboardingStore implements the onboardingStore interface defined in
// server.go using Redis hashes. The store is safe for concurrent use.
type RedisOnboardingStore struct {
	client *goredis.Client
	logger *slog.Logger
}

// New constructs a RedisOnboardingStore. client must not be nil.
func New(client *goredis.Client, logger *slog.Logger) *RedisOnboardingStore {
	if client == nil {
		panic("onboarding: New: redis client must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &RedisOnboardingStore{client: client, logger: logger}
}

// redisKey returns the Redis hash key for a tenant's onboarding state.
func redisKey(tenantID string) string {
	return keyPrefix + tenantID
}

// GetState retrieves the onboarding state for a tenant.
// Returns empty/zero values when no state exists yet (first call).
func (s *RedisOnboardingStore) GetState(ctx context.Context, tenantID string) (
	currentStep string,
	completedSteps []string,
	setupTasks map[string]string,
	completedAt string,
	err error,
) {
	if tenantID == "" {
		return "", nil, nil, "", fmt.Errorf("tenant_id is required")
	}

	key := redisKey(tenantID)
	fields, hErr := s.client.HGetAll(ctx, key).Result()
	if hErr != nil && hErr != goredis.Nil {
		return "", nil, nil, "", fmt.Errorf("failed to get onboarding state: %w", hErr)
	}

	// Return empty state when no record exists.
	if len(fields) == 0 {
		return "", []string{}, map[string]string{}, "", nil
	}

	currentStep = fields["current_step"]
	completedAt = fields["completed_at"]

	// Unmarshal completed_steps from JSON.
	completedSteps = []string{}
	if raw, ok := fields["completed_steps"]; ok && raw != "" {
		if jsonErr := json.Unmarshal([]byte(raw), &completedSteps); jsonErr != nil {
			s.logger.WarnContext(ctx, "onboarding: failed to unmarshal completed_steps",
				slog.String("tenant_id", tenantID),
				slog.String("error", jsonErr.Error()),
			)
			completedSteps = []string{}
		}
	}

	// Unmarshal setup_tasks from JSON.
	setupTasks = map[string]string{}
	if raw, ok := fields["setup_tasks"]; ok && raw != "" {
		if jsonErr := json.Unmarshal([]byte(raw), &setupTasks); jsonErr != nil {
			s.logger.WarnContext(ctx, "onboarding: failed to unmarshal setup_tasks",
				slog.String("tenant_id", tenantID),
				slog.String("error", jsonErr.Error()),
			)
			setupTasks = map[string]string{}
		}
	}

	return currentStep, completedSteps, setupTasks, completedAt, nil
}

// UpdateState persists the onboarding state for a tenant.
// If all setup_tasks are marked as "completed", completed_at is set to now.
func (s *RedisOnboardingStore) UpdateState(
	ctx context.Context,
	tenantID, currentStep string,
	completedSteps []string,
	setupTasks map[string]string,
) error {
	if tenantID == "" {
		return fmt.Errorf("tenant_id is required")
	}

	// Ensure slices/maps are never nil to produce consistent JSON output.
	if completedSteps == nil {
		completedSteps = []string{}
	}
	if setupTasks == nil {
		setupTasks = map[string]string{}
	}

	stepsJSON, err := json.Marshal(completedSteps)
	if err != nil {
		return fmt.Errorf("failed to marshal completed_steps: %w", err)
	}
	tasksJSON, err := json.Marshal(setupTasks)
	if err != nil {
		return fmt.Errorf("failed to marshal setup_tasks: %w", err)
	}

	// Determine completion timestamp if all tasks are done.
	completedAt := ""
	if allComplete(setupTasks) && len(setupTasks) > 0 {
		completedAt = time.Now().UTC().Format(time.RFC3339)
	}

	key := redisKey(tenantID)
	fields := map[string]any{
		"current_step":    currentStep,
		"completed_steps": string(stepsJSON),
		"setup_tasks":     string(tasksJSON),
		"completed_at":    completedAt,
	}

	if hErr := s.client.HMSet(ctx, key, fields).Err(); hErr != nil {
		return fmt.Errorf("failed to update onboarding state: %w", hErr)
	}

	s.logger.InfoContext(ctx, "onboarding: state updated",
		slog.String("tenant_id", tenantID),
		slog.String("current_step", currentStep),
		slog.Int("completed_steps", len(completedSteps)),
	)

	return nil
}

// allComplete returns true when every task value in the map is "completed".
func allComplete(tasks map[string]string) bool {
	if len(tasks) == 0 {
		return false
	}
	for _, v := range tasks {
		if v != "completed" {
			return false
		}
	}
	return true
}
