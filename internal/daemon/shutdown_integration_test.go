package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/config"
	"github.com/zero-day-ai/gibson/internal/mission"
	"github.com/zero-day-ai/gibson/internal/observability"
	"github.com/zero-day-ai/gibson/internal/types"
)

// TestShutdownCoordinator_Integration tests the full shutdown sequence.
func TestShutdownCoordinator_Integration(t *testing.T) {
	// Setup miniredis for testing
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	// Create Redis client
	redisClient := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	defer redisClient.Close()

	// Create logger
	logger := observability.NewLogger(observability.ConfigFromEnv())

	// Create shutdown config
	cfg := config.ShutdownConfig{
		Timeout:           10 * time.Second,
		DrainTimeout:      2 * time.Second,
		CheckpointTimeout: 2 * time.Second,
		AgentTimeout:      2 * time.Second,
	}

	// Create shutdown coordinator
	coordinator := NewShutdownCoordinator(cfg, logger)

	// Create health state manager
	healthState := newHealthStateManager()

	// Register phases
	coordinator.RegisterPhase(NewHealthPhase(healthState, logger))

	// Execute shutdown
	ctx := context.Background()
	err = coordinator.Shutdown(ctx)
	require.NoError(t, err)

	// Verify health state was set to shutting down
	assert.True(t, !healthState.IsHealthy())

	// Verify metrics were recorded
	metrics := coordinator.Metrics()
	assert.NotZero(t, metrics.TotalDuration())
	assert.Equal(t, 1, len(metrics.PhasesDuration))
	assert.Contains(t, metrics.PhasesDuration, "health_unhealthy")
}

// TestMissionCheckpointing_Integration tests mission checkpointing during shutdown.
func TestMissionCheckpointing_Integration(t *testing.T) {
	// Setup miniredis
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	// Create Redis client
	redisClient := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	defer redisClient.Close()

	// Create logger
	logger := observability.NewLogger(observability.ConfigFromEnv())

	// Create a running mission
	missionID := types.NewID()

	// Create active missions map
	activeMissions := map[string]context.CancelFunc{
		missionID.String(): func() {},
	}

	// Create checkpointer (pool is nil — per-tenant status update is skipped in test)
	checkpointer := NewDaemonMissionCheckpointer(
		redisClient,
		func() map[string]context.CancelFunc { return activeMissions },
		nil, // pool: nil in unit test; status updates require a real per-tenant pool
		logger,
	)

	// Checkpoint all missions
	ctx := context.Background()
	count, err := checkpointer.CheckpointAll(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	// Verify checkpoint was saved to Redis
	key := checkpointKeyPrefix + missionID.String()
	exists, err := redisClient.Exists(ctx, key).Result()
	require.NoError(t, err)
	assert.Equal(t, int64(1), exists)

	// Verify checkpoint can be retrieved
	checkpoint, err := checkpointer.GetCheckpoint(ctx, missionID)
	require.NoError(t, err)
	assert.NotNil(t, checkpoint)
	assert.Equal(t, missionID.String(), checkpoint.MissionID)
	assert.Equal(t, "graceful_shutdown", checkpoint.Label)
	assert.True(t, checkpoint.IsImplicit)
}

// TestCheckpointRecovery_Integration tests checkpoint discovery after restart.
func TestCheckpointRecovery_Integration(t *testing.T) {
	// Setup miniredis
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	// Create Redis client
	redisClient := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	defer redisClient.Close()

	// Create logger
	logger := observability.NewLogger(observability.ConfigFromEnv())

	// Create test missions
	missionID1 := types.NewID()
	missionID2 := types.NewID()

	// Create checkpointer and save checkpoints (pool is nil — status updates skipped in unit test)
	checkpointer := NewDaemonMissionCheckpointer(
		redisClient,
		func() map[string]context.CancelFunc {
			return map[string]context.CancelFunc{
				missionID1.String(): func() {},
				missionID2.String(): func() {},
			}
		},
		nil, // pool: nil in unit test
		logger,
	)

	ctx := context.Background()
	count, err := checkpointer.CheckpointAll(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, count)

	// Simulate restart by creating a new checkpointer instance
	newCheckpointer := NewDaemonMissionCheckpointer(
		redisClient,
		func() map[string]context.CancelFunc { return make(map[string]context.CancelFunc) },
		nil, // pool: nil in unit test
		logger,
	)

	// List checkpoints to discover suspended missions
	checkpoints, err := newCheckpointer.ListCheckpoints(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, len(checkpoints))

	// Verify both mission IDs are present
	foundMissions := make(map[types.ID]bool)
	for _, id := range checkpoints {
		foundMissions[id] = true
	}
	assert.True(t, foundMissions[missionID1])
	assert.True(t, foundMissions[missionID2])

	// Clean up checkpoints
	err = newCheckpointer.DeleteCheckpoint(ctx, missionID1)
	require.NoError(t, err)
	err = newCheckpointer.DeleteCheckpoint(ctx, missionID2)
	require.NoError(t, err)

	// Verify checkpoints are deleted
	checkpoints, err = newCheckpointer.ListCheckpoints(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, len(checkpoints))
}

// TestHealthStateManager_ShutdownState tests health endpoint behavior during shutdown.
func TestHealthStateManager_ShutdownState(t *testing.T) {
	healthState := newHealthStateManager()

	// Initially not shutting down
	assert.False(t, !healthState.IsHealthy())

	// Check function should return healthy
	checkFunc := healthState.CheckFunc()
	ctx := context.Background()
	status := checkFunc(ctx)
	assert.True(t, status.IsHealthy())

	// Set shutting down
	healthState.SetShuttingDown("graceful_shutdown")
	assert.True(t, !healthState.IsHealthy())

	// Check function should now return unhealthy
	status = checkFunc(ctx)
	assert.False(t, status.IsHealthy())
	assert.True(t, status.IsDegraded())
}

// TestShutdownPhases_Timeout tests phase timeout handling.
func TestShutdownPhases_Timeout(t *testing.T) {
	logger := observability.NewLogger(observability.ConfigFromEnv())

	// Create a phase that will timeout
	slowPhase := &mockSlowPhase{
		name:     "slow_phase",
		timeout:  100 * time.Millisecond,
		duration: 500 * time.Millisecond,
	}

	// Create shutdown config with short timeout
	cfg := config.ShutdownConfig{
		Timeout:           2 * time.Second,
		DrainTimeout:      100 * time.Millisecond,
		CheckpointTimeout: 100 * time.Millisecond,
		AgentTimeout:      100 * time.Millisecond,
	}

	coordinator := NewShutdownCoordinator(cfg, logger)
	coordinator.RegisterPhase(slowPhase)

	// Execute shutdown
	ctx := context.Background()
	err := coordinator.Shutdown(ctx)

	// Should complete despite phase timeout (phases continue on timeout)
	assert.NoError(t, err)

	// Verify metrics show the phase was attempted
	metrics := coordinator.Metrics()
	assert.Contains(t, metrics.PhasesDuration, "slow_phase")

	// Verify error was recorded
	assert.Equal(t, 1, metrics.ErrorCount())
}

// shutdownMockMissionStore is a simple in-memory mission store for testing shutdown scenarios.
type shutdownMockMissionStore struct {
	missions map[types.ID]*mission.Mission
}

func (m *shutdownMockMissionStore) Get(ctx context.Context, id types.ID) (*mission.Mission, error) {
	mis, ok := m.missions[id]
	if !ok {
		return nil, mission.NewNotFoundError("not found")
	}
	return mis, nil
}

func (m *shutdownMockMissionStore) UpdateStatus(ctx context.Context, id types.ID, status mission.MissionStatus) error {
	mis, ok := m.missions[id]
	if !ok {
		return mission.NewNotFoundError("not found")
	}
	mis.Status = status
	return nil
}

func (m *shutdownMockMissionStore) Create(ctx context.Context, mis *mission.Mission) error {
	m.missions[mis.ID] = mis
	return nil
}

func (m *shutdownMockMissionStore) Update(ctx context.Context, mis *mission.Mission) error {
	m.missions[mis.ID] = mis
	return nil
}

func (m *shutdownMockMissionStore) Delete(ctx context.Context, id types.ID) error {
	delete(m.missions, id)
	return nil
}

func (m *shutdownMockMissionStore) List(ctx context.Context) ([]*mission.Mission, error) {
	missions := make([]*mission.Mission, 0, len(m.missions))
	for _, mis := range m.missions {
		missions = append(missions, mis)
	}
	return missions, nil
}

func (m *shutdownMockMissionStore) GetActive(ctx context.Context) ([]*mission.Mission, error) {
	missions := make([]*mission.Mission, 0)
	for _, mis := range m.missions {
		if mis.Status == mission.MissionStatusRunning || mis.Status == mission.MissionStatusPaused {
			missions = append(missions, mis)
		}
	}
	return missions, nil
}

// mockSlowPhase simulates a phase that takes longer than its timeout.
type mockSlowPhase struct {
	name     string
	timeout  time.Duration
	duration time.Duration
}

func (p *mockSlowPhase) Name() string {
	return p.name
}

func (p *mockSlowPhase) Timeout() time.Duration {
	return p.timeout
}

func (p *mockSlowPhase) Execute(ctx context.Context) error {
	select {
	case <-time.After(p.duration):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
