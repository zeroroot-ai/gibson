package daemon

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/config"
	"github.com/zero-day-ai/gibson/internal/observability"
)

// mockPhase is a mock implementation of ShutdownPhase for testing.
type mockPhase struct {
	name          string
	timeout       time.Duration
	executeFn     func(ctx context.Context) error
	executeCount  int
	executeCalled bool
}

func (m *mockPhase) Name() string {
	return m.name
}

func (m *mockPhase) Timeout() time.Duration {
	return m.timeout
}

func (m *mockPhase) Execute(ctx context.Context) error {
	m.executeCalled = true
	m.executeCount++
	if m.executeFn != nil {
		return m.executeFn(ctx)
	}
	return nil
}

// TestShutdownCoordinator_RegisterPhase tests phase registration.
func TestShutdownCoordinator_RegisterPhase(t *testing.T) {
	logger := observability.NewLogger(observability.ConfigFromEnv())
	cfg := config.ShutdownConfig{
		Timeout:           30 * time.Second,
		DrainTimeout:      10 * time.Second,
		CheckpointTimeout: 5 * time.Second,
		AgentTimeout:      15 * time.Second,
	}

	coordinator := NewShutdownCoordinator(cfg, logger)

	// Register multiple phases
	phase1 := &mockPhase{name: "phase1", timeout: 5 * time.Second}
	phase2 := &mockPhase{name: "phase2", timeout: 5 * time.Second}
	phase3 := &mockPhase{name: "phase3", timeout: 5 * time.Second}

	coordinator.RegisterPhase(phase1)
	coordinator.RegisterPhase(phase2)
	coordinator.RegisterPhase(phase3)

	// Verify phases are registered
	assert.Equal(t, 3, len(coordinator.phases), "expected 3 phases to be registered")
}

// TestShutdownCoordinator_PhaseExecutionOrder tests that phases execute in order.
func TestShutdownCoordinator_PhaseExecutionOrder(t *testing.T) {
	logger := observability.NewLogger(observability.ConfigFromEnv())
	cfg := config.ShutdownConfig{
		Timeout:           30 * time.Second,
		DrainTimeout:      10 * time.Second,
		CheckpointTimeout: 5 * time.Second,
		AgentTimeout:      15 * time.Second,
	}

	coordinator := NewShutdownCoordinator(cfg, logger)

	var executionOrder []string
	var mu sync.Mutex

	// Create phases that record execution order
	phase1 := &mockPhase{
		name:    "phase1",
		timeout: 1 * time.Second,
		executeFn: func(ctx context.Context) error {
			mu.Lock()
			executionOrder = append(executionOrder, "phase1")
			mu.Unlock()
			return nil
		},
	}
	phase2 := &mockPhase{
		name:    "phase2",
		timeout: 1 * time.Second,
		executeFn: func(ctx context.Context) error {
			mu.Lock()
			executionOrder = append(executionOrder, "phase2")
			mu.Unlock()
			return nil
		},
	}
	phase3 := &mockPhase{
		name:    "phase3",
		timeout: 1 * time.Second,
		executeFn: func(ctx context.Context) error {
			mu.Lock()
			executionOrder = append(executionOrder, "phase3")
			mu.Unlock()
			return nil
		},
	}

	coordinator.RegisterPhase(phase1)
	coordinator.RegisterPhase(phase2)
	coordinator.RegisterPhase(phase3)

	// Execute shutdown
	err := coordinator.Shutdown(context.Background())
	require.NoError(t, err)

	// Verify execution order
	assert.Equal(t, []string{"phase1", "phase2", "phase3"}, executionOrder, "phases should execute in registration order")
}

// TestShutdownCoordinator_PhaseTimeout tests that individual phase timeouts are enforced.
func TestShutdownCoordinator_PhaseTimeout(t *testing.T) {
	logger := observability.NewLogger(observability.ConfigFromEnv())
	cfg := config.ShutdownConfig{
		Timeout:           30 * time.Second,
		DrainTimeout:      10 * time.Second,
		CheckpointTimeout: 5 * time.Second,
		AgentTimeout:      15 * time.Second,
	}

	coordinator := NewShutdownCoordinator(cfg, logger)

	// Create a phase that takes longer than its timeout
	slowPhase := &mockPhase{
		name:    "slow_phase",
		timeout: 100 * time.Millisecond,
		executeFn: func(ctx context.Context) error {
			// Wait for context cancellation or 5 seconds
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(5 * time.Second):
				return nil
			}
		},
	}

	fastPhase := &mockPhase{
		name:    "fast_phase",
		timeout: 1 * time.Second,
		executeFn: func(ctx context.Context) error {
			return nil
		},
	}

	coordinator.RegisterPhase(slowPhase)
	coordinator.RegisterPhase(fastPhase)

	// Execute shutdown
	start := time.Now()
	err := coordinator.Shutdown(context.Background())
	duration := time.Since(start)

	// Shutdown should complete (not return error) even though phase timed out
	require.NoError(t, err)

	// Both phases should have been called
	assert.True(t, slowPhase.executeCalled, "slow phase should have been called")
	assert.True(t, fastPhase.executeCalled, "fast phase should have been called after slow phase timeout")

	// Total duration should be less than 5 seconds (slow phase execution time)
	// and more than 100ms (slow phase timeout)
	assert.Less(t, duration, 5*time.Second, "shutdown should not wait for slow phase to complete")
	assert.GreaterOrEqual(t, duration, 100*time.Millisecond, "shutdown should wait at least for phase timeout")
}

// TestShutdownCoordinator_ErrorHandling tests that phase errors don't stop shutdown.
func TestShutdownCoordinator_ErrorHandling(t *testing.T) {
	logger := observability.NewLogger(observability.ConfigFromEnv())
	cfg := config.ShutdownConfig{
		Timeout:           30 * time.Second,
		DrainTimeout:      10 * time.Second,
		CheckpointTimeout: 5 * time.Second,
		AgentTimeout:      15 * time.Second,
	}

	coordinator := NewShutdownCoordinator(cfg, logger)

	// Create phases where one fails
	phase1 := &mockPhase{
		name:    "phase1",
		timeout: 1 * time.Second,
		executeFn: func(ctx context.Context) error {
			return nil
		},
	}
	failingPhase := &mockPhase{
		name:    "failing_phase",
		timeout: 1 * time.Second,
		executeFn: func(ctx context.Context) error {
			return errors.New("phase failed")
		},
	}
	phase3 := &mockPhase{
		name:    "phase3",
		timeout: 1 * time.Second,
		executeFn: func(ctx context.Context) error {
			return nil
		},
	}

	coordinator.RegisterPhase(phase1)
	coordinator.RegisterPhase(failingPhase)
	coordinator.RegisterPhase(phase3)

	// Execute shutdown
	err := coordinator.Shutdown(context.Background())

	// Shutdown should complete successfully despite phase error
	require.NoError(t, err)

	// All phases should have been executed
	assert.True(t, phase1.executeCalled, "phase1 should have been called")
	assert.True(t, failingPhase.executeCalled, "failing phase should have been called")
	assert.True(t, phase3.executeCalled, "phase3 should have been called after failing phase")

	// Verify error was recorded in metrics
	metrics := coordinator.Metrics()
	assert.Equal(t, 1, metrics.ErrorCount(), "should have recorded 1 error")
}

// TestShutdownCoordinator_TotalTimeout tests that total shutdown timeout is enforced.
func TestShutdownCoordinator_TotalTimeout(t *testing.T) {
	logger := observability.NewLogger(observability.ConfigFromEnv())
	cfg := config.ShutdownConfig{
		Timeout:           500 * time.Millisecond, // Very short total timeout
		DrainTimeout:      10 * time.Second,
		CheckpointTimeout: 5 * time.Second,
		AgentTimeout:      15 * time.Second,
	}

	coordinator := NewShutdownCoordinator(cfg, logger)

	// Create multiple phases that each take 200ms but respect context cancellation
	contextAwareSleep := func(ctx context.Context) error {
		select {
		case <-time.After(200 * time.Millisecond):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	phase1 := &mockPhase{
		name:    "phase1",
		timeout: 300 * time.Millisecond,
		executeFn: contextAwareSleep,
	}
	phase2 := &mockPhase{
		name:    "phase2",
		timeout: 300 * time.Millisecond,
		executeFn: contextAwareSleep,
	}
	phase3 := &mockPhase{
		name:    "phase3",
		timeout: 300 * time.Millisecond,
		executeFn: contextAwareSleep,
	}

	coordinator.RegisterPhase(phase1)
	coordinator.RegisterPhase(phase2)
	coordinator.RegisterPhase(phase3)

	// Execute shutdown
	start := time.Now()
	err := coordinator.Shutdown(context.Background())
	duration := time.Since(start)

	// Shutdown should return error when total timeout is exceeded
	require.Error(t, err)
	assert.Contains(t, err.Error(), "shutdown timeout exceeded", "error should indicate timeout")

	// Total duration should be around the timeout (500ms) not 600ms (3 * 200ms)
	assert.Less(t, duration, 800*time.Millisecond, "shutdown should stop after total timeout")

	// Verify forced exit flag is set
	metrics := coordinator.Metrics()
	assert.True(t, metrics.ForcedExit, "forced exit should be true when total timeout exceeded")
}

// TestShutdownCoordinator_Metrics tests that metrics are collected properly.
func TestShutdownCoordinator_Metrics(t *testing.T) {
	logger := observability.NewLogger(observability.ConfigFromEnv())
	cfg := config.ShutdownConfig{
		Timeout:           30 * time.Second,
		DrainTimeout:      10 * time.Second,
		CheckpointTimeout: 5 * time.Second,
		AgentTimeout:      15 * time.Second,
	}

	coordinator := NewShutdownCoordinator(cfg, logger)

	// Create phases with known execution times
	phase1 := &mockPhase{
		name:    "phase1",
		timeout: 1 * time.Second,
		executeFn: func(ctx context.Context) error {
			time.Sleep(100 * time.Millisecond)
			return nil
		},
	}
	phase2 := &mockPhase{
		name:    "phase2",
		timeout: 1 * time.Second,
		executeFn: func(ctx context.Context) error {
			time.Sleep(150 * time.Millisecond)
			return nil
		},
	}

	coordinator.RegisterPhase(phase1)
	coordinator.RegisterPhase(phase2)

	// Execute shutdown
	err := coordinator.Shutdown(context.Background())
	require.NoError(t, err)

	// Verify metrics
	metrics := coordinator.Metrics()
	assert.NotZero(t, metrics.StartTime, "start time should be set")
	assert.NotZero(t, metrics.TotalDuration(), "total duration should be non-zero")

	// Verify phase durations are recorded
	assert.Contains(t, metrics.PhasesDuration, "phase1", "phase1 duration should be recorded")
	assert.Contains(t, metrics.PhasesDuration, "phase2", "phase2 duration should be recorded")

	// Verify phase durations are reasonable
	phase1Duration := metrics.PhasesDuration["phase1"]
	phase2Duration := metrics.PhasesDuration["phase2"]
	assert.GreaterOrEqual(t, phase1Duration, 100*time.Millisecond, "phase1 duration should be at least 100ms")
	assert.GreaterOrEqual(t, phase2Duration, 150*time.Millisecond, "phase2 duration should be at least 150ms")

	// No errors should be recorded
	assert.Equal(t, 0, metrics.ErrorCount(), "no errors should be recorded")
	assert.False(t, metrics.ForcedExit, "forced exit should be false")
}

// TestShutdownCoordinator_EmptyPhases tests shutdown with no registered phases.
func TestShutdownCoordinator_EmptyPhases(t *testing.T) {
	logger := observability.NewLogger(observability.ConfigFromEnv())
	cfg := config.ShutdownConfig{
		Timeout:           30 * time.Second,
		DrainTimeout:      10 * time.Second,
		CheckpointTimeout: 5 * time.Second,
		AgentTimeout:      15 * time.Second,
	}

	coordinator := NewShutdownCoordinator(cfg, logger)

	// Execute shutdown with no phases
	err := coordinator.Shutdown(context.Background())

	// Should complete successfully
	require.NoError(t, err)

	// Metrics should still be initialized
	metrics := coordinator.Metrics()
	assert.NotZero(t, metrics.StartTime, "start time should be set")
	assert.NotZero(t, metrics.TotalDuration(), "total duration should be non-zero")
}

// TestShutdownCoordinator_ContextCancellation tests shutdown behavior when context is cancelled.
func TestShutdownCoordinator_ContextCancellation(t *testing.T) {
	logger := observability.NewLogger(observability.ConfigFromEnv())
	cfg := config.ShutdownConfig{
		Timeout:           30 * time.Second,
		DrainTimeout:      10 * time.Second,
		CheckpointTimeout: 5 * time.Second,
		AgentTimeout:      15 * time.Second,
	}

	coordinator := NewShutdownCoordinator(cfg, logger)

	// Create a phase that waits for context
	phase1 := &mockPhase{
		name:    "phase1",
		timeout: 5 * time.Second,
		executeFn: func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		},
	}

	coordinator.RegisterPhase(phase1)

	// Create a context that will be cancelled
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Execute shutdown
	err := coordinator.Shutdown(ctx)

	// Should return error when context is cancelled
	require.Error(t, err)
	assert.Contains(t, err.Error(), "shutdown timeout exceeded", "error should indicate timeout")

	// Phase should have been called
	assert.True(t, phase1.executeCalled, "phase should have been called")
}
