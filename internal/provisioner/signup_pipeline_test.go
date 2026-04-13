//go:build integration
// +build integration

// Package provisioner — signup_pipeline_test.go
//
// Integration tests for SignupPipeline. Uses miniredis (which supports Redis
// Streams including XREADGROUP/XACK) to verify the full event-driven state
// machine without a live Redis instance.
//
// Better Auth migration changes:
//   - The "org" step and kc KeycloakAdmin dependency have been removed.
//   - EventSignupRequested routes directly to handleFGA.
//   - The store is now ProvisioningStateStore (interface).
//     Tests use memProvisioningStore (defined in signup_handlers_test.go).
//
// Run with:
//
//	go test -tags=integration -timeout=60s ./internal/provisioner/... -run TestSignupPipeline
package provisioner

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zero-day-ai/gibson/internal/authz"
)

// ---------------------------------------------------------------------------
// Pipeline test helpers
// ---------------------------------------------------------------------------

// buildPipelineTestState builds a ready SignupState seed and a SignupPipeline
// wired to the given miniredis instance with test-friendly delays.
//
// It pre-creates the consumer group at position "0" so that any messages
// published before pipeline.Start is called will still be delivered — Start
// sees BUSYGROUP and skips re-creation, then XREADGROUP reads all un-acked
// messages from the beginning of the stream.
func buildPipelineTestState(
	t *testing.T,
	mr *miniredis.Miniredis,
	az authz.Authorizer,
	prov *Provisioner,
	store ProvisioningStateStore,
) (*SignupPipeline, *goredis.Client) {
	t.Helper()

	rdb := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	// Pre-create the consumer group at the beginning of the stream ("0").
	// This ensures messages published before Start() is called are delivered.
	// MKSTREAM creates the stream if absent. Start() will get BUSYGROUP and
	// skip re-creation, so the group position remains at 0.
	ctx := context.Background()
	err := rdb.XGroupCreateMkStream(ctx, SignupStreamKey, SignupConsumerGroup, "0").Err()
	if err != nil && !isBusyGroupError(err) {
		t.Fatalf("buildPipelineTestState: pre-create consumer group: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	p := &SignupPipeline{
		redis:          rdb,
		authz:          az,
		prov:           prov,
		store:          store,
		logger:         logger,
		consumer:       "test-pipeline",
		retryBaseDelay: 10 * time.Millisecond,  // fast retries for tests
		blockDuration:  100 * time.Millisecond, // short block so ctx.Done() is checked promptly
	}

	return p, rdb
}

// publishSignupRequested XADDs a signup.requested event to the stream.
func publishSignupRequested(t *testing.T, rdb *goredis.Client, userID, tenantID string) {
	t.Helper()
	ctx := context.Background()
	_, err := rdb.XAdd(ctx, &goredis.XAddArgs{
		Stream: SignupStreamKey,
		Values: map[string]interface{}{
			"event_type":   string(EventSignupRequested),
			"user_id":      userID,
			"tenant_id":    tenantID,
			"timestamp_ms": "1000",
		},
	}).Result()
	require.NoError(t, err, "publishSignupRequested: XAdd must succeed")
}

// waitForStatus polls the store every 10ms until the status matches or the
// timeout is exceeded.
func waitForStatus(t *testing.T, store ProvisioningStateStore, userID, wantStatus string, timeout time.Duration) *SignupState {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		state, err := store.Get(ctx, userID)
		if err == nil && state != nil && state.Status == wantStatus {
			return state
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for status=%q for user=%q", wantStatus, userID)
	return nil
}

// newMinimalProv builds a *Provisioner backed by the test miniredis.
func newMinimalProv(t *testing.T, mr *miniredis.Miniredis) *Provisioner {
	t.Helper()
	rdb := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	return New(rdb, &noopTenantCreator{}, nil, nil, logger)
}

// ---------------------------------------------------------------------------
// TestSignupPipeline_HappyPath
//
// Publishes signup.requested → asserts pipeline drives state to "active"
// (was "completed" in Redis-based store; Postgres uses "active" status).
// ---------------------------------------------------------------------------

func TestSignupPipeline_HappyPath(t *testing.T) {
	mr := miniredis.RunT(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	az := &mockAuthz{}
	prov := newMinimalProv(t, mr)
	store := newMemProvisioningStore()

	pipeline, rdb := buildPipelineTestState(t, mr, az, prov, store)

	// Seed state and publish event.
	require.NoError(t, store.Create(ctx, "happy-user", SignupState{
		Status:      "requested",
		Email:       "happy@example.com",
		CompanyName: "Happy Corp",
		TenantID:    "happy-corp",
		Plan:        "free",
		StepStatuses: map[string]string{
			"fga": "pending", "provision": "pending",
		},
	}))
	publishSignupRequested(t, rdb, "happy-user", "happy-corp")

	// Start pipeline in background; cancel ctx to stop it.
	done := make(chan error, 1)
	go func() { done <- pipeline.Start(ctx) }()

	// Wait for active status (pipeline completes fga + provision).
	state := waitForStatus(t, store, "happy-user", "active", 8*time.Second)
	require.NotNil(t, state)

	assert.Equal(t, "completed", state.StepStatuses["fga"])
	assert.Equal(t, "completed", state.StepStatuses["provision"])

	cancel()
	select {
	case err := <-done:
		assert.NoError(t, err, "pipeline.Start should return nil on ctx cancel")
	case <-time.After(2 * time.Second):
		t.Fatal("pipeline did not stop after ctx cancel")
	}
}

// ---------------------------------------------------------------------------
// TestSignupPipeline_ConsumerGroupCreatedOnStart
//
// Asserts that Start creates the consumer group even when no messages exist.
// ---------------------------------------------------------------------------

func TestSignupPipeline_ConsumerGroupCreatedOnStart(t *testing.T) {
	mr := miniredis.RunT(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	az := &mockAuthz{}
	prov := newMinimalProv(t, mr)
	store := newMemProvisioningStore()

	pipeline, rdb := buildPipelineTestState(t, mr, az, prov, store)

	// Start pipeline briefly to trigger group creation.
	go func() { _ = pipeline.Start(ctx) }()

	// Wait a moment for Start to call XGROUP CREATE.
	time.Sleep(200 * time.Millisecond)
	cancel()

	// Verify consumer group exists.
	groups, err := rdb.XInfoGroups(context.Background(), SignupStreamKey).Result()
	require.NoError(t, err)
	require.Len(t, groups, 1)
	assert.Equal(t, SignupConsumerGroup, groups[0].Name)
}

// ---------------------------------------------------------------------------
// TestSignupPipeline_ExhaustsRetries
//
// Wires a failing FGA authorizer. After maxRetries the state should be "failed".
// ---------------------------------------------------------------------------

func TestSignupPipeline_ExhaustsRetries(t *testing.T) {
	mr := miniredis.RunT(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// FGA always fails.
	az := &mockAuthz{writeErr: errInjected}
	prov := newMinimalProv(t, mr)
	store := newMemProvisioningStore()

	pipeline, rdb := buildPipelineTestState(t, mr, az, prov, store)

	require.NoError(t, store.Create(ctx, "retry-user", SignupState{
		Status:      "requested",
		Email:       "retry@example.com",
		CompanyName: "Retry Corp",
		TenantID:    "retry-corp",
		Plan:        "free",
		StepStatuses: map[string]string{
			"fga": "pending", "provision": "pending",
		},
	}))
	publishSignupRequested(t, rdb, "retry-user", "retry-corp")

	done := make(chan error, 1)
	go func() { done <- pipeline.Start(ctx) }()

	// Wait for failed status — should happen after 3 retries with 10ms base delay.
	state := waitForStatus(t, store, "retry-user", "failed", 10*time.Second)
	require.NotNil(t, state)
	assert.Equal(t, "failed", state.Status)
	assert.NotEmpty(t, state.Error, "error field must be set on failure")

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("pipeline did not stop after ctx cancel")
	}
}

// errInjected is the test-specific error for failure injection.
var errInjected = &injectedError{"injected test failure"}

type injectedError struct{ msg string }

func (e *injectedError) Error() string { return e.msg }

// ---------------------------------------------------------------------------
// TestSignupPipeline_IdempotentReplay
//
// Processes the same message twice. The second call should be a no-op because
// step_statuses["fga"] == "completed" after the first successful pass.
// ---------------------------------------------------------------------------

func TestSignupPipeline_IdempotentReplay(t *testing.T) {
	mr := miniredis.RunT(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	az := &mockAuthz{}
	prov := newMinimalProv(t, mr)
	store := newMemProvisioningStore()

	pipeline, rdb := buildPipelineTestState(t, mr, az, prov, store)

	require.NoError(t, store.Create(ctx, "idem-user", SignupState{
		Status:      "requested",
		Email:       "idem@example.com",
		CompanyName: "Idem Corp",
		TenantID:    "idem-corp",
		Plan:        "free",
		StepStatuses: map[string]string{
			"fga": "pending", "provision": "pending",
		},
	}))
	// Publish the same event twice.
	publishSignupRequested(t, rdb, "idem-user", "idem-corp")
	publishSignupRequested(t, rdb, "idem-user", "idem-corp")

	done := make(chan error, 1)
	go func() { done <- pipeline.Start(ctx) }()

	// The pipeline processes both messages; the second is a no-op for fga.
	state := waitForStatus(t, store, "idem-user", "active", 8*time.Second)
	require.NotNil(t, state)
	assert.Equal(t, "active", state.Status)

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("pipeline did not stop")
	}
}
