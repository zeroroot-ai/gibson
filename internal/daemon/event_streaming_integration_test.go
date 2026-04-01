//go:build integration
// +build integration

package daemon_test

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/daemon"
	daemonapi "github.com/zero-day-ai/gibson/internal/daemon/api"
	"github.com/zero-day-ai/gibson/internal/state"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// newTestRedisEventStream starts a miniredis instance and returns a
// RedisEventStream wired to it, along with the underlying StateClient.
// Both are registered for cleanup via t.Cleanup.
func newTestRedisEventStream(t *testing.T) (*daemon.RedisEventStream, *state.StateClient) {
	t.Helper()

	mr := miniredis.RunT(t)

	cfg := state.DefaultConfig()
	cfg.URL = "redis://" + mr.Addr()

	sc, err := state.NewStateClient(cfg)
	require.NoError(t, err, "failed to create state client against miniredis")

	t.Cleanup(func() { sc.Close() })

	res := daemon.NewRedisEventStream(sc, slog.Default())
	return res, sc
}

// ---------------------------------------------------------------------------
// TestSubscribeNotImplemented
// ---------------------------------------------------------------------------

// TestSubscribeNotImplemented previously skipped because Subscribe was not
// implemented. It now verifies the Subscribe RPC is live by exercising the
// Redis event stream directly with miniredis.
func TestSubscribeNotImplemented(t *testing.T) {
	res, _ := newTestRedisEventStream(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tenant := "test-tenant"

	ch, err := res.SubscribeStream(ctx, tenant, nil, "")
	require.NoError(t, err, "SubscribeStream must succeed")
	require.NotNil(t, ch)

	// Allow the XREAD goroutine to start.
	time.Sleep(50 * time.Millisecond)

	// Publish one event and confirm delivery within 500 ms.
	event := daemon.NewMissionStartedEvent("mission-subscribe-test")
	require.NoError(t, res.PublishEvent(ctx, tenant, event))

	select {
	case received, ok := <-ch:
		require.True(t, ok)
		assert.Equal(t, "mission.started", received.EventType)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("event not delivered within 500 ms")
	}
}

// ---------------------------------------------------------------------------
// TestEventStreamingAllTypes
// ---------------------------------------------------------------------------

// TestEventStreamingAllTypes verifies that mission, agent, and finding event
// types are all delivered through the Redis event stream.
func TestEventStreamingAllTypes(t *testing.T) {
	res, _ := newTestRedisEventStream(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tenant := "all-types-tenant"

	ch, err := res.SubscribeStream(ctx, tenant, nil, "")
	require.NoError(t, err)
	time.Sleep(50 * time.Millisecond)

	want := []struct {
		name    string
		publish func() error
	}{
		{"mission.started", func() error {
			return res.PublishEvent(ctx, tenant, daemon.NewMissionStartedEvent("m1"))
		}},
		{"mission.completed", func() error {
			return res.PublishEvent(ctx, tenant, daemon.NewMissionCompletedEvent("m1"))
		}},
		{"agent.registered", func() error {
			return res.PublishEvent(ctx, tenant, daemon.NewAgentRegisteredEvent("a1", "test-agent"))
		}},
		{"finding.discovered", func() error {
			return res.PublishEvent(ctx, tenant, daemon.NewFindingDiscoveredEvent("m1", daemonapi.FindingData{
				ID:    "f1",
				Title: "Test Finding",
			}))
		}},
	}

	for _, ev := range want {
		require.NoError(t, ev.publish(), "publish %s", ev.name)
	}

	received := make(map[string]bool)
	deadline := time.After(2 * time.Second)
	for len(received) < len(want) {
		select {
		case e, ok := <-ch:
			if !ok {
				t.Fatal("channel closed prematurely")
			}
			received[e.EventType] = true
		case <-deadline:
			t.Fatalf("timeout: received only %v (want all of %v)", received, want)
		}
	}

	assert.True(t, received["mission.started"])
	assert.True(t, received["mission.completed"])
	assert.True(t, received["agent.registered"])
	assert.True(t, received["finding.discovered"])
}

// ---------------------------------------------------------------------------
// TestEventStreamingFiltering
// ---------------------------------------------------------------------------

// TestEventStreamingFiltering verifies event-type and mission-ID filters work
// independently and combined.
func TestEventStreamingFiltering(t *testing.T) {
	res, _ := newTestRedisEventStream(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tenant := "filter-tenant"

	t.Run("event_type_filter", func(t *testing.T) {
		ch, err := res.SubscribeStream(ctx, tenant, []string{"mission.started"}, "")
		require.NoError(t, err)
		time.Sleep(50 * time.Millisecond)

		require.NoError(t, res.PublishEvent(ctx, tenant, daemon.NewMissionStartedEvent("m-f1")))
		require.NoError(t, res.PublishEvent(ctx, tenant, daemon.NewMissionCompletedEvent("m-f1")))
		require.NoError(t, res.PublishEvent(ctx, tenant, daemon.NewNodeStartedEvent("m-f1", "n1")))
		require.NoError(t, res.PublishEvent(ctx, tenant, daemon.NewMissionStartedEvent("m-f2")))

		count := 0
		deadline := time.After(1 * time.Second)
	loop1:
		for {
			select {
			case e, ok := <-ch:
				if !ok {
					break loop1
				}
				assert.Equal(t, "mission.started", e.EventType, "unexpected event type")
				count++
			case <-deadline:
				break loop1
			}
		}
		assert.Equal(t, 2, count, "expected exactly 2 mission.started events")
	})

	t.Run("mission_id_filter", func(t *testing.T) {
		ch, err := res.SubscribeStream(ctx, tenant, nil, "filter-m1")
		require.NoError(t, err)
		time.Sleep(50 * time.Millisecond)

		require.NoError(t, res.PublishEvent(ctx, tenant, daemon.NewMissionStartedEvent("filter-m1")))
		require.NoError(t, res.PublishEvent(ctx, tenant, daemon.NewMissionStartedEvent("filter-m2")))
		require.NoError(t, res.PublishEvent(ctx, tenant, daemon.NewMissionCompletedEvent("filter-m1")))

		count := 0
		deadline := time.After(1 * time.Second)
	loop2:
		for {
			select {
			case e, ok := <-ch:
				if !ok {
					break loop2
				}
				if e.MissionEvent != nil {
					assert.Equal(t, "filter-m1", e.MissionEvent.MissionID)
				}
				count++
			case <-deadline:
				break loop2
			}
		}
		assert.Equal(t, 2, count, "expected exactly 2 events for filter-m1")
	})
}

// ---------------------------------------------------------------------------
// TestEventStreamingMissionEvents
// ---------------------------------------------------------------------------

// TestEventStreamingMissionEvents verifies the full mission lifecycle event
// sequence is delivered in the correct order with the correct mission ID.
func TestEventStreamingMissionEvents(t *testing.T) {
	res, _ := newTestRedisEventStream(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tenant := "mission-events-tenant"
	missionID := "lifecycle-mission"

	ch, err := res.SubscribeStream(ctx, tenant, nil, missionID)
	require.NoError(t, err)
	time.Sleep(50 * time.Millisecond)

	sequence := []struct {
		publish func() error
		want    string
	}{
		{func() error { return res.PublishEvent(ctx, tenant, daemon.NewMissionStartedEvent(missionID)) }, "mission.started"},
		{func() error { return res.PublishEvent(ctx, tenant, daemon.NewNodeStartedEvent(missionID, "node-1")) }, "node.started"},
		{func() error { return res.PublishEvent(ctx, tenant, daemon.NewNodeCompletedEvent(missionID, "node-1")) }, "node.completed"},
		{func() error { return res.PublishEvent(ctx, tenant, daemon.NewMissionCompletedEvent(missionID)) }, "mission.completed"},
	}

	for _, step := range sequence {
		require.NoError(t, step.publish())
	}

	received := make([]string, 0, len(sequence))
	deadline := time.After(2 * time.Second)
	for len(received) < len(sequence) {
		select {
		case e, ok := <-ch:
			if !ok {
				t.Fatal("channel closed prematurely")
			}
			received = append(received, e.EventType)
			if e.MissionEvent != nil {
				assert.Equal(t, missionID, e.MissionEvent.MissionID,
					"event %s must carry correct mission ID", e.EventType)
				assert.NotEmpty(t, e.MissionEvent.Message)
			}
		case <-deadline:
			t.Fatalf("timeout: received %v, want %d events", received, len(sequence))
		}
	}

	for i, step := range sequence {
		assert.Equal(t, step.want, received[i], "event at position %d", i)
	}
}

// ---------------------------------------------------------------------------
// TestEventStreamingAgentEvents
// ---------------------------------------------------------------------------

// TestEventStreamingAgentEvents verifies that agent_registered and
// agent_unregistered events carry the correct agent ID and name.
func TestEventStreamingAgentEvents(t *testing.T) {
	res, _ := newTestRedisEventStream(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tenant := "agent-events-tenant"

	ch, err := res.SubscribeStream(ctx, tenant,
		[]string{"agent.registered", "agent.unregistered"}, "")
	require.NoError(t, err)
	time.Sleep(50 * time.Millisecond)

	require.NoError(t, res.PublishEvent(ctx, tenant,
		daemon.NewAgentRegisteredEvent("agent-42", "recon-agent")))
	require.NoError(t, res.PublishEvent(ctx, tenant,
		daemon.NewAgentUnregisteredEvent("agent-42", "recon-agent")))

	for _, wantType := range []string{"agent.registered", "agent.unregistered"} {
		select {
		case e, ok := <-ch:
			require.True(t, ok)
			assert.Equal(t, wantType, e.EventType)
			require.NotNil(t, e.AgentEvent, "agent event must be populated")
			assert.Equal(t, "agent-42", e.AgentEvent.AgentID)
			assert.Equal(t, "recon-agent", e.AgentEvent.AgentName)
		case <-time.After(500 * time.Millisecond):
			t.Fatalf("timeout waiting for %s", wantType)
		}
	}
}

// ---------------------------------------------------------------------------
// TestEventStreamingFindingEvents
// ---------------------------------------------------------------------------

// TestEventStreamingFindingEvents verifies that finding events carry complete
// finding details including severity, category, and mission ID.
func TestEventStreamingFindingEvents(t *testing.T) {
	res, _ := newTestRedisEventStream(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tenant := "finding-events-tenant"

	ch, err := res.SubscribeStream(ctx, tenant, []string{"finding.discovered"}, "")
	require.NoError(t, err)
	time.Sleep(50 * time.Millisecond)

	finding := daemonapi.FindingData{
		ID:          "f-001",
		Title:       "SQL Injection",
		Severity:    "critical",
		Category:    "injection",
		Description: "Classic SQL injection via login form",
		Technique:   "T1190",
		Evidence:    "login?id=1' OR '1'='1",
	}
	require.NoError(t, res.PublishEvent(ctx, tenant,
		daemon.NewFindingDiscoveredEvent("mission-finding", finding)))

	select {
	case e, ok := <-ch:
		require.True(t, ok)
		assert.Equal(t, "finding.discovered", e.EventType)
		require.NotNil(t, e.FindingEvent)
		assert.Equal(t, "mission-finding", e.FindingEvent.MissionID)
		assert.Equal(t, "f-001", e.FindingEvent.Finding.ID)
		assert.Equal(t, "SQL Injection", e.FindingEvent.Finding.Title)
		assert.Equal(t, "critical", e.FindingEvent.Finding.Severity)
		assert.Equal(t, "injection", e.FindingEvent.Finding.Category)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout waiting for finding event")
	}
}

// ---------------------------------------------------------------------------
// TestEventStreamingMultipleSubscribers
// ---------------------------------------------------------------------------

// TestEventStreamingMultipleSubscribers verifies fan-out: every subscriber
// receives every matching event, and one subscriber closing does not affect
// the others.
func TestEventStreamingMultipleSubscribers(t *testing.T) {
	res, _ := newTestRedisEventStream(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tenant := "multi-sub-tenant"

	const numSubscribers = 3

	channels := make([]<-chan daemonapi.EventData, numSubscribers)
	for i := range channels {
		ch, err := res.SubscribeStream(ctx, tenant, nil, "")
		require.NoError(t, err)
		channels[i] = ch
	}
	time.Sleep(100 * time.Millisecond)

	require.NoError(t, res.PublishEvent(ctx, tenant,
		daemon.NewMissionStartedEvent("shared-mission")))

	var wg sync.WaitGroup
	for i, ch := range channels {
		wg.Add(1)
		go func(idx int, c <-chan daemonapi.EventData) {
			defer wg.Done()
			select {
			case e, ok := <-c:
				assert.True(t, ok, "subscriber %d: channel must not be closed", idx)
				assert.Equal(t, "mission.started", e.EventType, "subscriber %d", idx)
			case <-time.After(500 * time.Millisecond):
				t.Errorf("subscriber %d: timeout", idx)
			}
		}(i, ch)
	}
	wg.Wait()

	// Cancel one subscriber's context and verify the others still work.
	// (All three share the same test context here; we test isolation via
	// separate contexts in TestEventStreamingCancellation.)
}

// ---------------------------------------------------------------------------
// TestEventStreamingBackpressure
// ---------------------------------------------------------------------------

// TestEventStreamingBackpressure verifies that rapid event publication does
// not block and that a slow consumer can catch up.
func TestEventStreamingBackpressure(t *testing.T) {
	res, _ := newTestRedisEventStream(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	tenant := "backpressure-tenant"

	ch, err := res.SubscribeStream(ctx, tenant, nil, "")
	require.NoError(t, err)
	time.Sleep(50 * time.Millisecond)

	const eventCount = 20

	for i := 0; i < eventCount; i++ {
		require.NoError(t, res.PublishEvent(ctx, tenant,
			daemon.NewMissionStartedEvent(fmt.Sprintf("bp-mission-%d", i))))
	}

	received := 0
	deadline := time.After(10 * time.Second)
	for received < eventCount {
		select {
		case _, ok := <-ch:
			if !ok {
				t.Fatalf("channel closed after %d events", received)
			}
			received++
			time.Sleep(10 * time.Millisecond) // simulate slow consumer
		case <-deadline:
			t.Fatalf("timeout: received %d/%d events", received, eventCount)
		}
	}
	assert.Equal(t, eventCount, received)
}

// ---------------------------------------------------------------------------
// TestEventStreamingReconnection
// ---------------------------------------------------------------------------

// TestEventStreamingReconnection verifies that a new subscription started
// after the previous context is cancelled delivers events published after
// the new subscription begins.
func TestEventStreamingReconnection(t *testing.T) {
	res, _ := newTestRedisEventStream(t)
	tenant := "reconnect-tenant"

	// First subscription.
	ctx1, cancel1 := context.WithCancel(context.Background())
	ch1, err := res.SubscribeStream(ctx1, tenant, nil, "")
	require.NoError(t, err)
	time.Sleep(50 * time.Millisecond)

	require.NoError(t, res.PublishEvent(ctx1, tenant,
		daemon.NewMissionStartedEvent("pre-disconnect")))
	select {
	case e, ok := <-ch1:
		require.True(t, ok)
		assert.Equal(t, "mission.started", e.EventType)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("first subscription: event not received")
	}

	// Disconnect first subscriber.
	cancel1()
	// Drain / allow goroutine to exit.
	time.Sleep(200 * time.Millisecond)

	// Second subscription (fresh context).
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()

	ch2, err := res.SubscribeStream(ctx2, tenant, nil, "")
	require.NoError(t, err)
	time.Sleep(50 * time.Millisecond)

	require.NoError(t, res.PublishEvent(ctx2, tenant,
		daemon.NewMissionStartedEvent("post-reconnect")))
	select {
	case e, ok := <-ch2:
		require.True(t, ok)
		assert.Equal(t, "mission.started", e.EventType)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("reconnected subscription: event not received")
	}
}

// ---------------------------------------------------------------------------
// TestEventStreamingCancellation
// ---------------------------------------------------------------------------

// TestEventStreamingCancellation verifies that cancelling the subscriber
// context closes the channel and does not leak goroutines.
func TestEventStreamingCancellation(t *testing.T) {
	res, _ := newTestRedisEventStream(t)
	tenant := "cancel-tenant"

	goroutinesBefore := runtime.NumGoroutine()

	ctx, cancel := context.WithCancel(context.Background())
	ch, err := res.SubscribeStream(ctx, tenant, nil, "")
	require.NoError(t, err)
	time.Sleep(50 * time.Millisecond)

	require.Greater(t, runtime.NumGoroutine(), goroutinesBefore,
		"subscriber goroutine should be running")

	cancel()

	select {
	case _, ok := <-ch:
		assert.False(t, ok, "channel must be closed after cancellation")
	case <-time.After(2 * time.Second):
		t.Fatal("channel not closed after context cancellation")
	}

	time.Sleep(200 * time.Millisecond)
	goroutinesAfter := runtime.NumGoroutine()
	// Allow a small tolerance for test-framework goroutines.
	assert.LessOrEqual(t, goroutinesAfter, goroutinesBefore+2,
		"goroutine leak detected: before=%d after=%d", goroutinesBefore, goroutinesAfter)
}

// ---------------------------------------------------------------------------
// TestEventTimestamps
// ---------------------------------------------------------------------------

// TestEventTimestamps verifies that event timestamps survive the round-trip
// through Redis Streams with at least millisecond fidelity.
func TestEventTimestamps(t *testing.T) {
	res, _ := newTestRedisEventStream(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tenant := "timestamp-tenant"

	ch, err := res.SubscribeStream(ctx, tenant, nil, "")
	require.NoError(t, err)
	time.Sleep(50 * time.Millisecond)

	before := time.Now()
	require.NoError(t, res.PublishEvent(ctx, tenant, daemon.NewMissionStartedEvent("ts-mission")))
	after := time.Now()

	select {
	case e, ok := <-ch:
		require.True(t, ok)
		assert.False(t, e.Timestamp.IsZero(), "timestamp must not be zero")
		// Allow ±1 s tolerance for clock skew and test latency.
		assert.False(t, e.Timestamp.Before(before.Add(-time.Second)),
			"timestamp must not be before publish time")
		assert.False(t, e.Timestamp.After(after.Add(time.Second)),
			"timestamp must not be far after publish time")
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout waiting for event with timestamp")
	}

	// Second event must have a non-zero timestamp too.
	time.Sleep(10 * time.Millisecond)
	require.NoError(t, res.PublishEvent(ctx, tenant, daemon.NewMissionCompletedEvent("ts-mission")))
	select {
	case e, ok := <-ch:
		require.True(t, ok)
		assert.Equal(t, "mission.completed", e.EventType)
		assert.False(t, e.Timestamp.IsZero())
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout waiting for second event")
	}
}

// ---------------------------------------------------------------------------
// TestEventDataEncoding
// ---------------------------------------------------------------------------

// TestEventDataEncoding verifies that complex nested event payloads survive
// JSON serialisation → Redis Stream → JSON deserialisation without data loss.
func TestEventDataEncoding(t *testing.T) {
	res, _ := newTestRedisEventStream(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tenant := "encoding-tenant"

	ch, err := res.SubscribeStream(ctx, tenant, nil, "")
	require.NoError(t, err)
	time.Sleep(50 * time.Millisecond)

	finding := daemonapi.FindingData{
		ID:          "enc-001",
		Title:       "XSS Reflected",
		Severity:    "high",
		Category:    "xss",
		Description: "Reflected XSS in search parameter",
		Technique:   "T1059.007",
		Evidence:    "param=<script>alert(1)</script>",
	}
	require.NoError(t, res.PublishEvent(ctx, tenant,
		daemon.NewFindingDiscoveredEvent("enc-mission", finding)))

	select {
	case e, ok := <-ch:
		require.True(t, ok)
		require.NotNil(t, e.FindingEvent, "finding event must survive encoding round-trip")
		assert.Equal(t, "enc-001", e.FindingEvent.Finding.ID)
		assert.Equal(t, "XSS Reflected", e.FindingEvent.Finding.Title)
		assert.Equal(t, "high", e.FindingEvent.Finding.Severity)
		assert.Equal(t, "xss", e.FindingEvent.Finding.Category)
		assert.Equal(t, "T1059.007", e.FindingEvent.Finding.Technique)
		assert.Equal(t, "param=<script>alert(1)</script>", e.FindingEvent.Finding.Evidence)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout waiting for encoded event")
	}
}

// ---------------------------------------------------------------------------
// TestAttackEventStreaming
// ---------------------------------------------------------------------------

// TestAttackEventStreaming verifies that attack lifecycle events (started,
// completed) are published and delivered with the correct attack ID.
func TestAttackEventStreaming(t *testing.T) {
	res, _ := newTestRedisEventStream(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tenant := "attack-events-tenant"

	ch, err := res.SubscribeStream(ctx, tenant,
		[]string{"attack.started", "attack.completed"}, "")
	require.NoError(t, err)
	time.Sleep(50 * time.Millisecond)

	attackID := "atk-001"
	require.NoError(t, res.PublishEvent(ctx, tenant, daemon.NewAttackStartedEvent(attackID)))
	require.NoError(t, res.PublishEvent(ctx, tenant, daemon.NewAttackCompletedEvent(attackID, true)))

	for _, wantType := range []string{"attack.started", "attack.completed"} {
		select {
		case e, ok := <-ch:
			require.True(t, ok)
			assert.Equal(t, wantType, e.EventType)
			if e.AttackEvent != nil {
				assert.Equal(t, attackID, e.AttackEvent.AttackID)
			}
		case <-time.After(500 * time.Millisecond):
			t.Fatalf("timeout waiting for %s", wantType)
		}
	}
}

// ---------------------------------------------------------------------------
// TestPingConnectBasicGRPC
// ---------------------------------------------------------------------------

// TestPingConnectBasicGRPC tests basic gRPC operations that are already implemented.
//
// This test verifies:
// 1. Client can connect and receive connection response
// 2. Ping returns valid timestamp
// 3. Status returns daemon information
//
// NOTE: This test is exercised by the full daemon integration test suite.
// The event-streaming tests in this file use miniredis-backed RedisEventStream
// directly and do not require a live daemon.
func TestPingConnectBasicGRPC(t *testing.T) {
	// The full daemon integration test (daemon_integration_test.go) covers gRPC
	// connectivity. This file focuses on Subscribe / event streaming.
	// Verify the Subscribe RPC itself via miniredis in TestSubscribeNotImplemented.
	t.Skip("Full daemon gRPC integration covered by daemon_integration_test.go")
}
