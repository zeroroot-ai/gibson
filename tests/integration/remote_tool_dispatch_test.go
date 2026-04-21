//go:build integration
// +build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zero-day-ai/gibson/internal/component"
	"github.com/zero-day-ai/gibson/internal/identity"
)

// newTestRedis starts a miniredis instance and returns a connected redis.Client.
// Both are registered for cleanup on test completion.
func newTestRedis(t *testing.T) (*redis.Client, *miniredis.Miniredis) {
	t.Helper()

	mr := miniredis.RunT(t)

	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	t.Cleanup(func() { _ = client.Close() })

	return client, mr
}

// newTestRegistry builds a RedisComponentRegistry with a short TTL suitable for tests.
func newTestRegistry(t *testing.T, client *redis.Client) component.ComponentRegistry {
	t.Helper()
	return component.NewRedisComponentRegistry(client, 30*time.Second)
}

// newTestWorkQueue builds a WorkQueue backed by the provided redis client.
func newTestWorkQueue(t *testing.T, client *redis.Client) component.WorkQueue {
	t.Helper()
	return component.NewRedisWorkQueue(client)
}

// mustMarshalJSON JSON-encodes v and fails the test on error.
func mustMarshalJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	require.NoError(t, err, "json.Marshal")
	return data
}

// mustUnmarshalJSON JSON-decodes data into v and fails the test on error.
func mustUnmarshalJSON(t *testing.T, data []byte, v any) {
	t.Helper()
	err := json.Unmarshal(data, v)
	require.NoError(t, err, "json.Unmarshal")
}

// claimWithRetry polls Claim until a work item arrives or the context is cancelled.
// blockTimeout controls how long each individual Claim call blocks before returning nil, nil.
func claimWithRetry(ctx context.Context, q component.WorkQueue, tenant, kind, name, consumerID string, blockTimeout time.Duration) (*component.WorkItem, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		item, err := q.Claim(ctx, tenant, kind, name, consumerID, blockTimeout)
		if err != nil {
			return nil, err
		}
		if item != nil {
			return item, nil
		}
	}
}

// TestRemoteToolDispatch_AgentCallsToolViaWorkQueue tests the full round-trip of
// a work item dispatched to a remote tool component:
//
//  1. Register tool "nmap" under _system tenant.
//  2. Goroutine A (harness side) enqueues a work item and blocks on WaitForResult.
//  3. Goroutine B (component side) claims the item, verifies payload, delivers
//     a mock result, and acknowledges the stream message.
//  4. Goroutine A unblocks and the caller asserts result correctness.
func TestRemoteToolDispatch_AgentCallsToolViaWorkQueue(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	client, _ := newTestRedis(t)
	reg := newTestRegistry(t, client)
	queue := newTestWorkQueue(t, client)

	// Register "nmap" as a system-level tool.
	instanceID, err := reg.Register(ctx, "_system", "tool", "nmap", component.ComponentInfo{
		Version: "7.94",
	})
	require.NoError(t, err, "Register nmap")
	t.Logf("registered nmap instance: %s", instanceID)

	type nmapRequest struct {
		Targets []string `json:"targets"`
	}
	type nmapResult struct {
		Hosts []string `json:"hosts"`
		Port  int      `json:"port"`
	}

	// Pre-assign the WorkID so both the enqueue caller and the WaitForResult caller
	// reference the same correlation ID. Enqueue takes WorkItem by value; it only
	// assigns a UUID when WorkID is empty, so the caller's copy would otherwise
	// remain empty.
	workID := uuid.New().String()

	workItem := component.WorkItem{
		WorkID:    workID,
		WorkType:  "tool",
		Payload:   mustMarshalJSON(t, nmapRequest{Targets: []string{"192.168.1.1"}}),
		Context:   map[string]string{"tenant": "_system"},
		TimeoutMs: 5000,
	}

	var (
		receivedResult *component.WorkResult
		harnessErr     error
		wg             sync.WaitGroup
	)

	// Goroutine A — harness/agent side: enqueue then block on WaitForResult.
	wg.Add(1)
	go func() {
		defer wg.Done()

		msgID, enqErr := queue.Enqueue(ctx, "_system", "tool", "nmap", workItem)
		if enqErr != nil {
			harnessErr = fmt.Errorf("enqueue: %w", enqErr)
			return
		}
		t.Logf("harness enqueued work item %s (stream msg: %s)", workID, msgID)

		result, waitErr := queue.WaitForResult(ctx, workID, 10*time.Second)
		if waitErr != nil {
			harnessErr = fmt.Errorf("WaitForResult: %w", waitErr)
			return
		}
		receivedResult = result
	}()

	// Goroutine B — remote tool component side: claim, verify, deliver, acknowledge.
	wg.Add(1)
	go func() {
		defer wg.Done()

		claimed, claimErr := claimWithRetry(ctx, queue, "_system", "tool", "nmap", "nmap-worker-1", 500*time.Millisecond)
		if claimErr != nil {
			t.Errorf("Claim failed: %v", claimErr)
			return
		}

		t.Logf("component claimed work item: %s", claimed.WorkID)
		assert.Equal(t, workID, claimed.WorkID, "claimed WorkID must match enqueued WorkID")

		var req nmapRequest
		mustUnmarshalJSON(t, claimed.Payload, &req)
		assert.Equal(t, []string{"192.168.1.1"}, req.Targets, "payload targets")

		mockOutput := mustMarshalJSON(t, nmapResult{Hosts: []string{"192.168.1.1"}, Port: 80})
		assert.NoError(t, queue.DeliverResult(ctx, claimed.WorkID, component.WorkResult{
			WorkID: claimed.WorkID,
			Result: mockOutput,
		}), "DeliverResult")
	}()

	wg.Wait()

	require.NoError(t, harnessErr, "harness goroutine must not error")
	require.NotNil(t, receivedResult, "WaitForResult must return a result")
	assert.Equal(t, workID, receivedResult.WorkID, "result WorkID must match")
	assert.Nil(t, receivedResult.Error, "result must carry no error")

	var out nmapResult
	mustUnmarshalJSON(t, receivedResult.Result, &out)
	assert.Equal(t, []string{"192.168.1.1"}, out.Hosts, "result hosts")
	assert.Equal(t, 80, out.Port, "result port")
}

// TestRemoteToolDispatch_SystemToolAccessibleFromAnyTenant verifies that a tool
// registered under _system is discoverable from any tenant context and that the
// full enqueue/claim/deliver/wait round-trip succeeds when initiated from a
// tenant-scoped context.
func TestRemoteToolDispatch_SystemToolAccessibleFromAnyTenant(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	client, _ := newTestRedis(t)
	reg := newTestRegistry(t, client)
	queue := newTestWorkQueue(t, client)

	// Register httpx under _system.
	_, err := reg.Register(ctx, "_system", "tool", "httpx", component.ComponentInfo{
		Version: "1.6.0",
	})
	require.NoError(t, err, "Register httpx")

	// Build a tenant-a context and confirm tenant extraction.
	tenantCtx := identity.ContextWithTenant(ctx, "tenant-a")
	require.Equal(t, "tenant-a", identity.TenantFromContext(tenantCtx))

	// Discover from tenant-a — Discover falls back to _system automatically.
	instances, err := reg.Discover(tenantCtx, "tenant-a", "tool", "httpx")
	require.NoError(t, err, "Discover httpx from tenant-a context")
	require.NotEmpty(t, instances, "tenant-a must see the _system httpx registration")
	assert.Equal(t, "_system", instances[0].TenantID, "found instance must belong to _system")

	type httpxPayload struct {
		Target string `json:"target"`
	}
	type httpxResult struct {
		URLs   []string `json:"urls"`
		Status int      `json:"status"`
	}

	workID := uuid.New().String()
	workItem := component.WorkItem{
		WorkID:   workID,
		WorkType: "tool",
		Payload:  mustMarshalJSON(t, httpxPayload{Target: "https://example.com"}),
		Context:  map[string]string{"tenant": "tenant-a"},
		// Work is enqueued against _system stream because that is where httpx is
		// registered; the context carries the originating tenant for audit purposes.
		TimeoutMs: 5000,
	}

	var (
		receivedResult *component.WorkResult
		harnessErr     error
		wg             sync.WaitGroup
	)

	// Harness goroutine: enqueue against _system stream and wait.
	wg.Add(1)
	go func() {
		defer wg.Done()

		msgID, enqErr := queue.Enqueue(tenantCtx, "_system", "tool", "httpx", workItem)
		if enqErr != nil {
			harnessErr = fmt.Errorf("enqueue: %w", enqErr)
			return
		}
		t.Logf("harness enqueued httpx work item %s (stream msg: %s)", workID, msgID)

		result, waitErr := queue.WaitForResult(tenantCtx, workID, 10*time.Second)
		if waitErr != nil {
			harnessErr = fmt.Errorf("WaitForResult: %w", waitErr)
			return
		}
		receivedResult = result
	}()

	// Component goroutine: claim from _system stream and deliver.
	wg.Add(1)
	go func() {
		defer wg.Done()

		claimed, claimErr := claimWithRetry(ctx, queue, "_system", "tool", "httpx", "httpx-worker-1", 500*time.Millisecond)
		if claimErr != nil {
			t.Errorf("Claim failed: %v", claimErr)
			return
		}

		t.Logf("httpx component claimed work item: %s", claimed.WorkID)
		assert.Equal(t, workID, claimed.WorkID)
		assert.Equal(t, "tenant-a", claimed.Context["tenant"], "originating tenant preserved in context")

		mockOut := mustMarshalJSON(t, httpxResult{
			URLs:   []string{"https://example.com/index.html"},
			Status: 200,
		})
		assert.NoError(t, queue.DeliverResult(ctx, claimed.WorkID, component.WorkResult{
			WorkID: claimed.WorkID,
			Result: mockOut,
		}), "DeliverResult httpx")
	}()

	wg.Wait()

	require.NoError(t, harnessErr, "harness goroutine must not error")
	require.NotNil(t, receivedResult, "must receive a result")
	assert.Equal(t, workID, receivedResult.WorkID)
	assert.Nil(t, receivedResult.Error)

	var out httpxResult
	mustUnmarshalJSON(t, receivedResult.Result, &out)
	assert.Equal(t, 200, out.Status)
	assert.Contains(t, out.URLs, "https://example.com/index.html")
}

// TestRemoteToolDispatch_TenantScopedPluginDispatch verifies the end-to-end
// round-trip for a plugin registered under a specific tenant ("acme").
//
//  1. Register plugin "gitlab" under tenant "acme".
//  2. Discover within acme to confirm registration is visible.
//  3. Enqueue work item against the acme:plugin:gitlab stream.
//  4. Component claims, verifies method in payload and tenant context, delivers result.
//  5. Caller asserts result payload.
func TestRemoteToolDispatch_TenantScopedPluginDispatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	client, _ := newTestRedis(t)
	reg := newTestRegistry(t, client)
	queue := newTestWorkQueue(t, client)

	// Register the plugin under tenant "acme".
	instanceID, err := reg.Register(ctx, "acme", "plugin", "gitlab", component.ComponentInfo{
		Version: "2.0.0",
		Metadata: map[string]string{
			"methods": "list_projects,get_project,create_issue",
		},
	})
	require.NoError(t, err, "Register gitlab plugin")
	t.Logf("registered gitlab plugin instance: %s", instanceID)

	// Confirm the plugin is discoverable within the acme tenant.
	instances, err := reg.Discover(ctx, "acme", "plugin", "gitlab")
	require.NoError(t, err)
	require.Len(t, instances, 1, "should find exactly one gitlab plugin instance")
	assert.Equal(t, "acme", instances[0].TenantID)
	assert.Equal(t, "2.0.0", instances[0].Version)
	assert.Equal(t, "list_projects,get_project,create_issue", instances[0].Metadata["methods"])

	type pluginPayload struct {
		Method string         `json:"method"`
		Params map[string]any `json:"params"`
	}
	type pluginResult struct {
		Projects []string `json:"projects"`
	}

	workID := uuid.New().String()
	workItem := component.WorkItem{
		WorkID:   workID,
		WorkType: "plugin",
		Payload: mustMarshalJSON(t, pluginPayload{
			Method: "list_projects",
			Params: map[string]any{"visibility": "private"},
		}),
		Context:   map[string]string{"tenant": "acme"},
		TimeoutMs: 5000,
	}

	var (
		receivedResult *component.WorkResult
		harnessErr     error
		wg             sync.WaitGroup
	)

	// Harness goroutine.
	wg.Add(1)
	go func() {
		defer wg.Done()

		msgID, enqErr := queue.Enqueue(ctx, "acme", "plugin", "gitlab", workItem)
		if enqErr != nil {
			harnessErr = fmt.Errorf("enqueue: %w", enqErr)
			return
		}
		t.Logf("harness enqueued gitlab plugin work item %s (stream msg: %s)", workID, msgID)

		result, waitErr := queue.WaitForResult(ctx, workID, 10*time.Second)
		if waitErr != nil {
			harnessErr = fmt.Errorf("WaitForResult: %w", waitErr)
			return
		}
		receivedResult = result
	}()

	// Plugin component goroutine.
	wg.Add(1)
	go func() {
		defer wg.Done()

		claimed, claimErr := claimWithRetry(ctx, queue, "acme", "plugin", "gitlab", "gitlab-worker-1", 500*time.Millisecond)
		if claimErr != nil {
			t.Errorf("Claim failed: %v", claimErr)
			return
		}

		t.Logf("gitlab plugin claimed work item: %s", claimed.WorkID)
		assert.Equal(t, workID, claimed.WorkID, "claimed WorkID must match")
		assert.Equal(t, "plugin", claimed.WorkType, "work type must be plugin")
		assert.Equal(t, "acme", claimed.Context["tenant"], "tenant context must be acme")

		var pl pluginPayload
		mustUnmarshalJSON(t, claimed.Payload, &pl)
		assert.Equal(t, "list_projects", pl.Method, "payload method")
		assert.Equal(t, "private", pl.Params["visibility"], "payload params")

		mockOut := mustMarshalJSON(t, pluginResult{
			Projects: []string{"acme/webapp", "acme/backend", "acme/infra"},
		})
		assert.NoError(t, queue.DeliverResult(ctx, claimed.WorkID, component.WorkResult{
			WorkID: claimed.WorkID,
			Result: mockOut,
		}), "DeliverResult gitlab")
	}()

	wg.Wait()

	require.NoError(t, harnessErr, "harness goroutine must not error")
	require.NotNil(t, receivedResult, "must receive a result")
	assert.Equal(t, workID, receivedResult.WorkID)
	assert.Nil(t, receivedResult.Error)

	var out pluginResult
	mustUnmarshalJSON(t, receivedResult.Result, &out)
	assert.ElementsMatch(t, []string{"acme/webapp", "acme/backend", "acme/infra"}, out.Projects)
}

// TestRemoteToolDispatch_WorkItemTimeout verifies that WaitForResult returns a
// deadline-exceeded error when no component claims and delivers a result within
// the configured timeout window.
func TestRemoteToolDispatch_WorkItemTimeout(t *testing.T) {
	ctx := context.Background()
	client, _ := newTestRedis(t)
	queue := newTestWorkQueue(t, client)

	workID := uuid.New().String()
	workItem := component.WorkItem{
		WorkID:    workID,
		WorkType:  "tool",
		Payload:   mustMarshalJSON(t, map[string]string{"target": "10.0.0.1"}),
		Context:   map[string]string{"tenant": "_system"},
		TimeoutMs: 100,
	}

	// Enqueue the item so it is sitting in the stream — but nobody will claim
	// or deliver a result within the short WaitForResult timeout.
	msgID, err := queue.Enqueue(ctx, "_system", "tool", "slow-tool", workItem)
	require.NoError(t, err, "Enqueue must succeed")
	t.Logf("enqueued work item %s (stream msg: %s); waiting with 100ms timeout", workID, msgID)

	// WaitForResult must time out because the result is never delivered.
	result, waitErr := queue.WaitForResult(ctx, workID, 100*time.Millisecond)

	assert.Nil(t, result, "result must be nil on timeout")
	require.Error(t, waitErr, "WaitForResult must return an error on timeout")
	assert.Contains(t, waitErr.Error(), workID,
		"error message must reference the work ID for correlation")
	assert.Contains(t, waitErr.Error(), "timeout",
		"error message must indicate a timeout condition")
}
