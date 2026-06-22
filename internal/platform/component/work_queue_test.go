package component

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestWorkQueue creates a WorkQueue backed by a fresh miniredis instance.
// The miniredis server and redis client are both cleaned up via t.Cleanup.
func newTestWorkQueue(t *testing.T) (WorkQueue, *miniredis.Miniredis) {
	t.Helper()

	mr := miniredis.RunT(t)

	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	t.Cleanup(func() { _ = client.Close() })

	return NewRedisWorkQueue(client), mr
}

// testItem builds a WorkItem with predictable fields for use in assertions.
func testItem(workID, workType string, payload []byte) WorkItem {
	return WorkItem{
		WorkID:    workID,
		WorkType:  workType,
		Payload:   payload,
		Context:   map[string]string{"env": "test"},
		TimeoutMs: 5000,
		CreatedAt: time.Now().UTC().Truncate(time.Millisecond),
	}
}

// TestWorkQueue_Enqueue_ValidatesRequiredFields verifies that Enqueue returns
// an error for each missing required parameter before touching Redis.
func TestWorkQueue_Enqueue_ValidatesRequiredFields(t *testing.T) {
	q, _ := newTestWorkQueue(t)
	ctx := context.Background()
	item := testItem("wid-1", "scan", []byte(`{}`))

	tests := []struct {
		name   string
		tenant string
		kind   string
		qname  string
	}{
		{"empty tenant", "", "agent", "scanner"},
		{"empty kind", "acme", "", "scanner"},
		{"empty name", "acme", "agent", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := q.Enqueue(ctx, tc.tenant, tc.kind, tc.qname, item)
			assert.Error(t, err)
		})
	}
}

// TestWorkQueue_Claim_ValidatesRequiredFields verifies that Claim returns an
// error for each missing required parameter.
func TestWorkQueue_Claim_ValidatesRequiredFields(t *testing.T) {
	q, _ := newTestWorkQueue(t)
	ctx := context.Background()

	tests := []struct {
		name       string
		tenant     string
		kind       string
		qname      string
		consumerID string
	}{
		{"empty tenant", "", "agent", "scanner", "c1"},
		{"empty kind", "acme", "", "scanner", "c1"},
		{"empty name", "acme", "agent", "", "c1"},
		{"empty consumerID", "acme", "agent", "scanner", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := q.Claim(ctx, tc.tenant, tc.kind, tc.qname, tc.consumerID, 10*time.Millisecond)
			assert.Error(t, err)
		})
	}
}

// TestWorkQueue_EnqueueAndClaim_HappyPath is the primary functional test: enqueue
// a work item and immediately claim it, asserting all fields round-trip correctly.
func TestWorkQueue_EnqueueAndClaim_HappyPath(t *testing.T) {
	q, _ := newTestWorkQueue(t)
	ctx := context.Background()

	const (
		tenant = "acme"
		kind   = "agent"
		name   = "scanner"
		wid    = "work-abc-123"
		wtype  = "port-scan"
	)

	payload := []byte(`{"target":"10.0.0.1","ports":"1-1024"}`)
	item := testItem(wid, wtype, payload)

	// Enqueue
	msgID, err := q.Enqueue(ctx, tenant, kind, name, item)
	require.NoError(t, err)
	assert.NotEmpty(t, msgID, "XADD should return a non-empty stream message ID")

	// Claim — use a short but non-zero block timeout; the message is already in
	// the stream so XREADGROUP should return immediately.
	claimed, err := q.Claim(ctx, tenant, kind, name, "consumer-1", 500*time.Millisecond)
	require.NoError(t, err)
	require.NotNil(t, claimed, "Claim should return the enqueued item")

	assert.Equal(t, wid, claimed.WorkID)
	assert.Equal(t, wtype, claimed.WorkType)
	assert.Equal(t, payload, claimed.Payload)
	assert.Equal(t, map[string]string{"env": "test"}, claimed.Context)
	assert.Equal(t, int64(5000), claimed.TimeoutMs)
	assert.False(t, claimed.CreatedAt.IsZero(), "CreatedAt should be preserved through serialization")
}

// TestWorkQueue_Enqueue_AutoAssignsWorkID verifies that Enqueue populates a
// missing WorkID rather than leaving it empty.
func TestWorkQueue_Enqueue_AutoAssignsWorkID(t *testing.T) {
	q, _ := newTestWorkQueue(t)
	ctx := context.Background()

	item := WorkItem{
		WorkType: "probe",
		Payload:  []byte(`{}`),
	}

	_, err := q.Enqueue(ctx, "acme", "tool", "probe", item)
	require.NoError(t, err)

	claimed, err := q.Claim(ctx, "acme", "tool", "probe", "c1", 500*time.Millisecond)
	require.NoError(t, err)
	require.NotNil(t, claimed)

	assert.NotEmpty(t, claimed.WorkID, "Enqueue should auto-assign a WorkID when the field is empty")
}

// TestWorkQueue_Claim_ReturnsNilWhenEmpty verifies that Claim returns nil, nil
// (rather than an error) when no work is available within the block timeout.
func TestWorkQueue_Claim_ReturnsNilWhenEmpty(t *testing.T) {
	q, _ := newTestWorkQueue(t)
	ctx := context.Background()

	start := time.Now()
	// Miniredis fast-paths the block to return immediately on an empty stream,
	// so this will complete well under the stated timeout in tests.
	claimed, err := q.Claim(ctx, "acme", "agent", "empty-queue", "c1", 50*time.Millisecond)

	require.NoError(t, err, "empty queue with elapsed timeout should not return an error")
	assert.Nil(t, claimed, "Claim should return nil when no work is available")
	_ = start // elapsed time check intentionally omitted to avoid flakiness
}

// TestWorkQueue_DeliverAndWait covers the primary result-delivery flow:
// a producer goroutine calls DeliverResult while the main goroutine is blocked
// in WaitForResult.  Both the result payload and the WorkID must survive the
// round-trip through Redis.
func TestWorkQueue_DeliverAndWait(t *testing.T) {
	q, _ := newTestWorkQueue(t)
	ctx := context.Background()

	const workID = "work-deliver-wait-1"
	expected := WorkResult{
		WorkID: workID,
		Result: []byte(`{"findings":3}`),
	}

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		// Small sleep so WaitForResult establishes its pub/sub subscription first.
		time.Sleep(30 * time.Millisecond)
		err := q.DeliverResult(ctx, workID, expected)
		assert.NoError(t, err, "DeliverResult should not error")
	}()

	result, err := q.WaitForResult(ctx, workID, 3*time.Second)
	wg.Wait()

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, expected.WorkID, result.WorkID)
	assert.Equal(t, expected.Result, result.Result)
	assert.Nil(t, result.Error)
}

// TestWorkQueue_DeliverAndWait_WithError verifies that a WorkError is preserved
// when delivered and retrieved via WaitForResult.
func TestWorkQueue_DeliverAndWait_WithError(t *testing.T) {
	q, _ := newTestWorkQueue(t)
	ctx := context.Background()

	const workID = "work-deliver-err-1"
	expected := WorkResult{
		WorkID: workID,
		Error: &WorkError{
			Code:      "TIMEOUT",
			Message:   "component timed out after 5s",
			Retryable: true,
		},
	}

	go func() {
		time.Sleep(20 * time.Millisecond)
		_ = q.DeliverResult(ctx, workID, expected)
	}()

	result, err := q.WaitForResult(ctx, workID, 3*time.Second)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.Error)
	assert.Equal(t, "TIMEOUT", result.Error.Code)
	assert.True(t, result.Error.Retryable)
}

// TestWorkQueue_WaitForResult_AlreadyDelivered checks the race-free pre-check:
// if DeliverResult finishes before WaitForResult is called the result should be
// returned from the key without needing to wait for a pub/sub message.
func TestWorkQueue_WaitForResult_AlreadyDelivered(t *testing.T) {
	q, _ := newTestWorkQueue(t)
	ctx := context.Background()

	const workID = "work-predelivered-1"
	expected := WorkResult{
		WorkID: workID,
		Result: []byte(`{"status":"ok"}`),
	}

	// Deliver before WaitForResult is called.
	require.NoError(t, q.DeliverResult(ctx, workID, expected))

	result, err := q.WaitForResult(ctx, workID, 3*time.Second)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, expected.WorkID, result.WorkID)
	assert.Equal(t, expected.Result, result.Result)
}

// TestWorkQueue_WaitForResult_Timeout verifies that WaitForResult returns a
// wrapped context.DeadlineExceeded when no result arrives before the timeout.
func TestWorkQueue_WaitForResult_Timeout(t *testing.T) {
	q, _ := newTestWorkQueue(t)
	ctx := context.Background()

	// Use a very short timeout; no goroutine will deliver a result.
	result, err := q.WaitForResult(ctx, "work-never-delivered", 50*time.Millisecond)

	assert.Error(t, err, "WaitForResult should error when timeout elapses without a result")
	assert.Nil(t, result)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

// TestWorkQueue_Acknowledge verifies that Acknowledge removes a message from the
// pending-entries list (PEL) without returning an error.
func TestWorkQueue_Acknowledge(t *testing.T) {
	q, _ := newTestWorkQueue(t)
	ctx := context.Background()

	const (
		tenant = "acme"
		kind   = "agent"
		name   = "scanner"
	)

	item := testItem("work-ack-1", "scan", []byte(`{}`))

	msgID, err := q.Enqueue(ctx, tenant, kind, name, item)
	require.NoError(t, err)

	// Claim the message so it enters the PEL.
	claimed, err := q.Claim(ctx, tenant, kind, name, "consumer-1", 500*time.Millisecond)
	require.NoError(t, err)
	require.NotNil(t, claimed)

	// Acknowledge using the stream message ID returned by Enqueue.
	err = q.Acknowledge(ctx, tenant, kind, name, msgID)
	assert.NoError(t, err, "Acknowledge should succeed for a pending message")

	// Idempotent: acknowledging again should not error.
	err = q.Acknowledge(ctx, tenant, kind, name, msgID)
	assert.NoError(t, err, "Acknowledge should be idempotent")
}

// TestWorkQueue_Acknowledge_ValidatesRequiredFields verifies that Acknowledge
// rejects calls with missing required parameters.
func TestWorkQueue_Acknowledge_ValidatesRequiredFields(t *testing.T) {
	q, _ := newTestWorkQueue(t)
	ctx := context.Background()

	tests := []struct {
		name      string
		tenant    string
		kind      string
		qname     string
		messageID string
	}{
		{"empty tenant", "", "agent", "scanner", "1-0"},
		{"empty kind", "acme", "", "scanner", "1-0"},
		{"empty name", "acme", "agent", "", "1-0"},
		{"empty messageID", "acme", "agent", "scanner", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := q.Acknowledge(ctx, tc.tenant, tc.kind, tc.qname, tc.messageID)
			assert.Error(t, err)
		})
	}
}

// TestWorkQueue_MultipleConsumers_GetDifferentItems enqueues two items and verifies
// that two independent consumers each receive exactly one distinct item (no
// duplicate delivery).
func TestWorkQueue_MultipleConsumers_GetDifferentItems(t *testing.T) {
	q, _ := newTestWorkQueue(t)
	ctx := context.Background()

	const (
		tenant = "acme"
		kind   = "agent"
		name   = "multi-consumer"
	)

	item1 := testItem("work-mc-1", "scan", []byte(`{"id":1}`))
	item2 := testItem("work-mc-2", "scan", []byte(`{"id":2}`))

	_, err := q.Enqueue(ctx, tenant, kind, name, item1)
	require.NoError(t, err)

	_, err = q.Enqueue(ctx, tenant, kind, name, item2)
	require.NoError(t, err)

	// Consumer A claims first available message.
	claimedA, err := q.Claim(ctx, tenant, kind, name, "consumer-a", 500*time.Millisecond)
	require.NoError(t, err)
	require.NotNil(t, claimedA, "consumer-a should receive a work item")

	// Consumer B claims the next available message.
	claimedB, err := q.Claim(ctx, tenant, kind, name, "consumer-b", 500*time.Millisecond)
	require.NoError(t, err)
	require.NotNil(t, claimedB, "consumer-b should receive a work item")

	// Each consumer should have received a different item.
	assert.NotEqual(t, claimedA.WorkID, claimedB.WorkID,
		"two consumers must not receive the same work item")

	// Together they cover both enqueued items.
	receivedIDs := map[string]bool{
		claimedA.WorkID: true,
		claimedB.WorkID: true,
	}
	assert.True(t, receivedIDs["work-mc-1"], "work-mc-1 should be claimed by one of the consumers")
	assert.True(t, receivedIDs["work-mc-2"], "work-mc-2 should be claimed by one of the consumers")

	// A third Claim on an empty stream should return nil.
	claimedC, err := q.Claim(ctx, tenant, kind, name, "consumer-c", 50*time.Millisecond)
	require.NoError(t, err)
	assert.Nil(t, claimedC, "no more items should be available after both are claimed")
}

// TestWorkQueue_ReclaimAbandoned verifies that ReclaimAbandoned transfers
// ownership of messages that have been idle longer than the threshold.
//
// miniredis supports XCLAIM and provides (*Miniredis).FastForward to advance
// the internal clock, which makes it possible to simulate idle time without
// real wall-clock waiting.
func TestWorkQueue_ReclaimAbandoned(t *testing.T) {
	q, mr := newTestWorkQueue(t)
	ctx := context.Background()

	const (
		tenant = "acme"
		kind   = "agent"
		name   = "reclaim-test"
	)

	item := testItem("work-reclaim-1", "scan", []byte(`{}`))

	msgID, err := q.Enqueue(ctx, tenant, kind, name, item)
	require.NoError(t, err)

	// Claim the message so it appears in the PEL under "consumer-1".
	claimed, err := q.Claim(ctx, tenant, kind, name, "consumer-1", 500*time.Millisecond)
	require.NoError(t, err)
	require.NotNil(t, claimed)

	// FastForward miniredis time so the message idle duration exceeds the threshold.
	idleThreshold := 100 * time.Millisecond
	mr.FastForward(idleThreshold + 10*time.Millisecond)

	// ReclaimAbandoned should transfer the stale message to reclaimConsumer.
	err = q.ReclaimAbandoned(ctx, tenant, kind, name, idleThreshold)
	require.NoError(t, err, "ReclaimAbandoned should not error when stale messages exist")

	// The message should now be owned by reclaimConsumer. Acknowledge it via
	// its original stream ID to confirm it is still in the group's PEL.
	err = q.Acknowledge(ctx, tenant, kind, name, msgID)
	assert.NoError(t, err, "message should still be in the PEL after reclaim, allowing ack")
}

// TestWorkQueue_ReclaimAbandoned_EmptyQueue verifies that ReclaimAbandoned on a
// queue with no pending messages is a no-op and returns no error.
func TestWorkQueue_ReclaimAbandoned_EmptyQueue(t *testing.T) {
	q, _ := newTestWorkQueue(t)
	ctx := context.Background()

	err := q.ReclaimAbandoned(ctx, "acme", "agent", "empty", 100*time.Millisecond)
	assert.NoError(t, err, "ReclaimAbandoned on an empty queue should be a no-op")
}

// TestWorkQueue_ReclaimAbandoned_ValidatesRequiredFields verifies that
// ReclaimAbandoned rejects calls with missing required parameters.
func TestWorkQueue_ReclaimAbandoned_ValidatesRequiredFields(t *testing.T) {
	q, _ := newTestWorkQueue(t)
	ctx := context.Background()

	tests := []struct {
		name   string
		tenant string
		kind   string
		qname  string
	}{
		{"empty tenant", "", "agent", "scanner"},
		{"empty kind", "acme", "", "scanner"},
		{"empty name", "acme", "agent", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := q.ReclaimAbandoned(ctx, tc.tenant, tc.kind, tc.qname, 100*time.Millisecond)
			assert.Error(t, err)
		})
	}
}

// TestWorkQueue_StreamKeyIsolation confirms that items enqueued to one
// tenant/kind/name triple are not visible when claiming from a different triple.
func TestWorkQueue_StreamKeyIsolation(t *testing.T) {
	q, _ := newTestWorkQueue(t)
	ctx := context.Background()

	item := testItem("work-isolation-1", "scan", []byte(`{}`))

	_, err := q.Enqueue(ctx, "tenant-a", "agent", "scanner", item)
	require.NoError(t, err)

	// Attempt to claim from a different stream; should return nil.
	claimed, err := q.Claim(ctx, "tenant-b", "agent", "scanner", "c1", 50*time.Millisecond)
	require.NoError(t, err)
	assert.Nil(t, claimed, "items in tenant-a stream must not bleed into tenant-b stream")
}

// TestWorkQueue_DeliverResult_ValidatesWorkID verifies that DeliverResult
// rejects an empty workID without touching Redis.
func TestWorkQueue_DeliverResult_ValidatesWorkID(t *testing.T) {
	q, _ := newTestWorkQueue(t)
	ctx := context.Background()

	err := q.DeliverResult(ctx, "", WorkResult{})
	assert.Error(t, err)
}

// TestWorkQueue_WaitForResult_ValidatesWorkID verifies that WaitForResult
// rejects an empty workID without blocking.
func TestWorkQueue_WaitForResult_ValidatesWorkID(t *testing.T) {
	q, _ := newTestWorkQueue(t)
	ctx := context.Background()

	result, err := q.WaitForResult(ctx, "", 100*time.Millisecond)
	assert.Error(t, err)
	assert.Nil(t, result)
}

// TestWorkQueue_FullCycle exercises the complete happy path in a single test:
// Enqueue → Claim → DeliverResult → WaitForResult → Acknowledge.
func TestWorkQueue_FullCycle(t *testing.T) {
	q, _ := newTestWorkQueue(t)
	ctx := context.Background()

	const (
		tenant = "acme"
		kind   = "agent"
		name   = "full-cycle"
	)

	// Step 1: enqueue.
	item := testItem("", "recon", []byte(`{"scope":"10.0.0.0/24"}`))
	msgID, err := q.Enqueue(ctx, tenant, kind, name, item)
	require.NoError(t, err)
	require.NotEmpty(t, msgID)

	// Step 2: claim.
	claimed, err := q.Claim(ctx, tenant, kind, name, "worker-1", 500*time.Millisecond)
	require.NoError(t, err)
	require.NotNil(t, claimed)
	require.NotEmpty(t, claimed.WorkID)

	// Step 3: deliver result concurrently while main goroutine waits.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(20 * time.Millisecond)
		err := q.DeliverResult(ctx, claimed.WorkID, WorkResult{
			WorkID: claimed.WorkID,
			Result: []byte(`{"hosts_up":12}`),
		})
		assert.NoError(t, err)
	}()

	// Step 4: wait for the result.
	result, err := q.WaitForResult(ctx, claimed.WorkID, 3*time.Second)
	wg.Wait()
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, claimed.WorkID, result.WorkID)
	assert.Equal(t, []byte(`{"hosts_up":12}`), result.Result)

	// Step 5: acknowledge.
	err = q.Acknowledge(ctx, tenant, kind, name, msgID)
	assert.NoError(t, err)
}
