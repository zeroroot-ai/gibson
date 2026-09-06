// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/infra/observability"
)

// streamDeliveryBudget bounds how long a test waits for a single already-written,
// already-fsynced line to be delivered by the tailer.
//
// It is a liveness backstop, not a throughput assertion. The work behind one
// line is a single inotify wakeup plus a short read, so a functioning tailer
// completes it in microseconds. The budget is set six orders of magnitude above
// that deliberately: no amount of host load can consume it, so exhausting it
// means the tailer stopped delivering. See gibson#1247 — the previous version of
// this test asserted "at least 3 lines within 3 seconds", which conflated
// "the tailer works" with "this box was not busy" and failed on loaded hosts.
const streamDeliveryBudget = 30 * time.Second

// awaitStreamedLine blocks until sub delivers one entry.
//
// It fails the test on the two ways delivery can genuinely break — the channel
// closing early, or the tailer going silent — and says which, so a red run is
// never ambiguous about whether the code or the machine is at fault.
func awaitStreamedLine(t *testing.T, sub *Subscription, what string) LogEntry {
	t.Helper()

	start := time.Now()
	select {
	case entry, ok := <-sub.Output:
		if !ok {
			t.Fatalf("%s: subscription channel closed before the line arrived; "+
				"the tailer tore the subscription down while it was still following", what)
		}
		return entry

	case <-time.After(streamDeliveryBudget):
		t.Fatalf("%s: nothing delivered in %s. TAILER DEFECT, not host load: the write and "+
			"fsync had already returned before this wait began, so the line was on disk the "+
			"whole time and the tailer simply never emitted it. This budget is ~10^6x the work "+
			"involved and is not reachable by a slow or contended machine.",
			what, time.Since(start).Round(time.Millisecond))
		return LogEntry{} // unreachable; t.Fatalf does not return
	}
}

// drainHistorical reads every entry from a bounded (Follow: false)
// subscription until its output channel closes. Closing is the expected
// terminal event for such a subscription — handleSubscription sends the
// historical window and returns, which closes sub.Output via
// removeSubscriberAndClose — unlike awaitStreamedLine, which is for
// Follow: true subscriptions where a closed channel is itself the failure.
//
// The same liveness backstop applies: a functioning tailer sends its whole
// window and closes near-instantly, so exhausting the budget without either
// an entry or a close means the tailer stalled mid-send.
func drainHistorical(t *testing.T, sub *Subscription, what string) []LogEntry {
	t.Helper()

	var entries []LogEntry
	for {
		select {
		case entry, ok := <-sub.Output:
			if !ok {
				return entries
			}
			entries = append(entries, entry)

		case <-time.After(streamDeliveryBudget):
			t.Fatalf("%s: channel neither closed nor delivered an entry within %s; "+
				"the tailer appears to have stalled mid-send", what, streamDeliveryBudget)
			return nil // unreachable; t.Fatalf does not return
		}
	}
}

// TestLogTailer_StreamingLogs tests streaming logs from a running component.
// This is an integration test that writes to a real file and verifies the tailer picks up new lines.
//
// The test is lock-stepped: it writes one line, waits for that exact line to be
// streamed back, and only then writes the next. Every wait is on the tailer
// making progress, never on the clock, so a slow filesystem or a saturated CPU
// makes the test slower and never makes it fail (gibson#1247). Because the
// writer and the reader are the same goroutine there is no race to lose, which
// lets the assertion be far stricter than the count-based one it replaces: all
// five lines must arrive, in order, with exact content.
func TestLogTailer_StreamingLogs(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := observability.NewLogger(observability.Config{
		Component: "test",
		Level:     slog.LevelError,
	})

	// Create temp log file
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "component.log")
	f, err := os.Create(logFile)
	require.NoError(t, err)
	defer f.Close()

	// Write initial content. The watcher seeks to end-of-file when it attaches,
	// so these two lines are deliberately NOT expected on the follow stream —
	// they exist to prove the tailer starts from the tail rather than replaying
	// the file.
	_, err = f.WriteString("initial line 1\ninitial line 2\n")
	require.NoError(t, err)
	require.NoError(t, f.Sync())

	// Create tailer
	tailer := NewLogTailer(ctx, 1000, *logger)
	defer tailer.Close()

	// Start watching. StartWatching opens the file and registers the inotify
	// watch synchronously, so on return every subsequent write is observable.
	err = tailer.StartWatching("test-component", logFile)
	require.NoError(t, err)

	// Subscribe with follow mode. Subscribe registers the subscriber under the
	// tailer's write lock, and processLines fans out under the matching read
	// lock, so on return every line the watcher subsequently reads is fanned
	// out to us. That is the synchronisation point the old sleep was standing
	// in for; no sleep is needed here and none would be correct.
	sub, err := tailer.Subscribe(ctx, SubscribeOptions{
		ComponentIDs: []string{"test-component"},
		Follow:       true,
		TailLines:    0, // No history
	})
	require.NoError(t, err)
	require.NotNil(t, sub)

	const streamedLines = 5
	received := make([]string, 0, streamedLines)

	for i := 1; i <= streamedLines; i++ {
		want := fmt.Sprintf("streaming line %d", i)

		_, err = f.WriteString(want + "\n")
		require.NoError(t, err, "writing %q", want)
		require.NoError(t, f.Sync(), "syncing %q", want)

		// Only one line is unread on disk at this point, so exactly one entry
		// is owed to us. Wait for it before writing the next.
		entry := awaitStreamedLine(t, sub, fmt.Sprintf("waiting for %q", want))
		received = append(received, entry.Message)

		require.Equal(t, want, entry.Message,
			"streamed line %d has the wrong content: the tailer delivered lines out of order, "+
				"replayed history, or corrupted the line", i)
		require.Equal(t, "test-component", entry.Component,
			"streamed line %d attributed to the wrong component", i)
	}

	// Every line written after the subscription was established must have been
	// streamed — no drops, no truncation of the run.
	require.Len(t, received, streamedLines, "the tailer stopped streaming part-way through")

	for _, line := range received {
		require.True(t, strings.Contains(line, "streaming line"),
			"unexpected entry %q on the follow stream: pre-subscription history must not be replayed", line)
	}
}

// TestLogTailer_LogRotation tests that log rotation is handled correctly.
func TestLogTailer_LogRotation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	logger := observability.NewLogger(observability.Config{
		Component: "test",
		Level:     slog.LevelError,
	})

	// Create temp log file
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "rotating.log")

	// Create initial file
	f, err := os.Create(logFile)
	require.NoError(t, err)

	// Write initial content
	_, err = f.WriteString("pre-rotation line 1\npre-rotation line 2\n")
	require.NoError(t, err)
	require.NoError(t, f.Sync())
	f.Close()

	// Create tailer
	tailer := NewLogTailer(ctx, 1000, *logger)
	defer tailer.Close()

	// Start watching
	err = tailer.StartWatching("rotating-component", logFile)
	require.NoError(t, err)

	// Wait for initial processing
	time.Sleep(300 * time.Millisecond)

	// Subscribe with follow mode
	sub, err := tailer.Subscribe(ctx, SubscribeOptions{
		ComponentIDs: []string{"rotating-component"},
		Follow:       true,
		TailLines:    0,
	})
	require.NoError(t, err)

	// Simulate log rotation: rename old file, create new one
	go func() {
		time.Sleep(200 * time.Millisecond)

		// Rotate: rename current file
		rotatedFile := logFile + ".1"
		_ = os.Rename(logFile, rotatedFile)

		// Create new file with same name
		time.Sleep(100 * time.Millisecond)
		newF, err := os.Create(logFile)
		if err != nil {
			return
		}
		defer newF.Close()

		// Write to new file
		for i := 1; i <= 5; i++ {
			line := fmt.Sprintf("post-rotation line %d\n", i)
			_, _ = newF.WriteString(line)
			_ = newF.Sync()
			time.Sleep(50 * time.Millisecond)
		}
	}()

	// Collect entries
	receivedLines := make([]string, 0)
	timeout := time.After(5 * time.Second)

LOOP:
	for {
		select {
		case entry, ok := <-sub.Output:
			if !ok {
				break LOOP
			}
			receivedLines = append(receivedLines, entry.Message)
			if len(receivedLines) >= 5 {
				break LOOP
			}
		case <-timeout:
			break LOOP
		}
	}

	// We may or may not receive post-rotation lines depending on timing
	// The key is that the tailer doesn't crash and continues to function
	t.Logf("received %d lines during rotation test", len(receivedLines))
}

// TestLogTailer_MultipleSubscribers tests that multiple subscribers all
// receive the same stream of entries.
//
// Like TestLogTailer_StreamingLogs, this is lock-stepped: the test writes one
// line, waits for that exact line to arrive on every subscriber, and only
// then writes the next. That removes the wall-clock race the previous
// version had (a 2s budget racing a goroutine that slept 100ms + 5x30ms) and
// lets the assertion be exact instead of `>= 1` — which passed even for a
// tailer that delivered a single line to one subscriber and then stopped
// forever (gibson#1291).
func TestLogTailer_MultipleSubscribers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := observability.NewLogger(observability.Config{
		Component: "test",
		Level:     slog.LevelError,
	})

	// Create temp log file
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "multi-sub.log")
	f, err := os.Create(logFile)
	require.NoError(t, err)
	defer f.Close()

	// Write initial content. As in TestLogTailer_StreamingLogs, the watcher
	// seeks to end-of-file when it attaches, so this line is deliberately
	// NOT expected on any of the follow subscriptions below.
	_, err = f.WriteString("initial line\n")
	require.NoError(t, err)
	require.NoError(t, f.Sync())

	// Create tailer
	tailer := NewLogTailer(ctx, 1000, *logger)
	defer tailer.Close()

	// Start watching
	err = tailer.StartWatching("multi-sub-component", logFile)
	require.NoError(t, err)

	// Create multiple subscribers. Subscribe registers under the tailer's
	// write lock and processLines fans out under the matching read lock, so
	// on return every line the watcher subsequently reads is fanned out to
	// all three — no sleep needed to wait for this.
	sub1, err := tailer.Subscribe(ctx, SubscribeOptions{
		ComponentIDs: []string{"multi-sub-component"},
		Follow:       true,
	})
	require.NoError(t, err)

	sub2, err := tailer.Subscribe(ctx, SubscribeOptions{
		ComponentIDs: []string{"multi-sub-component"},
		Follow:       true,
	})
	require.NoError(t, err)

	sub3, err := tailer.Subscribe(ctx, SubscribeOptions{
		ComponentIDs: []string{"multi-sub-component"},
		Follow:       true,
	})
	require.NoError(t, err)

	subs := []*Subscription{sub1, sub2, sub3}
	const streamedLines = 5
	received := make([][]string, len(subs))
	for i := range received {
		received[i] = make([]string, 0, streamedLines)
	}

	for i := 1; i <= streamedLines; i++ {
		want := fmt.Sprintf("multi-sub line %d", i)

		_, err = f.WriteString(want + "\n")
		require.NoError(t, err, "writing %q", want)
		require.NoError(t, f.Sync(), "syncing %q", want)

		// Exactly one line is unread on disk at this point, so each of the
		// three subscribers is owed exactly one entry. Drain all three
		// (sequentially, from this one goroutine — awaitStreamedLine calls
		// t.Fatalf, which the testing package requires to run on the test's
		// own goroutine) before writing the next line.
		for subIdx, sub := range subs {
			entry := awaitStreamedLine(t, sub, fmt.Sprintf("subscriber %d waiting for %q", subIdx+1, want))
			require.Equal(t, want, entry.Message,
				"subscriber %d received the wrong content for line %d", subIdx+1, i)
			require.Equal(t, "multi-sub-component", entry.Component,
				"subscriber %d: line %d attributed to the wrong component", subIdx+1, i)
			received[subIdx] = append(received[subIdx], entry.Message)
		}
	}

	// Every subscriber must have received every line written after it
	// subscribed — no drops, and no subscriber silently falling behind the
	// others.
	for subIdx, entries := range received {
		require.Len(t, entries, streamedLines, "subscriber %d stopped receiving part-way through", subIdx+1)
	}
	require.Equal(t, received[0], received[1], "subscriber 1 and subscriber 2 diverged")
	require.Equal(t, received[0], received[2], "subscriber 1 and subscriber 3 diverged")
}

// TestLogTailer_HistoryRetrieval tests retrieving historical log entries.
//
// Delivery is synchronised through a throwaway follow subscription instead of
// a fixed sleep: processLines is single-threaded per component and always
// appends an entry to the ring buffer before fanning it out (see
// processLines in log_tailer.go), so observing line 100 arrive on that
// subscription proves lines 1-99 are already in the buffer too. That removes
// the 500ms sleep racing 100 unsynchronised writes (gibson#1291) and lets
// GetHistory's counts be asserted exactly instead of with `>=`.
func TestLogTailer_HistoryRetrieval(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := observability.NewLogger(observability.Config{
		Component: "test",
		Level:     slog.LevelError,
	})

	// Create empty temp log file, start watching, then write content
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "history.log")
	f, err := os.Create(logFile)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	// Create tailer and start watching before writing content
	tailer := NewLogTailer(ctx, 1000, *logger)
	defer tailer.Close()

	err = tailer.StartWatching("history-component", logFile)
	require.NoError(t, err)

	// A throwaway follow subscription used purely to observe when the tailer
	// has caught up with the writes below; unsubscribed before the real
	// assertions so it can't interfere with them.
	syncSub, err := tailer.Subscribe(ctx, SubscribeOptions{
		ComponentIDs: []string{"history-component"},
		Follow:       true,
	})
	require.NoError(t, err)

	const totalLines = 100
	for i := 1; i <= totalLines; i++ {
		want := fmt.Sprintf("history line %d", i)

		_, err = f.WriteString(want + "\n")
		require.NoError(t, err, "writing %q", want)
		require.NoError(t, f.Sync(), "syncing %q", want)

		entry := awaitStreamedLine(t, syncSub, fmt.Sprintf("waiting for %q", want))
		require.Equal(t, want, entry.Message, "line %d arrived with the wrong content", i)
	}
	tailer.Unsubscribe(syncSub)

	// All 100 lines are now guaranteed to be in the buffer.

	// Test GetHistory with specific count: the last 10, exactly.
	entries, err := tailer.GetHistory("history-component", 10)
	require.NoError(t, err)
	require.Len(t, entries, 10, "should have exactly the 10 most recent history entries")
	for i, entry := range entries {
		want := fmt.Sprintf("history line %d", totalLines-10+i+1)
		require.Equal(t, want, entry.Message, "entry %d of the last-10 window has the wrong content", i)
	}

	// Test GetHistory with 0 (get all): exactly all 100, in order.
	allEntries, err := tailer.GetHistory("history-component", 0)
	require.NoError(t, err)
	require.Len(t, allEntries, totalLines, "should have exactly all 100 history entries")
	for i, entry := range allEntries {
		want := fmt.Sprintf("history line %d", i+1)
		require.Equal(t, want, entry.Message, "entry %d of the full history has the wrong content", i)
	}

	// Test subscribe with TailLines: a bounded, non-follow subscription sends
	// its historical window and then closes — that closure is the expected
	// terminal event, not a failure (see drainHistorical).
	sub, err := tailer.Subscribe(ctx, SubscribeOptions{
		ComponentIDs: []string{"history-component"},
		Follow:       false,
		TailLines:    20,
	})
	require.NoError(t, err)

	receivedEntries := drainHistorical(t, sub, "history tail-lines subscription")

	require.Len(t, receivedEntries, 20, "should receive exactly the 20 tail lines")
	for i, entry := range receivedEntries {
		want := fmt.Sprintf("history line %d", totalLines-20+i+1)
		require.Equal(t, want, entry.Message, "tail-lines entry %d has the wrong content", i)
	}
}

// TestLogTailer_SinceTimestamp tests filtering logs by timestamp.
//
// The previous version wrote 10 lines, slept 500ms, then asserted `< 10`
// received — which passed even if the tailer delivered zero lines, exactly
// what a broken tailer produces (gibson#1291). It also wrote all 10 lines
// before calling StartWatching; since the watcher seeks to end-of-file on
// attach (see TestLogTailer_StreamingLogs), none of those lines were ever
// actually observed, so the test always passed on zero delivered lines
// regardless of the sleep.
//
// This version starts watching first, so every line is genuinely observed
// and timestamped by the tailer, and derives the cutoff from that timeline
// (via a lock-stepped follow subscription, same technique as
// TestLogTailer_StreamingLogs) instead of from a wall-clock sleep. entry.
// Timestamp is assigned inside the tailer strictly before the entry reaches
// the test, so a cutoff taken immediately after the "before" batch is
// received is guaranteed later than every "before" timestamp and — since the
// "after" lines are not written until later in program order — guaranteed
// earlier than every "after" timestamp. The since-filtered read is then
// asserted to return exactly the "after" batch: neither more (a leaky
// filter) nor fewer/zero (a filter, or a tailer, that drops everything).
func TestLogTailer_SinceTimestamp(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := observability.NewLogger(observability.Config{
		Component: "test",
		Level:     slog.LevelError,
	})

	// Create temp log file
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "since.log")
	f, err := os.Create(logFile)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	// Create tailer and start watching before writing content
	tailer := NewLogTailer(ctx, 1000, *logger)
	defer tailer.Close()

	err = tailer.StartWatching("since-component", logFile)
	require.NoError(t, err)

	syncSub, err := tailer.Subscribe(ctx, SubscribeOptions{
		ComponentIDs: []string{"since-component"},
		Follow:       true,
	})
	require.NoError(t, err)

	writeAndAwait := func(want string) {
		t.Helper()

		_, err := f.WriteString(want + "\n")
		require.NoError(t, err, "writing %q", want)
		require.NoError(t, f.Sync(), "syncing %q", want)

		entry := awaitStreamedLine(t, syncSub, fmt.Sprintf("waiting for %q", want))
		require.Equal(t, want, entry.Message, "arrived with the wrong content")
	}

	const beforeCount = 5
	for i := 1; i <= beforeCount; i++ {
		writeAndAwait(fmt.Sprintf("before line %d", i))
	}

	cutoff := time.Now()

	const afterCount = 5
	for i := 1; i <= afterCount; i++ {
		writeAndAwait(fmt.Sprintf("after line %d", i))
	}
	tailer.Unsubscribe(syncSub)

	// Subscribe with Since option: a bounded, non-follow subscription, so
	// its channel closing is the expected terminal event (drainHistorical).
	sub, err := tailer.Subscribe(ctx, SubscribeOptions{
		ComponentIDs: []string{"since-component"},
		Follow:       false,
		Since:        &cutoff,
	})
	require.NoError(t, err)

	receivedEntries := drainHistorical(t, sub, "since-timestamp subscription")

	require.Len(t, receivedEntries, afterCount,
		"should receive exactly the lines written after the cutoff: neither the earlier lines "+
			"(a leaky filter) nor zero lines (the tailer or the filter dropped everything)")
	for i, entry := range receivedEntries {
		want := fmt.Sprintf("after line %d", i+1)
		require.Equal(t, want, entry.Message, "since-filtered entry %d has the wrong content", i)
	}
}

// TestLogTailer_JSONLogParsing tests parsing of JSON formatted logs.
func TestLogTailer_JSONLogParsing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	logger := observability.NewLogger(observability.Config{
		Component: "test",
		Level:     slog.LevelError,
	})

	// Create empty temp log file, start watching, then write content
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "json.log")
	f, err := os.Create(logFile)
	require.NoError(t, err)

	// Create tailer and start watching before writing content
	tailer := NewLogTailer(ctx, 1000, *logger)
	defer tailer.Close()

	err = tailer.StartWatching("json-component", logFile)
	require.NoError(t, err)

	// Write JSON formatted logs after watching starts
	jsonLines := []string{
		`{"timestamp":"2024-01-01T12:00:00Z","level":"info","message":"info message","request_id":"abc123"}`,
		`{"timestamp":"2024-01-01T12:00:01Z","level":"warn","message":"warning message","user":"admin"}`,
		`{"timestamp":"2024-01-01T12:00:02Z","level":"error","msg":"error occurred","error":"connection timeout"}`,
		`plain text log line`,
	}

	for _, line := range jsonLines {
		_, err = f.WriteString(line + "\n")
		require.NoError(t, err)
	}
	require.NoError(t, f.Sync())
	f.Close()

	// Wait for processing
	time.Sleep(500 * time.Millisecond)

	// Get history
	entries, err := tailer.GetHistory("json-component", 0)
	require.NoError(t, err)

	// Verify parsing
	assert.GreaterOrEqual(t, len(entries), 4, "should have at least 4 entries")

	// Find specific entries and verify parsing
	for _, entry := range entries {
		switch {
		case entry.Message == "info message":
			assert.Equal(t, "info", entry.Level)
			assert.Equal(t, "abc123", entry.Fields["request_id"])
		case entry.Message == "warning message":
			assert.Equal(t, "warn", entry.Level)
			assert.Equal(t, "admin", entry.Fields["user"])
		case entry.Message == "error occurred":
			assert.Equal(t, "error", entry.Level)
		case entry.Message == "plain text log line":
			assert.Empty(t, entry.Level)
		}
	}
}

// TestLogTailer_ComponentIsolation tests that components are isolated from each other.
func TestLogTailer_ComponentIsolation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	logger := observability.NewLogger(observability.Config{
		Component: "test",
		Level:     slog.LevelError,
	})

	// Create temp log files for two components
	tmpDir := t.TempDir()
	logFile1 := filepath.Join(tmpDir, "comp1.log")
	logFile2 := filepath.Join(tmpDir, "comp2.log")

	f1, err := os.Create(logFile1)
	require.NoError(t, err)
	defer f1.Close()

	f2, err := os.Create(logFile2)
	require.NoError(t, err)
	defer f2.Close()

	// Write distinct content
	_, err = f1.WriteString("component1-only-line\n")
	require.NoError(t, err)
	require.NoError(t, f1.Sync())

	_, err = f2.WriteString("component2-only-line\n")
	require.NoError(t, err)
	require.NoError(t, f2.Sync())

	// Create tailer
	tailer := NewLogTailer(ctx, 1000, *logger)
	defer tailer.Close()

	// Start watching both
	err = tailer.StartWatching("component-1", logFile1)
	require.NoError(t, err)
	err = tailer.StartWatching("component-2", logFile2)
	require.NoError(t, err)

	// Wait for processing
	time.Sleep(300 * time.Millisecond)

	// Subscribe to only component-1
	sub, err := tailer.Subscribe(ctx, SubscribeOptions{
		ComponentIDs: []string{"component-1"},
		Follow:       false,
		TailLines:    10,
	})
	require.NoError(t, err)

	// Collect entries
	receivedLines := make([]string, 0)
	timeout := time.After(2 * time.Second)

LOOP:
	for {
		select {
		case entry, ok := <-sub.Output:
			if !ok {
				break LOOP
			}
			receivedLines = append(receivedLines, entry.Message)
			assert.Equal(t, "component-1", entry.Component, "should only receive from component-1")
		case <-timeout:
			break LOOP
		}
	}

	// Verify we only got component-1 lines
	for _, line := range receivedLines {
		assert.NotContains(t, line, "component2", "should not receive component-2 lines")
	}
}

// TestLogTailer_SubscribeErrorHandling tests error cases for subscription.
func TestLogTailer_SubscribeErrorHandling(t *testing.T) {
	ctx := context.Background()
	logger := observability.NewLogger(observability.Config{
		Component: "test",
		Level:     slog.LevelError,
	})

	tailer := NewLogTailer(ctx, 1000, *logger)
	defer tailer.Close()

	// Test subscribing to non-existent component
	_, err := tailer.Subscribe(ctx, SubscribeOptions{
		ComponentIDs: []string{"non-existent"},
		Follow:       true,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not being watched")

	// Test subscribing with no component IDs
	_, err = tailer.Subscribe(ctx, SubscribeOptions{
		ComponentIDs: []string{},
		Follow:       true,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one component ID")
}

// TestLogTailer_CleanupOnDisconnect tests that resources are cleaned up when subscription is cancelled.
func TestLogTailer_CleanupOnDisconnect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	logger := observability.NewLogger(observability.Config{
		Component: "test",
		Level:     slog.LevelError,
	})

	// Create temp log file
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "cleanup.log")
	f, err := os.Create(logFile)
	require.NoError(t, err)
	defer f.Close()

	_, err = f.WriteString("initial line\n")
	require.NoError(t, err)
	require.NoError(t, f.Sync())

	// Create tailer
	tailer := NewLogTailer(ctx, 1000, *logger)
	defer tailer.Close()

	// Start watching
	err = tailer.StartWatching("cleanup-component", logFile)
	require.NoError(t, err)

	// Wait for processing
	time.Sleep(200 * time.Millisecond)

	// Create subscription with cancellable context
	subCtx, subCancel := context.WithCancel(ctx)
	sub, err := tailer.Subscribe(subCtx, SubscribeOptions{
		ComponentIDs: []string{"cleanup-component"},
		Follow:       true,
	})
	require.NoError(t, err)

	// Cancel the subscription context
	subCancel()

	// Wait a moment for cleanup
	time.Sleep(200 * time.Millisecond)

	// The output channel should eventually close
	timeout := time.After(2 * time.Second)
	select {
	case _, ok := <-sub.Output:
		if !ok {
			// Channel closed as expected
			t.Log("subscription channel closed correctly after cancel")
		}
	case <-timeout:
		// Timeout is acceptable - the channel might still be open but the subscription was cancelled
		t.Log("timeout waiting for channel close - subscription was cancelled")
	}
}

// TestLogTailer_HighVolumeLogs tests handling of high volume log writes.
func TestLogTailer_HighVolumeLogs(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := observability.NewLogger(observability.Config{
		Component: "test",
		Level:     slog.LevelError,
	})

	// Create temp log file
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "high-volume.log")
	f, err := os.Create(logFile)
	require.NoError(t, err)
	defer f.Close()

	// Create tailer with small buffer to test overflow
	tailer := NewLogTailer(ctx, 100, *logger)
	defer tailer.Close()

	// Start watching
	err = tailer.StartWatching("high-volume-component", logFile)
	require.NoError(t, err)

	// Subscribe with follow mode
	sub, err := tailer.Subscribe(ctx, SubscribeOptions{
		ComponentIDs: []string{"high-volume-component"},
		Follow:       true,
	})
	require.NoError(t, err)

	// Write many lines rapidly
	lineCount := 500
	go func() {
		for i := 1; i <= lineCount; i++ {
			line := fmt.Sprintf("high-volume line %d\n", i)
			_, _ = f.WriteString(line)
			if i%50 == 0 {
				_ = f.Sync()
			}
		}
		_ = f.Sync()
	}()

	// Collect entries
	receivedCount := 0
	timeout := time.After(10 * time.Second)

LOOP:
	for {
		select {
		case _, ok := <-sub.Output:
			if !ok {
				break LOOP
			}
			receivedCount++
			if receivedCount >= lineCount/2 {
				break LOOP
			}
		case <-timeout:
			break LOOP
		}
	}

	t.Logf("received %d lines out of %d written", receivedCount, lineCount)

	// We should have received some entries (may not be all due to slow subscriber)
	assert.Greater(t, receivedCount, 0, "should have received some entries")

	// Verify buffer didn't crash and still functions
	entries, err := tailer.GetHistory("high-volume-component", 10)
	require.NoError(t, err)
	assert.LessOrEqual(t, len(entries), 100, "buffer should respect size limit")
}
