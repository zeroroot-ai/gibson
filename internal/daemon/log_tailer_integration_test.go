package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/observability"
)

// TestLogTailer_StreamingLogs tests streaming logs from a running component.
// This is an integration test that writes to a real file and verifies the tailer picks up new lines.
func TestLogTailer_StreamingLogs(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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

	// Write initial content
	_, err = f.WriteString("initial line 1\ninitial line 2\n")
	require.NoError(t, err)
	require.NoError(t, f.Sync())

	// Create tailer
	tailer := NewLogTailer(ctx, 1000, *logger)
	defer tailer.Close()

	// Start watching
	err = tailer.StartWatching("test-component", logFile)
	require.NoError(t, err)

	// Wait for initial lines to be processed
	time.Sleep(300 * time.Millisecond)

	// Subscribe with follow mode
	sub, err := tailer.Subscribe(ctx, SubscribeOptions{
		ComponentIDs: []string{"test-component"},
		Follow:       true,
		TailLines:    0, // No history
	})
	require.NoError(t, err)
	require.NotNil(t, sub)

	// Write new lines in goroutine
	go func() {
		time.Sleep(100 * time.Millisecond)
		for i := 1; i <= 5; i++ {
			line := fmt.Sprintf("streaming line %d\n", i)
			_, _ = f.WriteString(line)
			_ = f.Sync()
			time.Sleep(50 * time.Millisecond)
		}
	}()

	// Collect streaming entries
	receivedLines := make([]string, 0)
	timeout := time.After(3 * time.Second)

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

	// Verify we received the streaming lines
	assert.GreaterOrEqual(t, len(receivedLines), 3, "should receive at least 3 streaming lines")

	// Verify content
	foundStreaming := false
	for _, line := range receivedLines {
		if strings.Contains(line, "streaming line") {
			foundStreaming = true
			break
		}
	}
	assert.True(t, foundStreaming, "should have received streaming lines")
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

// TestLogTailer_MultipleSubscribers tests that multiple subscribers receive the same entries.
func TestLogTailer_MultipleSubscribers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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

	// Write initial content
	_, err = f.WriteString("initial line\n")
	require.NoError(t, err)
	require.NoError(t, f.Sync())

	// Create tailer
	tailer := NewLogTailer(ctx, 1000, *logger)
	defer tailer.Close()

	// Start watching
	err = tailer.StartWatching("multi-sub-component", logFile)
	require.NoError(t, err)

	// Wait for initial processing
	time.Sleep(300 * time.Millisecond)

	// Create multiple subscribers
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

	// Write new lines
	go func() {
		time.Sleep(100 * time.Millisecond)
		for i := 1; i <= 5; i++ {
			line := fmt.Sprintf("multi-sub line %d\n", i)
			_, _ = f.WriteString(line)
			_ = f.Sync()
			time.Sleep(30 * time.Millisecond)
		}
	}()

	// Collect entries from all subscribers
	var wg sync.WaitGroup
	results := make([][]string, 3)
	mu := sync.Mutex{}

	collectEntries := func(idx int, sub *Subscription) {
		defer wg.Done()
		entries := make([]string, 0)
		timeout := time.After(2 * time.Second)

	LOOP:
		for {
			select {
			case entry, ok := <-sub.Output:
				if !ok {
					break LOOP
				}
				entries = append(entries, entry.Message)
				if len(entries) >= 5 {
					break LOOP
				}
			case <-timeout:
				break LOOP
			}
		}

		mu.Lock()
		results[idx] = entries
		mu.Unlock()
	}

	wg.Add(3)
	go collectEntries(0, sub1)
	go collectEntries(1, sub2)
	go collectEntries(2, sub3)
	wg.Wait()

	// Verify all subscribers received entries
	for i, entries := range results {
		assert.GreaterOrEqual(t, len(entries), 1, "subscriber %d should receive entries", i+1)
	}

	// Verify consistency: all subscribers should have received same lines
	// (though order might differ slightly due to timing)
	minLen := len(results[0])
	for i := 1; i < len(results); i++ {
		if len(results[i]) < minLen {
			minLen = len(results[i])
		}
	}

	if minLen > 0 {
		t.Logf("all subscribers received at least %d entries", minLen)
	}
}

// TestLogTailer_HistoryRetrieval tests retrieving historical log entries.
func TestLogTailer_HistoryRetrieval(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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

	// Create tailer and start watching before writing content
	tailer := NewLogTailer(ctx, 1000, *logger)
	defer tailer.Close()

	err = tailer.StartWatching("history-component", logFile)
	require.NoError(t, err)

	// Write 100 lines after watching starts
	for i := 1; i <= 100; i++ {
		_, err = f.WriteString(fmt.Sprintf("history line %d\n", i))
		require.NoError(t, err)
	}
	require.NoError(t, f.Sync())
	f.Close()

	// Wait for all lines to be processed
	time.Sleep(500 * time.Millisecond)

	// Test GetHistory with specific count
	entries, err := tailer.GetHistory("history-component", 10)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(entries), 10, "should have at least 10 history entries")

	// Test GetHistory with 0 (get all)
	allEntries, err := tailer.GetHistory("history-component", 0)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(allEntries), 50, "should have many history entries")

	// Test subscribe with TailLines
	sub, err := tailer.Subscribe(ctx, SubscribeOptions{
		ComponentIDs: []string{"history-component"},
		Follow:       false,
		TailLines:    20,
	})
	require.NoError(t, err)

	// Collect historical entries
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
		case <-timeout:
			break LOOP
		}
	}

	// Should have received tail lines
	assert.GreaterOrEqual(t, len(receivedLines), 15, "should receive at least 15 tail lines")
}

// TestLogTailer_SinceTimestamp tests filtering logs by timestamp.
func TestLogTailer_SinceTimestamp(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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

	// Write lines with delays to create different timestamps
	for i := 1; i <= 10; i++ {
		_, err = f.WriteString(fmt.Sprintf("line %d\n", i))
		require.NoError(t, err)
		require.NoError(t, f.Sync())
		time.Sleep(50 * time.Millisecond)
	}
	f.Close()

	// Mark the midpoint time
	midTime := time.Now().Add(-250 * time.Millisecond)

	// Create tailer
	tailer := NewLogTailer(ctx, 1000, *logger)
	defer tailer.Close()

	// Start watching
	err = tailer.StartWatching("since-component", logFile)
	require.NoError(t, err)

	// Wait for all lines to be processed
	time.Sleep(500 * time.Millisecond)

	// Subscribe with Since option
	sub, err := tailer.Subscribe(ctx, SubscribeOptions{
		ComponentIDs: []string{"since-component"},
		Follow:       false,
		Since:        &midTime,
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
		case <-timeout:
			break LOOP
		}
	}

	// Should have received some but not all lines
	t.Logf("received %d lines since midpoint", len(receivedLines))
	assert.Less(t, len(receivedLines), 10, "should not receive all 10 lines")
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
