package daemon

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/observability"
)

func TestNewLogTailer(t *testing.T) {
	ctx := context.Background()
	logger := observability.NewLogger(observability.Config{
		Component: "test",
		Level:     slog.LevelError,
	})

	tailer := NewLogTailer(ctx, 1000, *logger)
	require.NotNil(t, tailer)
	assert.Equal(t, 1000, tailer.bufferSize)

	defer tailer.Close()
}

func TestLogTailer_StartWatching(t *testing.T) {
	ctx := context.Background()
	logger := observability.NewLogger(observability.Config{
		Component: "test",
		Level:     slog.LevelError,
	})

	// Create temp log file
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")
	err := os.WriteFile(logFile, []byte("test log\n"), 0644)
	require.NoError(t, err)

	tailer := NewLogTailer(ctx, 1000, *logger)
	defer tailer.Close()

	err = tailer.StartWatching("test-component", logFile)
	require.NoError(t, err)

	// Verify component is being watched
	assert.True(t, tailer.IsWatching("test-component"))

	// Stop watching
	err = tailer.StopWatching("test-component")
	require.NoError(t, err)

	assert.False(t, tailer.IsWatching("test-component"))
}

func TestLogTailer_Subscribe(t *testing.T) {
	ctx := context.Background()
	logger := observability.NewLogger(observability.Config{
		Component: "test",
		Level:     slog.LevelError,
	})

	// Create empty temp log file, then start watching before writing content
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")
	f, err := os.Create(logFile)
	require.NoError(t, err)

	tailer := NewLogTailer(ctx, 1000, *logger)
	defer tailer.Close()

	err = tailer.StartWatching("test-component", logFile)
	require.NoError(t, err)

	// Write content after watching starts (watcher seeks to EOF on open)
	_, err = f.WriteString("line 1\nline 2\nline 3\n")
	require.NoError(t, err)
	require.NoError(t, f.Sync())
	f.Close()

	// Wait for watcher to process lines
	time.Sleep(500 * time.Millisecond)

	// Subscribe with tail lines
	sub, err := tailer.Subscribe(ctx, SubscribeOptions{
		ComponentIDs: []string{"test-component"},
		Follow:       false,
		TailLines:    2,
	})
	require.NoError(t, err)
	require.NotNil(t, sub)

	// Read historical entries
	entries := make([]LogEntry, 0)
	timeout := time.After(2 * time.Second)

	for len(entries) < 2 {
		select {
		case entry, ok := <-sub.Output:
			if !ok {
				// Channel closed, we're done
				goto DONE
			}
			entries = append(entries, entry)
		case <-timeout:
			t.Fatalf("timeout waiting for entries, got %d", len(entries))
		}
	}

DONE:
	assert.True(t, len(entries) >= 2, "should receive at least 2 historical entries")
}

func TestLogTailer_GetHistory(t *testing.T) {
	ctx := context.Background()
	logger := observability.NewLogger(observability.Config{
		Component: "test",
		Level:     slog.LevelError,
	})

	// Create empty temp log file, start watching, then write content
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")
	f, err := os.Create(logFile)
	require.NoError(t, err)

	tailer := NewLogTailer(ctx, 1000, *logger)
	defer tailer.Close()

	err = tailer.StartWatching("test-component", logFile)
	require.NoError(t, err)

	// Write content after watching starts
	_, err = f.WriteString("line 1\nline 2\nline 3\nline 4\nline 5\n")
	require.NoError(t, err)
	require.NoError(t, f.Sync())
	f.Close()

	// Wait for lines to be processed
	time.Sleep(500 * time.Millisecond)

	// Get history
	entries, err := tailer.GetHistory("test-component", 3)
	require.NoError(t, err)

	assert.True(t, len(entries) >= 3, "should have at least 3 entries")
}

func TestLogTailer_ParseLine(t *testing.T) {
	ctx := context.Background()
	logger := observability.NewLogger(observability.Config{
		Component: "test",
		Level:     slog.LevelError,
	})

	tailer := NewLogTailer(ctx, 1000, *logger)
	defer tailer.Close()

	tests := []struct {
		name      string
		line      string
		expectMsg string
		expectLvl string
	}{
		{
			name:      "plain text",
			line:      "simple log message",
			expectMsg: "simple log message",
			expectLvl: "",
		},
		{
			name:      "json log",
			line:      `{"timestamp":"2024-01-01T12:00:00Z","level":"info","message":"test message"}`,
			expectMsg: "test message",
			expectLvl: "info",
		},
		{
			name:      "json with msg field",
			line:      `{"time":"2024-01-01T12:00:00Z","level":"error","msg":"error occurred"}`,
			expectMsg: "error occurred",
			expectLvl: "error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := tailer.parseLine(tt.line, "test-component")

			assert.Equal(t, tt.expectMsg, entry.Message)
			assert.Equal(t, tt.expectLvl, entry.Level)
			assert.Equal(t, "test-component", entry.Component)
		})
	}
}

func TestLogTailer_MultiComponent(t *testing.T) {
	ctx := context.Background()
	logger := observability.NewLogger(observability.Config{
		Component: "test",
		Level:     slog.LevelError,
	})

	// Create empty temp log files
	tmpDir := t.TempDir()
	logFile1 := filepath.Join(tmpDir, "comp1.log")
	logFile2 := filepath.Join(tmpDir, "comp2.log")
	f1, err := os.Create(logFile1)
	require.NoError(t, err)
	f2, err := os.Create(logFile2)
	require.NoError(t, err)

	tailer := NewLogTailer(ctx, 1000, *logger)
	defer tailer.Close()

	err = tailer.StartWatching("component-1", logFile1)
	require.NoError(t, err)
	err = tailer.StartWatching("component-2", logFile2)
	require.NoError(t, err)

	// Write content after watching starts
	_, _ = f1.WriteString("comp1 line 1\ncomp1 line 2\n")
	_ = f1.Sync()
	f1.Close()
	_, _ = f2.WriteString("comp2 line 1\ncomp2 line 2\n")
	_ = f2.Sync()
	f2.Close()

	// Wait for processing
	time.Sleep(500 * time.Millisecond)

	// Subscribe to both components
	sub, err := tailer.Subscribe(ctx, SubscribeOptions{
		ComponentIDs: []string{"component-1", "component-2"},
		Follow:       false,
		TailLines:    10,
	})
	require.NoError(t, err)

	// Collect entries
	entries := make([]LogEntry, 0)
	timeout := time.After(2 * time.Second)

LOOP:
	for {
		select {
		case entry, ok := <-sub.Output:
			if !ok {
				break LOOP
			}
			entries = append(entries, entry)
		case <-timeout:
			break LOOP
		}
	}

	// Should have entries from both components
	assert.True(t, len(entries) >= 2, "should have entries from both components")

	// Verify we have entries from both components
	comp1Found := false
	comp2Found := false
	for _, entry := range entries {
		if entry.Component == "component-1" {
			comp1Found = true
		}
		if entry.Component == "component-2" {
			comp2Found = true
		}
	}

	assert.True(t, comp1Found, "should have entries from component-1")
	assert.True(t, comp2Found, "should have entries from component-2")
}

func TestLogTailer_GetWatchedComponents(t *testing.T) {
	ctx := context.Background()
	logger := observability.NewLogger(observability.Config{
		Component: "test",
		Level:     slog.LevelError,
	})

	tmpDir := t.TempDir()
	logFile1 := filepath.Join(tmpDir, "comp1.log")
	logFile2 := filepath.Join(tmpDir, "comp2.log")

	err := os.WriteFile(logFile1, []byte("test\n"), 0644)
	require.NoError(t, err)
	err = os.WriteFile(logFile2, []byte("test\n"), 0644)
	require.NoError(t, err)

	tailer := NewLogTailer(ctx, 1000, *logger)
	defer tailer.Close()

	err = tailer.StartWatching("component-1", logFile1)
	require.NoError(t, err)
	err = tailer.StartWatching("component-2", logFile2)
	require.NoError(t, err)

	components := tailer.GetWatchedComponents()
	assert.Len(t, components, 2)
	assert.Contains(t, components, "component-1")
	assert.Contains(t, components, "component-2")
}
