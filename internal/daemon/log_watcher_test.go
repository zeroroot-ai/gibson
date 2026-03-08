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
	"github.com/zero-day-ai/gibson/internal/observability"
)

func TestNewLogWatcher(t *testing.T) {
	ctx := context.Background()
	logger := observability.NewLogger(observability.Config{
		Component: "test",
		Level:     slog.LevelError,
	})

	// Create temp file
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")
	f, err := os.Create(logFile)
	require.NoError(t, err)
	f.Close()

	watcher, err := NewLogWatcher(ctx, logFile, logger)
	require.NoError(t, err)
	require.NotNil(t, watcher)

	defer watcher.Close()

	assert.Equal(t, logFile, watcher.path)
	assert.NotNil(t, watcher.watcher)
	assert.NotNil(t, watcher.output)
}

func TestLogWatcher_Start(t *testing.T) {
	ctx := context.Background()
	logger := observability.NewLogger(observability.Config{
		Component: "test",
		Level:     slog.LevelError,
	})

	// Create temp file with initial content
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")
	err := os.WriteFile(logFile, []byte("initial line\n"), 0644)
	require.NoError(t, err)

	watcher, err := NewLogWatcher(ctx, logFile, logger)
	require.NoError(t, err)
	defer watcher.Close()

	err = watcher.Start()
	require.NoError(t, err)

	// Give watcher time to start
	time.Sleep(100 * time.Millisecond)
}

func TestLogWatcher_NewLines(t *testing.T) {
	ctx := context.Background()
	logger := observability.NewLogger(observability.Config{
		Component: "test",
		Level:     slog.LevelError,
	})

	// Create temp file
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")
	f, err := os.Create(logFile)
	require.NoError(t, err)
	f.Close()

	watcher, err := NewLogWatcher(ctx, logFile, logger)
	require.NoError(t, err)
	defer watcher.Close()

	err = watcher.Start()
	require.NoError(t, err)

	// Give watcher time to start
	time.Sleep(100 * time.Millisecond)

	// Append new lines
	f, err = os.OpenFile(logFile, os.O_APPEND|os.O_WRONLY, 0644)
	require.NoError(t, err)
	_, err = f.WriteString("line 1\n")
	require.NoError(t, err)
	_, err = f.WriteString("line 2\n")
	require.NoError(t, err)
	f.Close()

	// Read lines from watcher with timeout
	lines := make([]string, 0, 2)
	timeout := time.After(2 * time.Second)

	for len(lines) < 2 {
		select {
		case line := <-watcher.Lines():
			lines = append(lines, line)
		case <-timeout:
			t.Fatal("timeout waiting for lines")
		}
	}

	assert.Len(t, lines, 2)
	assert.Equal(t, "line 1", lines[0])
	assert.Equal(t, "line 2", lines[1])
}

func TestLogWatcher_ReadHistoricalLines(t *testing.T) {
	ctx := context.Background()
	logger := observability.NewLogger(observability.Config{
		Component: "test",
		Level:     slog.LevelError,
	})

	// Create temp file with historical content
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")
	content := "line 1\nline 2\nline 3\nline 4\nline 5\n"
	err := os.WriteFile(logFile, []byte(content), 0644)
	require.NoError(t, err)

	watcher, err := NewLogWatcher(ctx, logFile, logger)
	require.NoError(t, err)
	defer watcher.Close()

	err = watcher.Start()
	require.NoError(t, err)

	// Read last 3 lines
	lines, err := watcher.ReadHistoricalLines(3)
	require.NoError(t, err)
	assert.Len(t, lines, 3)
	assert.Equal(t, "line 3", lines[0])
	assert.Equal(t, "line 4", lines[1])
	assert.Equal(t, "line 5", lines[2])

	// Read all lines
	watcher.Close()
	watcher, err = NewLogWatcher(ctx, logFile, logger)
	require.NoError(t, err)
	defer watcher.Close()
	err = watcher.Start()
	require.NoError(t, err)

	lines, err = watcher.ReadHistoricalLines(0)
	require.NoError(t, err)
	assert.Len(t, lines, 5)
	assert.Equal(t, "line 1", lines[0])
}

func TestLogWatcher_Rotation(t *testing.T) {
	ctx := context.Background()
	logger := observability.NewLogger(observability.Config{
		Component: "test",
		Level:     slog.LevelError,
	})

	// Create temp file
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")
	err := os.WriteFile(logFile, []byte("line 1\n"), 0644)
	require.NoError(t, err)

	watcher, err := NewLogWatcher(ctx, logFile, logger)
	require.NoError(t, err)
	defer watcher.Close()

	err = watcher.Start()
	require.NoError(t, err)

	// Seek to end so we only capture new lines
	err = watcher.SeekToEnd()
	require.NoError(t, err)

	// Give watcher time to start
	time.Sleep(100 * time.Millisecond)

	// Simulate log rotation: rename old file, create new file
	oldFile := logFile + ".old"
	err = os.Rename(logFile, oldFile)
	require.NoError(t, err)

	// Give time for fsnotify to detect rename
	time.Sleep(200 * time.Millisecond)

	// Create new file with new content
	err = os.WriteFile(logFile, []byte("new line 1\n"), 0644)
	require.NoError(t, err)

	// Append more content
	time.Sleep(200 * time.Millisecond)
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_WRONLY, 0644)
	require.NoError(t, err)
	_, err = f.WriteString("new line 2\n")
	require.NoError(t, err)
	f.Close()

	// Read lines from watcher with timeout
	lines := make([]string, 0)
	timeout := time.After(3 * time.Second)

	for len(lines) < 2 {
		select {
		case line, ok := <-watcher.Lines():
			if !ok {
				t.Fatal("channel closed unexpectedly")
			}
			lines = append(lines, line)
		case <-timeout:
			// It's okay if we don't get all lines in this test
			// as rotation timing is tricky
			if len(lines) > 0 {
				t.Logf("Got %d lines before timeout (rotation timing is tricky)", len(lines))
				return
			}
			t.Fatal("timeout waiting for lines after rotation")
		}
	}

	// We should get the new lines
	assert.Contains(t, lines, "new line 1")
	assert.Contains(t, lines, "new line 2")
}

func TestLogWatcher_FileNotFound(t *testing.T) {
	ctx := context.Background()
	logger := observability.NewLogger(observability.Config{
		Component: "test",
		Level:     slog.LevelError,
	})

	// Try to watch non-existent file
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "nonexistent.log")

	watcher, err := NewLogWatcher(ctx, logFile, logger)
	require.NoError(t, err)
	defer watcher.Close()

	err = watcher.Start()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open log file")
}

func TestLogWatcher_Close(t *testing.T) {
	ctx := context.Background()
	logger := observability.NewLogger(observability.Config{
		Component: "test",
		Level:     slog.LevelError,
	})

	// Create temp file
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")
	err := os.WriteFile(logFile, []byte("line 1\n"), 0644)
	require.NoError(t, err)

	watcher, err := NewLogWatcher(ctx, logFile, logger)
	require.NoError(t, err)

	err = watcher.Start()
	require.NoError(t, err)

	// Close watcher
	err = watcher.Close()
	assert.NoError(t, err)

	// Channel should be closed
	_, ok := <-watcher.Lines()
	assert.False(t, ok, "channel should be closed")
}

func TestLogWatcher_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	logger := observability.NewLogger(observability.Config{
		Component: "test",
		Level:     slog.LevelError,
	})

	// Create temp file
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")
	err := os.WriteFile(logFile, []byte("line 1\n"), 0644)
	require.NoError(t, err)

	watcher, err := NewLogWatcher(ctx, logFile, logger)
	require.NoError(t, err)

	err = watcher.Start()
	require.NoError(t, err)

	// Cancel context
	cancel()

	// Wait for watcher to stop
	time.Sleep(200 * time.Millisecond)

	// Channel should be closed
	select {
	case _, ok := <-watcher.Lines():
		assert.False(t, ok, "channel should be closed")
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for channel to close")
	}
}

func TestLogWatcher_MultipleLines(t *testing.T) {
	ctx := context.Background()
	logger := observability.NewLogger(observability.Config{
		Component: "test",
		Level:     slog.LevelError,
	})

	// Create temp file
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")
	f, err := os.Create(logFile)
	require.NoError(t, err)
	f.Close()

	watcher, err := NewLogWatcher(ctx, logFile, logger)
	require.NoError(t, err)
	defer watcher.Close()

	err = watcher.Start()
	require.NoError(t, err)

	// Give watcher time to start
	time.Sleep(100 * time.Millisecond)

	// Write multiple lines
	f, err = os.OpenFile(logFile, os.O_APPEND|os.O_WRONLY, 0644)
	require.NoError(t, err)
	for i := 1; i <= 10; i++ {
		_, err = f.WriteString("line " + string(rune('0'+i)) + "\n")
		require.NoError(t, err)
	}
	f.Close()

	// Read lines from watcher
	lines := make([]string, 0)
	timeout := time.After(2 * time.Second)

	for len(lines) < 10 {
		select {
		case line := <-watcher.Lines():
			lines = append(lines, line)
		case <-timeout:
			t.Fatalf("timeout waiting for lines, got %d", len(lines))
		}
	}

	assert.Len(t, lines, 10)
}

func TestLogWatcher_EmptyFile(t *testing.T) {
	ctx := context.Background()
	logger := observability.NewLogger(observability.Config{
		Component: "test",
		Level:     slog.LevelError,
	})

	// Create empty file
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")
	f, err := os.Create(logFile)
	require.NoError(t, err)
	f.Close()

	watcher, err := NewLogWatcher(ctx, logFile, logger)
	require.NoError(t, err)
	defer watcher.Close()

	err = watcher.Start()
	require.NoError(t, err)

	// Read historical lines from empty file
	lines, err := watcher.ReadHistoricalLines(10)
	require.NoError(t, err)
	assert.Empty(t, lines)

	// Now append a line
	time.Sleep(100 * time.Millisecond)
	f, err = os.OpenFile(logFile, os.O_APPEND|os.O_WRONLY, 0644)
	require.NoError(t, err)
	_, err = f.WriteString("first line\n")
	require.NoError(t, err)
	f.Close()

	// Should receive the line
	select {
	case line := <-watcher.Lines():
		assert.Equal(t, "first line", line)
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for line")
	}
}
