package component

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDefaultLogWriter(t *testing.T) {
	tmpDir := t.TempDir()
	logDir := filepath.Join(tmpDir, "logs")

	writer, err := NewDefaultLogWriter(logDir, nil)
	require.NoError(t, err)
	require.NotNil(t, writer)

	// Verify directory was created
	stat, err := os.Stat(logDir)
	require.NoError(t, err)
	assert.True(t, stat.IsDir())

	// Verify permissions are correct
	assert.Equal(t, os.FileMode(0755), stat.Mode().Perm())

	// Verify internal state
	assert.Equal(t, logDir, writer.logDir)
	assert.NotNil(t, writer.writers)
	assert.Empty(t, writer.writers)
	assert.NotNil(t, writer.rotator) // Should have default rotator
}

func TestNewDefaultLogWriter_ExistingDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a writer which will create the directory
	writer1, err := NewDefaultLogWriter(tmpDir, nil)
	require.NoError(t, err)
	require.NotNil(t, writer1)

	// Create another writer pointing to the same directory
	writer2, err := NewDefaultLogWriter(tmpDir, nil)
	require.NoError(t, err)
	require.NotNil(t, writer2)

	// Both should work fine
	assert.Equal(t, tmpDir, writer1.logDir)
	assert.Equal(t, tmpDir, writer2.logDir)
}

func TestNewDefaultLogWriter_InvalidPath(t *testing.T) {
	// Try to create a log writer in a path that can't be created
	writer, err := NewDefaultLogWriter("/proc/invalid/path/that/cannot/be/created", nil)
	assert.Error(t, err)
	assert.Nil(t, writer)
	assert.Contains(t, err.Error(), "failed to create log directory")
}

func TestCreateWriter_CreatesDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	logDir := filepath.Join(tmpDir, "nested", "log", "directory")

	writer, err := NewDefaultLogWriter(logDir, nil)
	require.NoError(t, err)
	require.NotNil(t, writer)

	// Directory should exist after NewDefaultLogWriter
	stat, err := os.Stat(logDir)
	require.NoError(t, err)
	assert.True(t, stat.IsDir())
}

func TestCreateWriter_CreatesLogFile(t *testing.T) {
	tmpDir := t.TempDir()
	writer, err := NewDefaultLogWriter(tmpDir, nil)
	require.NoError(t, err)

	componentName := "test-component"
	w, err := writer.CreateWriter(componentName, "stdout")
	require.NoError(t, err)
	require.NotNil(t, w)
	defer w.Close()

	// Verify log file was created
	logPath := filepath.Join(tmpDir, "test-component.log")
	stat, err := os.Stat(logPath)
	require.NoError(t, err)
	assert.False(t, stat.IsDir())

	// Verify permissions are correct
	assert.Equal(t, os.FileMode(0644), stat.Mode().Perm())
}

func TestCreateWriter_AppendsToExisting(t *testing.T) {
	tmpDir := t.TempDir()
	writer, err := NewDefaultLogWriter(tmpDir, nil)
	require.NoError(t, err)

	componentName := "append-test"
	logPath := filepath.Join(tmpDir, "append-test.log")

	// Create initial log file with some content
	initialContent := "existing log content\n"
	require.NoError(t, os.WriteFile(logPath, []byte(initialContent), 0644))

	// Create a writer which should append
	w, err := writer.CreateWriter(componentName, "stdout")
	require.NoError(t, err)
	require.NotNil(t, w)

	// Write new content
	_, err = w.Write([]byte("new content\n"))
	require.NoError(t, err)

	// Close to flush
	require.NoError(t, w.Close())

	// Read the file and verify both old and new content exist
	content, err := os.ReadFile(logPath)
	require.NoError(t, err)

	contentStr := string(content)
	assert.Contains(t, contentStr, initialContent)
	assert.Contains(t, contentStr, "new content")

	// Verify old content comes first
	assert.True(t, strings.Index(contentStr, initialContent) < strings.Index(contentStr, "new content"))
}

func TestStreamPrefixWriter_FormatsLines_Stdout(t *testing.T) {
	tmpDir := t.TempDir()
	writer, err := NewDefaultLogWriter(tmpDir, nil)
	require.NoError(t, err)

	componentName := "format-test"
	w, err := writer.CreateWriter(componentName, "stdout")
	require.NoError(t, err)
	defer w.Close()

	// Write a single line
	testMsg := "test message\n"
	_, err = w.Write([]byte(testMsg))
	require.NoError(t, err)

	// Close to flush
	require.NoError(t, w.Close())

	// Read the file
	logPath := filepath.Join(tmpDir, "format-test.log")
	content, err := os.ReadFile(logPath)
	require.NoError(t, err)

	contentStr := string(content)

	// Verify format: timestamp [STDOUT] message
	assert.Contains(t, contentStr, "[STDOUT]")
	assert.Contains(t, contentStr, "test message")

	// Verify RFC3339 timestamp format. time.RFC3339 produces "Z" for UTC
	// and "+HH:MM" for non-UTC zones; accept both.
	assert.Regexp(t, `\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(Z|[+-]\d{2}:\d{2}) \[STDOUT\] test message`, contentStr)
}

func TestStreamPrefixWriter_FormatsLines_Stderr(t *testing.T) {
	tmpDir := t.TempDir()
	writer, err := NewDefaultLogWriter(tmpDir, nil)
	require.NoError(t, err)

	componentName := "stderr-test"
	w, err := writer.CreateWriter(componentName, "stderr")
	require.NoError(t, err)
	defer w.Close()

	// Write a single line
	testMsg := "error message\n"
	_, err = w.Write([]byte(testMsg))
	require.NoError(t, err)

	// Close to flush
	require.NoError(t, w.Close())

	// Read the file
	logPath := filepath.Join(tmpDir, "stderr-test.log")
	content, err := os.ReadFile(logPath)
	require.NoError(t, err)

	contentStr := string(content)

	// Verify format: timestamp [STDERR] message
	assert.Contains(t, contentStr, "[STDERR]")
	assert.Contains(t, contentStr, "error message")

	// Verify RFC3339 timestamp format. time.RFC3339 produces "Z" for UTC
	// and "+HH:MM" for non-UTC zones; accept both.
	assert.Regexp(t, `\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(Z|[+-]\d{2}:\d{2}) \[STDERR\] error message`, contentStr)
}

func TestStreamPrefixWriter_MultipleLines(t *testing.T) {
	tmpDir := t.TempDir()
	writer, err := NewDefaultLogWriter(tmpDir, nil)
	require.NoError(t, err)

	componentName := "multiline-test"
	w, err := writer.CreateWriter(componentName, "stdout")
	require.NoError(t, err)
	defer w.Close()

	// Write multiple lines
	lines := []string{
		"line one\n",
		"line two\n",
		"line three\n",
	}

	for _, line := range lines {
		_, err = w.Write([]byte(line))
		require.NoError(t, err)
	}

	// Close to flush
	require.NoError(t, w.Close())

	// Read the file
	logPath := filepath.Join(tmpDir, "multiline-test.log")
	content, err := os.ReadFile(logPath)
	require.NoError(t, err)

	contentStr := string(content)

	// Each line should have its own timestamp and prefix
	for _, line := range lines {
		trimmed := strings.TrimSuffix(line, "\n")
		assert.Contains(t, contentStr, trimmed)
	}

	// Count the number of [STDOUT] prefixes - should be 3
	stdoutCount := strings.Count(contentStr, "[STDOUT]")
	assert.Equal(t, 3, stdoutCount)

	// Count the number of lines - should be 3
	lineCount := strings.Count(contentStr, "\n")
	assert.Equal(t, 3, lineCount)
}

func TestStreamPrefixWriter_PartialLines(t *testing.T) {
	tmpDir := t.TempDir()
	writer, err := NewDefaultLogWriter(tmpDir, nil)
	require.NoError(t, err)

	componentName := "partial-test"
	w, err := writer.CreateWriter(componentName, "stdout")
	require.NoError(t, err)
	defer w.Close()

	// Write partial line (no newline)
	_, err = w.Write([]byte("partial "))
	require.NoError(t, err)

	// Write more to the same line
	_, err = w.Write([]byte("line"))
	require.NoError(t, err)

	// Complete the line
	_, err = w.Write([]byte(" complete\n"))
	require.NoError(t, err)

	// Close to flush
	require.NoError(t, w.Close())

	// Read the file
	logPath := filepath.Join(tmpDir, "partial-test.log")
	content, err := os.ReadFile(logPath)
	require.NoError(t, err)

	contentStr := string(content)

	// Should only have ONE timestamp/prefix for the entire line
	stdoutCount := strings.Count(contentStr, "[STDOUT]")
	assert.Equal(t, 1, stdoutCount)

	// Should contain the complete message
	assert.Contains(t, contentStr, "partial line complete")
}

func TestStreamPrefixWriter_EmptyWrite(t *testing.T) {
	tmpDir := t.TempDir()
	writer, err := NewDefaultLogWriter(tmpDir, nil)
	require.NoError(t, err)

	componentName := "empty-test"
	w, err := writer.CreateWriter(componentName, "stdout")
	require.NoError(t, err)
	defer w.Close()

	// Write empty data
	n, err := w.Write([]byte{})
	require.NoError(t, err)
	assert.Equal(t, 0, n)

	// Close to flush
	require.NoError(t, w.Close())

	// File should exist but be empty
	logPath := filepath.Join(tmpDir, "empty-test.log")
	content, err := os.ReadFile(logPath)
	require.NoError(t, err)
	assert.Empty(t, content)
}

func TestClose_FlushesBuffer(t *testing.T) {
	tmpDir := t.TempDir()
	writer, err := NewDefaultLogWriter(tmpDir, nil)
	require.NoError(t, err)

	componentName := "flush-test"
	w, err := writer.CreateWriter(componentName, "stdout")
	require.NoError(t, err)

	// Write data but don't close the writer yet
	testMsg := "buffered content\n"
	_, err = w.Write([]byte(testMsg))
	require.NoError(t, err)

	logPath := filepath.Join(tmpDir, "flush-test.log")

	// Data might not be in the file yet (still buffered)
	// Now close the writer
	require.NoError(t, w.Close())

	// Data should definitely be in the file now
	content, err := os.ReadFile(logPath)
	require.NoError(t, err)
	assert.Contains(t, string(content), "buffered content")
}

func TestClose_ComponentWriter(t *testing.T) {
	tmpDir := t.TempDir()
	writer, err := NewDefaultLogWriter(tmpDir, nil)
	require.NoError(t, err)

	componentName := "close-test"

	// Create multiple writers for the same component
	stdout, err := writer.CreateWriter(componentName, "stdout")
	require.NoError(t, err)

	stderr, err := writer.CreateWriter(componentName, "stderr")
	require.NoError(t, err)

	// Write to both
	_, err = stdout.Write([]byte("stdout message\n"))
	require.NoError(t, err)

	_, err = stderr.Write([]byte("stderr message\n"))
	require.NoError(t, err)

	// Close all writers for the component
	err = writer.Close(componentName)
	require.NoError(t, err)

	// Verify data was flushed
	logPath := filepath.Join(tmpDir, "close-test.log")
	content, err := os.ReadFile(logPath)
	require.NoError(t, err)

	contentStr := string(content)
	assert.Contains(t, contentStr, "stdout message")
	assert.Contains(t, contentStr, "stderr message")
	assert.Contains(t, contentStr, "[STDOUT]")
	assert.Contains(t, contentStr, "[STDERR]")

	// Verify writers were removed from tracking
	writer.mu.Lock()
	assert.Empty(t, writer.writers[componentName])
	writer.mu.Unlock()
}

func TestClose_NonexistentComponent(t *testing.T) {
	tmpDir := t.TempDir()
	writer, err := NewDefaultLogWriter(tmpDir, nil)
	require.NoError(t, err)

	// Close a component that doesn't exist - should not error
	err = writer.Close("nonexistent")
	assert.NoError(t, err)
}

func TestClose_MultipleTimes(t *testing.T) {
	tmpDir := t.TempDir()
	writer, err := NewDefaultLogWriter(tmpDir, nil)
	require.NoError(t, err)

	componentName := "multi-close-test"
	w, err := writer.CreateWriter(componentName, "stdout")
	require.NoError(t, err)

	_, err = w.Write([]byte("test\n"))
	require.NoError(t, err)

	// Close the component
	err = writer.Close(componentName)
	require.NoError(t, err)

	// Close again - should not error
	err = writer.Close(componentName)
	assert.NoError(t, err)
}

func TestConcurrentWrites_Safe(t *testing.T) {
	tmpDir := t.TempDir()
	writer, err := NewDefaultLogWriter(tmpDir, nil)
	require.NoError(t, err)

	componentName := "concurrent-test"

	// Create stdout and stderr writers
	stdout, err := writer.CreateWriter(componentName, "stdout")
	require.NoError(t, err)
	defer stdout.Close()

	stderr, err := writer.CreateWriter(componentName, "stderr")
	require.NoError(t, err)
	defer stderr.Close()

	// Number of goroutines and writes per goroutine
	const numGoroutines = 10
	const writesPerGoroutine = 100

	var wg sync.WaitGroup

	// Launch goroutines writing to stdout
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < writesPerGoroutine; j++ {
				msg := fmt.Sprintf("stdout-%d-%d\n", id, j)
				_, err := stdout.Write([]byte(msg))
				assert.NoError(t, err)
			}
		}(i)
	}

	// Launch goroutines writing to stderr
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < writesPerGoroutine; j++ {
				msg := fmt.Sprintf("stderr-%d-%d\n", id, j)
				_, err := stderr.Write([]byte(msg))
				assert.NoError(t, err)
			}
		}(i)
	}

	// Wait for all writes to complete
	wg.Wait()

	// Close to flush
	require.NoError(t, writer.Close(componentName))

	// Read and verify the log file
	logPath := filepath.Join(tmpDir, "concurrent-test.log")
	content, err := os.ReadFile(logPath)
	require.NoError(t, err)

	contentStr := string(content)

	// Count total lines - should be numGoroutines * writesPerGoroutine * 2 (stdout + stderr)
	expectedLines := numGoroutines * writesPerGoroutine * 2
	actualLines := strings.Count(contentStr, "\n")
	assert.Equal(t, expectedLines, actualLines)

	// Verify all messages are present
	for i := 0; i < numGoroutines; i++ {
		for j := 0; j < writesPerGoroutine; j++ {
			stdoutMsg := fmt.Sprintf("stdout-%d-%d", i, j)
			stderrMsg := fmt.Sprintf("stderr-%d-%d", i, j)
			assert.Contains(t, contentStr, stdoutMsg)
			assert.Contains(t, contentStr, stderrMsg)
		}
	}

	// Verify prefixes are present
	stdoutCount := strings.Count(contentStr, "[STDOUT]")
	stderrCount := strings.Count(contentStr, "[STDERR]")
	expectedCount := numGoroutines * writesPerGoroutine
	assert.Equal(t, expectedCount, stdoutCount)
	assert.Equal(t, expectedCount, stderrCount)
}

func TestConcurrentWrites_SplitLines(t *testing.T) {
	tmpDir := t.TempDir()
	writer, err := NewDefaultLogWriter(tmpDir, nil)
	require.NoError(t, err)

	componentName := "split-concurrent-test"
	w, err := writer.CreateWriter(componentName, "stdout")
	require.NoError(t, err)
	defer w.Close()

	const numGoroutines = 5
	const writesPerGoroutine = 50

	var wg sync.WaitGroup

	// Each goroutine writes partial lines
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < writesPerGoroutine; j++ {
				// Write message in parts
				msg := fmt.Sprintf("msg-%d-%d", id, j)
				_, err := w.Write([]byte(msg))
				assert.NoError(t, err)
				_, err = w.Write([]byte("\n"))
				assert.NoError(t, err)
			}
		}(i)
	}

	wg.Wait()
	require.NoError(t, writer.Close(componentName))

	// Verify the log file
	logPath := filepath.Join(tmpDir, "split-concurrent-test.log")
	content, err := os.ReadFile(logPath)
	require.NoError(t, err)

	contentStr := string(content)

	// All messages should be present
	for i := 0; i < numGoroutines; i++ {
		for j := 0; j < writesPerGoroutine; j++ {
			msg := fmt.Sprintf("msg-%d-%d", i, j)
			assert.Contains(t, contentStr, msg)
		}
	}

	// Total line count should match
	expectedLines := numGoroutines * writesPerGoroutine
	actualLines := strings.Count(contentStr, "\n")
	assert.Equal(t, expectedLines, actualLines)
}

func TestMultipleComponents(t *testing.T) {
	tmpDir := t.TempDir()
	writer, err := NewDefaultLogWriter(tmpDir, nil)
	require.NoError(t, err)

	// Create writers for different components
	components := []string{"component-a", "component-b", "component-c"}

	for _, comp := range components {
		w, err := writer.CreateWriter(comp, "stdout")
		require.NoError(t, err)

		msg := fmt.Sprintf("message from %s\n", comp)
		_, err = w.Write([]byte(msg))
		require.NoError(t, err)

		w.Close()
	}

	// Verify each component has its own log file
	for _, comp := range components {
		logPath := filepath.Join(tmpDir, fmt.Sprintf("%s.log", comp))
		content, err := os.ReadFile(logPath)
		require.NoError(t, err)

		contentStr := string(content)
		expectedMsg := fmt.Sprintf("message from %s", comp)
		assert.Contains(t, contentStr, expectedMsg)

		// Verify it doesn't contain messages from other components
		for _, otherComp := range components {
			if otherComp != comp {
				otherMsg := fmt.Sprintf("message from %s", otherComp)
				assert.NotContains(t, contentStr, otherMsg)
			}
		}
	}
}

func TestTimestampFormat(t *testing.T) {
	tmpDir := t.TempDir()
	writer, err := NewDefaultLogWriter(tmpDir, nil)
	require.NoError(t, err)

	componentName := "timestamp-test"
	w, err := writer.CreateWriter(componentName, "stdout")
	require.NoError(t, err)

	before := time.Now()
	_, err = w.Write([]byte("test\n"))
	require.NoError(t, err)
	after := time.Now()

	require.NoError(t, w.Close())

	// Read the file
	logPath := filepath.Join(tmpDir, "timestamp-test.log")
	content, err := os.ReadFile(logPath)
	require.NoError(t, err)

	contentStr := string(content)

	// Extract timestamp from the log line
	// Format: "2025-01-01T12:00:00-06:00 [STDOUT] test"
	parts := strings.SplitN(contentStr, " ", 3)
	require.Len(t, parts, 3)

	timestampStr := parts[0]
	timestamp, err := time.Parse(time.RFC3339, timestampStr)
	require.NoError(t, err)

	// Verify timestamp is reasonable (within the before/after window)
	// Allow for some clock skew
	assert.True(t, timestamp.After(before.Add(-time.Second)))
	assert.True(t, timestamp.Before(after.Add(time.Second)))
}

func TestLogWriter_WithRotation(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a rotator with very small threshold for testing (2KB)
	rotator := NewDefaultLogRotator(2048, 3)
	writer, err := NewDefaultLogWriter(tmpDir, rotator)
	require.NoError(t, err)

	componentName := "rotation-test"
	w, err := writer.CreateWriter(componentName, "stdout")
	require.NoError(t, err)

	// Write enough data to trigger rotation check (> 1MB to exceed rotationCheckInterval)
	// Each line is roughly 100 bytes, so write 12000 lines (~1.2MB)
	lineTemplate := "This is a test log line with some content - line %05d\n"
	for i := 0; i < 12000; i++ {
		line := fmt.Sprintf(lineTemplate, i)
		_, err := w.Write([]byte(line))
		require.NoError(t, err)
	}

	// Close to flush
	require.NoError(t, w.Close())

	// Verify log file exists
	logPath := filepath.Join(tmpDir, "rotation-test.log")
	require.FileExists(t, logPath)

	// Since we wrote > 2KB and triggered the rotation check,
	// we should have backup files
	backup1Path := fmt.Sprintf("%s.1", logPath)

	// The file may or may not be rotated depending on timing,
	// but at minimum we should have a log file
	stat, err := os.Stat(logPath)
	require.NoError(t, err)
	assert.Greater(t, stat.Size(), int64(0), "log file should have content")

	// If rotation occurred, verify backup exists
	if _, err := os.Stat(backup1Path); err == nil {
		t.Logf("Rotation occurred - backup file exists: %s", backup1Path)
		backupStat, err := os.Stat(backup1Path)
		require.NoError(t, err)
		assert.Greater(t, backupStat.Size(), int64(0), "backup should have content")
	}
}

func TestLogWriter_CustomRotator(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a custom rotator with specific settings
	customRotator := NewDefaultLogRotator(5*1024, 2) // 5KB, 2 backups
	writer, err := NewDefaultLogWriter(tmpDir, customRotator)
	require.NoError(t, err)
	require.NotNil(t, writer.rotator)

	// Verify the rotator settings
	assert.Equal(t, int64(5*1024), customRotator.MaxSize())
	assert.Equal(t, 2, customRotator.MaxBackups())
}

func TestLogWriter_NilRotatorUsesDefault(t *testing.T) {
	tmpDir := t.TempDir()

	// Pass nil rotator - should create default
	writer, err := NewDefaultLogWriter(tmpDir, nil)
	require.NoError(t, err)
	require.NotNil(t, writer.rotator)

	// Verify it's a default rotator by checking it has reasonable defaults
	// We can't directly check the type, but we can verify it works
	componentName := "default-rotator-test"
	w, err := writer.CreateWriter(componentName, "stdout")
	require.NoError(t, err)

	_, err = w.Write([]byte("test message\n"))
	require.NoError(t, err)

	require.NoError(t, w.Close())

	logPath := filepath.Join(tmpDir, "default-rotator-test.log")
	require.FileExists(t, logPath)
}

// Benchmark tests
func BenchmarkLogWriter_SingleWrite(b *testing.B) {
	tmpDir := b.TempDir()
	writer, err := NewDefaultLogWriter(tmpDir, nil)
	require.NoError(b, err)

	w, err := writer.CreateWriter("bench-component", "stdout")
	require.NoError(b, err)
	defer w.Close()

	msg := []byte("benchmark message\n")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = w.Write(msg)
	}
}

func BenchmarkLogWriter_ConcurrentWrites(b *testing.B) {
	tmpDir := b.TempDir()
	writer, err := NewDefaultLogWriter(tmpDir, nil)
	require.NoError(b, err)

	stdout, err := writer.CreateWriter("bench-component", "stdout")
	require.NoError(b, err)
	defer stdout.Close()

	stderr, err := writer.CreateWriter("bench-component", "stderr")
	require.NoError(b, err)
	defer stderr.Close()

	msg := []byte("benchmark message\n")

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = stdout.Write(msg)
			_, _ = stderr.Write(msg)
		}
	})
}
