package component

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLogParserIntegration demonstrates how the log parser will be used
// in the status command to display recent errors from component logs.
func TestLogParserIntegration(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "component.log")

	// Simulate a component log file with realistic log entries
	logContent := `{"level":"INFO","msg":"component starting","time":"2025-01-01T10:00:00Z"}
{"level":"INFO","msg":"grpc server listening on port 50051","time":"2025-01-01T10:00:01Z"}
{"level":"DEBUG","msg":"received health check request","time":"2025-01-01T10:00:05Z"}
{"level":"INFO","msg":"processing task","time":"2025-01-01T10:00:10Z"}
{"level":"ERROR","msg":"failed to connect to database: connection timeout","time":"2025-01-01T10:00:15Z"}
{"level":"WARN","msg":"retrying database connection","time":"2025-01-01T10:00:20Z"}
{"level":"ERROR","msg":"database connection failed after 3 retries","time":"2025-01-01T10:00:25Z"}
{"level":"INFO","msg":"falling back to cache","time":"2025-01-01T10:00:26Z"}
{"level":"DEBUG","msg":"cache hit for key: user:123","time":"2025-01-01T10:00:27Z"}
{"level":"FATAL","msg":"out of memory: cannot allocate 1GB","time":"2025-01-01T10:00:30Z"}
`
	require.NoError(t, os.WriteFile(logFile, []byte(logContent), 0644))

	// Parse the 3 most recent errors as the status command would
	errors, err := ParseRecentErrors(logFile, 3)
	require.NoError(t, err)
	require.Len(t, errors, 3)

	// Verify we got the most recent errors in the correct order
	assert.Equal(t, "FATAL", errors[0].Level)
	assert.Equal(t, "out of memory: cannot allocate 1GB", errors[0].Message)
	assert.Equal(t, 2025, errors[0].Timestamp.Year())

	assert.Equal(t, "ERROR", errors[1].Level)
	assert.Equal(t, "database connection failed after 3 retries", errors[1].Message)

	assert.Equal(t, "ERROR", errors[2].Level)
	assert.Equal(t, "failed to connect to database: connection timeout", errors[2].Message)

	// Verify timestamps are in descending order
	assert.True(t, errors[0].Timestamp.After(errors[1].Timestamp))
	assert.True(t, errors[1].Timestamp.After(errors[2].Timestamp))
}

// TestLogParserWithComponentLogPath tests parsing logs from a realistic
// component installation directory structure.
func TestLogParserWithComponentLogPath(t *testing.T) {
	// Simulate the actual Gibson component directory structure
	// ~/.gibson/agents/scanner/logs/scanner.log
	tmpDir := t.TempDir()
	componentDir := filepath.Join(tmpDir, ".gibson", "agents", "scanner")
	logsDir := filepath.Join(componentDir, "logs")
	require.NoError(t, os.MkdirAll(logsDir, 0755))

	logFile := filepath.Join(logsDir, "scanner.log")

	// Write some realistic scanner agent logs
	logContent := `time=2025-01-01T10:00:00Z level=INFO msg="scanner agent started"
time=2025-01-01T10:01:00Z level=INFO msg="scanning target: example.com"
time=2025-01-01T10:02:00Z level=ERROR msg="nmap command failed: exit code 1"
time=2025-01-01T10:03:00Z level=ERROR msg="failed to parse nmap output"
time=2025-01-01T10:04:00Z level=INFO msg="scan completed with errors"
`
	require.NoError(t, os.WriteFile(logFile, []byte(logContent), 0644))

	// Parse errors
	errors, err := ParseRecentErrors(logFile, 5)
	require.NoError(t, err)
	require.Len(t, errors, 2)

	// Verify error details
	assert.Equal(t, "failed to parse nmap output", errors[0].Message)
	assert.Equal(t, "nmap command failed: exit code 1", errors[1].Message)
}

// TestLogParserPerformanceWithLargeLogFile verifies the parser can handle
// large log files efficiently (important for long-running components).
func TestLogParserPerformanceWithLargeLogFile(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping performance test in short mode")
	}

	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "large.log")

	// Create a large log file (10,000 entries, ~1MB)
	file, err := os.Create(logFile)
	require.NoError(t, err)
	defer file.Close()

	// Write 9,000 INFO logs and 1,000 ERROR logs
	for i := 0; i < 9000; i++ {
		_, _ = file.WriteString(`{"level":"INFO","msg":"normal operation","time":"2025-01-01T10:00:00Z"}` + "\n")
	}
	for i := 0; i < 1000; i++ {
		timestamp := time.Date(2025, 1, 1, 10, 0, i, 0, time.UTC)
		msg := `{"level":"ERROR","msg":"error ` + string(rune(i)) + `","time":"` + timestamp.Format(time.RFC3339) + `"}` + "\n"
		_, _ = file.WriteString(msg)
	}
	file.Close()

	// Measure parsing time
	start := time.Now()
	errors, err := ParseRecentErrors(logFile, 10)
	elapsed := time.Since(start)

	require.NoError(t, err)
	require.Len(t, errors, 10)

	// Should parse a 1MB file in under 2s. CI shared runners vary significantly;
	// 100ms was too tight on GitHub Actions. This is a smoke check, not a benchmark.
	assert.Less(t, elapsed, 2*time.Second, "parsing should be fast even for large files")

	t.Logf("Parsed 10,000 log entries in %v", elapsed)
}

// TestLogParserRotatedLogs tests handling of log rotation scenarios
// where the current log might be small but older logs exist.
func TestLogParserRotatedLogs(t *testing.T) {
	tmpDir := t.TempDir()
	currentLog := filepath.Join(tmpDir, "app.log")

	// Current log has only recent entries
	logContent := `{"level":"INFO","msg":"application restarted","time":"2025-01-02T00:00:00Z"}
{"level":"ERROR","msg":"new error after restart","time":"2025-01-02T00:00:10Z"}
`
	require.NoError(t, os.WriteFile(currentLog, []byte(logContent), 0644))

	// Parse the current log
	errors, err := ParseRecentErrors(currentLog, 5)
	require.NoError(t, err)
	require.Len(t, errors, 1)

	assert.Equal(t, "new error after restart", errors[0].Message)
}
