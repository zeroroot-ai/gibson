package component

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseRecentErrors_MissingFile(t *testing.T) {
	errors, err := ParseRecentErrors("/nonexistent/path/to/log.log", 5)
	require.NoError(t, err)
	assert.Empty(t, errors)
}

func TestParseRecentErrors_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "empty.log")
	require.NoError(t, os.WriteFile(logFile, []byte(""), 0644))

	errors, err := ParseRecentErrors(logFile, 5)
	require.NoError(t, err)
	assert.Empty(t, errors)
}

func TestParseRecentErrors_NoErrors(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "no-errors.log")

	content := `{"level":"INFO","msg":"starting up","time":"2025-01-01T12:00:00Z"}
{"level":"DEBUG","msg":"processing request","time":"2025-01-01T12:01:00Z"}
{"level":"WARN","msg":"slow query","time":"2025-01-01T12:02:00Z"}
`
	require.NoError(t, os.WriteFile(logFile, []byte(content), 0644))

	errors, err := ParseRecentErrors(logFile, 5)
	require.NoError(t, err)
	assert.Empty(t, errors)
}

func TestParseRecentErrors_JSONFormat(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "json.log")

	content := `{"level":"INFO","msg":"starting up","time":"2025-01-01T12:00:00Z"}
{"level":"ERROR","msg":"connection failed","time":"2025-01-01T12:01:00Z"}
{"level":"DEBUG","msg":"processing","time":"2025-01-01T12:02:00Z"}
{"level":"FATAL","msg":"system crash","time":"2025-01-01T12:03:00Z"}
{"level":"ERROR","msg":"timeout occurred","time":"2025-01-01T12:04:00Z"}
`
	require.NoError(t, os.WriteFile(logFile, []byte(content), 0644))

	errors, err := ParseRecentErrors(logFile, 10)
	require.NoError(t, err)
	require.Len(t, errors, 3)

	// Should be in reverse chronological order (newest first)
	assert.Equal(t, "timeout occurred", errors[0].Message)
	assert.Equal(t, "ERROR", errors[0].Level)
	assert.Equal(t, "2025-01-01T12:04:00Z", errors[0].Timestamp.Format(time.RFC3339))

	assert.Equal(t, "system crash", errors[1].Message)
	assert.Equal(t, "FATAL", errors[1].Level)

	assert.Equal(t, "connection failed", errors[2].Message)
	assert.Equal(t, "ERROR", errors[2].Level)
}

func TestParseRecentErrors_KeyValueFormat(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "keyvalue.log")

	content := `time=2025-01-01T12:00:00Z level=INFO msg="starting up"
time=2025-01-01T12:01:00Z level=ERROR msg="connection failed"
time=2025-01-01T12:02:00Z level=DEBUG msg="processing"
time=2025-01-01T12:03:00Z level=FATAL msg="system crash"
time=2025-01-01T12:04:00Z level=ERROR msg="timeout occurred"
`
	require.NoError(t, os.WriteFile(logFile, []byte(content), 0644))

	errors, err := ParseRecentErrors(logFile, 10)
	require.NoError(t, err)
	require.Len(t, errors, 3)

	// Should be in reverse chronological order
	assert.Equal(t, "timeout occurred", errors[0].Message)
	assert.Equal(t, "ERROR", errors[0].Level)

	assert.Equal(t, "system crash", errors[1].Message)
	assert.Equal(t, "FATAL", errors[1].Level)

	assert.Equal(t, "connection failed", errors[2].Message)
	assert.Equal(t, "ERROR", errors[2].Level)
}

func TestParseRecentErrors_MixedFormats(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "mixed.log")

	content := `{"level":"ERROR","msg":"json error 1","time":"2025-01-01T12:01:00Z"}
time=2025-01-01T12:02:00Z level=ERROR msg="keyvalue error 1"
{"level":"FATAL","msg":"json fatal","time":"2025-01-01T12:03:00Z"}
time=2025-01-01T12:04:00Z level=FATAL msg="keyvalue fatal"
`
	require.NoError(t, os.WriteFile(logFile, []byte(content), 0644))

	errors, err := ParseRecentErrors(logFile, 10)
	require.NoError(t, err)
	require.Len(t, errors, 4)

	// Verify order (newest first)
	assert.Equal(t, "keyvalue fatal", errors[0].Message)
	assert.Equal(t, "json fatal", errors[1].Message)
	assert.Equal(t, "keyvalue error 1", errors[2].Message)
	assert.Equal(t, "json error 1", errors[3].Message)
}

func TestParseRecentErrors_LimitCount(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "limit.log")

	content := `{"level":"ERROR","msg":"error 1","time":"2025-01-01T12:01:00Z"}
{"level":"ERROR","msg":"error 2","time":"2025-01-01T12:02:00Z"}
{"level":"ERROR","msg":"error 3","time":"2025-01-01T12:03:00Z"}
{"level":"ERROR","msg":"error 4","time":"2025-01-01T12:04:00Z"}
{"level":"ERROR","msg":"error 5","time":"2025-01-01T12:05:00Z"}
`
	require.NoError(t, os.WriteFile(logFile, []byte(content), 0644))

	errors, err := ParseRecentErrors(logFile, 3)
	require.NoError(t, err)
	require.Len(t, errors, 3)

	// Should get the 3 most recent
	assert.Equal(t, "error 5", errors[0].Message)
	assert.Equal(t, "error 4", errors[1].Message)
	assert.Equal(t, "error 3", errors[2].Message)
}

func TestParseRecentErrors_MalformedLines(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "malformed.log")

	content := `{"level":"ERROR","msg":"valid json","time":"2025-01-01T12:01:00Z"}
this is not json or keyvalue
{broken json
time=2025-01-01T12:02:00Z level=ERROR msg="valid keyvalue"
random text here
incomplete=keyvalue
{"level":"ERROR","msg":"another valid","time":"2025-01-01T12:03:00Z"}
`
	require.NoError(t, os.WriteFile(logFile, []byte(content), 0644))

	errors, err := ParseRecentErrors(logFile, 10)
	require.NoError(t, err)
	require.Len(t, errors, 3)

	assert.Equal(t, "another valid", errors[0].Message)
	assert.Equal(t, "valid keyvalue", errors[1].Message)
	assert.Equal(t, "valid json", errors[2].Message)
}

func TestParseRecentErrors_CaseInsensitiveLevel(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "case.log")

	content := `{"level":"error","msg":"lowercase error","time":"2025-01-01T12:01:00Z"}
{"level":"Error","msg":"mixed case error","time":"2025-01-01T12:02:00Z"}
{"level":"ERROR","msg":"uppercase error","time":"2025-01-01T12:03:00Z"}
time=2025-01-01T12:04:00Z level=fatal msg="lowercase fatal"
time=2025-01-01T12:05:00Z level=FATAL msg="uppercase fatal"
`
	require.NoError(t, os.WriteFile(logFile, []byte(content), 0644))

	errors, err := ParseRecentErrors(logFile, 10)
	require.NoError(t, err)
	require.Len(t, errors, 5)

	// All should be normalized to uppercase
	for _, e := range errors {
		assert.True(t, e.Level == "ERROR" || e.Level == "FATAL")
	}
}

func TestParseRecentErrors_TimestampFormats(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "timestamps.log")

	content := `{"level":"ERROR","msg":"RFC3339","time":"2025-01-01T12:00:00Z"}
{"level":"ERROR","msg":"RFC3339Nano","time":"2025-01-01T12:01:00.123456789Z"}
{"level":"ERROR","msg":"No Z","time":"2025-01-01T12:02:00"}
time=2025-01-01T12:03:00Z level=ERROR msg="keyvalue timestamp"
`
	require.NoError(t, os.WriteFile(logFile, []byte(content), 0644))

	errors, err := ParseRecentErrors(logFile, 10)
	require.NoError(t, err)
	require.Len(t, errors, 4)

	// All timestamps should be parsed successfully
	for _, e := range errors {
		assert.False(t, e.Timestamp.IsZero(), "timestamp should not be zero for: %s", e.Message)
	}
}

func TestParseRecentErrors_EmptyLinesAndWhitespace(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "whitespace.log")

	content := `
{"level":"ERROR","msg":"error 1","time":"2025-01-01T12:01:00Z"}

{"level":"ERROR","msg":"error 2","time":"2025-01-01T12:02:00Z"}

`
	require.NoError(t, os.WriteFile(logFile, []byte(content), 0644))

	errors, err := ParseRecentErrors(logFile, 10)
	require.NoError(t, err)
	require.Len(t, errors, 2)
}

func TestParseRecentErrors_QuotedValues(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "quoted.log")

	content := `time=2025-01-01T12:01:00Z level=ERROR msg="error with spaces and special chars: !@#$%"
time=2025-01-01T12:02:00Z level=FATAL msg="another error with = equals sign"
`
	require.NoError(t, os.WriteFile(logFile, []byte(content), 0644))

	errors, err := ParseRecentErrors(logFile, 10)
	require.NoError(t, err)
	require.Len(t, errors, 2)

	assert.Equal(t, "another error with = equals sign", errors[0].Message)
	assert.Equal(t, "error with spaces and special chars: !@#$%", errors[1].Message)
}

func TestParseRecentErrors_ZeroCount(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "zero.log")

	content := `{"level":"ERROR","msg":"error 1","time":"2025-01-01T12:01:00Z"}
{"level":"ERROR","msg":"error 2","time":"2025-01-01T12:02:00Z"}
`
	require.NoError(t, os.WriteFile(logFile, []byte(content), 0644))

	errors, err := ParseRecentErrors(logFile, 0)
	require.NoError(t, err)
	assert.Empty(t, errors)
}

// Benchmark tests
func BenchmarkParseRecentErrors_JSON(b *testing.B) {
	tmpDir := b.TempDir()
	logFile := filepath.Join(tmpDir, "bench.log")

	// Create a log file with 1000 entries (10% errors)
	var content string
	for i := 0; i < 1000; i++ {
		level := "INFO"
		if i%10 == 0 {
			level = "ERROR"
		}
		content += `{"level":"` + level + `","msg":"message ` + string(rune(i)) + `","time":"2025-01-01T12:00:00Z"}` + "\n"
	}
	require.NoError(b, os.WriteFile(logFile, []byte(content), 0644))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseRecentErrors(logFile, 10)
	}
}

func BenchmarkParseRecentErrors_KeyValue(b *testing.B) {
	tmpDir := b.TempDir()
	logFile := filepath.Join(tmpDir, "bench.log")

	// Create a log file with 1000 entries (10% errors)
	var content string
	for i := 0; i < 1000; i++ {
		level := "INFO"
		if i%10 == 0 {
			level = "ERROR"
		}
		content += `time=2025-01-01T12:00:00Z level=` + level + ` msg="message ` + string(rune(i)) + `"` + "\n"
	}
	require.NoError(b, os.WriteFile(logFile, []byte(content), 0644))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseRecentErrors(logFile, 10)
	}
}
