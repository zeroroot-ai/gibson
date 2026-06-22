package component

import (
	"bufio"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	// defaultBufferSize for reading log files efficiently
	defaultBufferSize = 64 * 1024 // 64KB

	// maxLineLength prevents excessive memory usage from malformed logs
	maxLineLength = 1024 * 1024 // 1MB
)

// ParseRecentErrors parses the most recent error-level log entries from a log file.
// It supports two log formats:
//  1. JSON: {"level":"ERROR","msg":"something failed","time":"2025-01-01T12:00:00Z"}
//  2. Key=value: time=2025-01-01T12:00:00Z level=ERROR msg="something failed"
//
// The function filters for ERROR and FATAL level entries only and returns the most
// recent 'count' errors in reverse chronological order (newest first).
//
// Edge cases:
//   - Missing file: returns empty slice, nil error
//   - Empty file: returns empty slice, nil
//   - No errors found: returns empty slice, nil
//   - Malformed lines: skipped without causing failure
//
// For efficiency with large files, this reads the entire file and filters errors,
// then returns the most recent ones. Future optimization could implement true
// tail-reading for extremely large files.
func ParseRecentErrors(logPath string, count int) ([]LogError, error) {
	// Handle edge case: missing file
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		return []LogError{}, nil
	}

	file, err := os.Open(logPath)
	if err != nil {
		// If we can't open the file, treat it as missing
		return []LogError{}, nil
	}
	defer file.Close()

	var errors []LogError
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, defaultBufferSize), maxLineLength)

	// Read all lines and parse errors
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		// Try parsing as JSON first, then fall back to key=value
		if logErr, ok := parseJSONLogLine(line); ok {
			if isErrorLevel(logErr.Level) {
				errors = append(errors, logErr)
			}
		} else if logErr, ok := parseKeyValueLogLine(line); ok {
			if isErrorLevel(logErr.Level) {
				errors = append(errors, logErr)
			}
		}
		// Silently skip malformed lines
	}

	// Check for scanner errors (but don't fail on them)
	if err := scanner.Err(); err != nil {
		// Return what we've parsed so far
	}

	// Handle edge case: no errors found
	if len(errors) == 0 {
		return []LogError{}, nil
	}

	// Sort by timestamp (newest first)
	sort.Slice(errors, func(i, j int) bool {
		return errors[i].Timestamp.After(errors[j].Timestamp)
	})

	// Return the most recent 'count' errors
	if len(errors) > count {
		return errors[:count], nil
	}

	return errors, nil
}

// parseJSONLogLine attempts to parse a log line in JSON format.
// Expected format: {"level":"ERROR","msg":"something failed","time":"2025-01-01T12:00:00Z"}
// Returns the parsed LogError and true if successful, false otherwise.
func parseJSONLogLine(line string) (LogError, bool) {
	var logEntry struct {
		Level   string `json:"level"`
		Message string `json:"msg"`
		Time    string `json:"time"`
	}

	if err := json.Unmarshal([]byte(line), &logEntry); err != nil {
		return LogError{}, false
	}

	// Parse timestamp - try multiple common formats
	timestamp := parseTimestamp(logEntry.Time)

	return LogError{
		Timestamp: timestamp,
		Message:   logEntry.Message,
		Level:     strings.ToUpper(logEntry.Level),
	}, true
}

// parseKeyValueLogLine attempts to parse a log line in key=value format.
// Expected format: time=2025-01-01T12:00:00Z level=ERROR msg="something failed"
// Returns the parsed LogError and true if successful, false otherwise.
func parseKeyValueLogLine(line string) (LogError, bool) {
	fields := make(map[string]string)

	// Simple key=value parser that handles quoted values
	parts := splitKeyValue(line)
	for _, part := range parts {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])
		// Remove quotes from value if present
		value = strings.Trim(value, `"`)
		fields[key] = value
	}

	// Must have at least level and msg fields
	level, hasLevel := fields["level"]
	msg, hasMsg := fields["msg"]
	if !hasLevel || !hasMsg {
		return LogError{}, false
	}

	// Parse timestamp if present
	timeStr, hasTime := fields["time"]
	var timestamp time.Time
	if hasTime {
		timestamp = parseTimestamp(timeStr)
	}

	return LogError{
		Timestamp: timestamp,
		Message:   msg,
		Level:     strings.ToUpper(level),
	}, true
}

// splitKeyValue splits a key=value formatted line, respecting quoted values.
// Example: time=2025-01-01T12:00:00Z level=ERROR msg="something failed"
// Returns: [time=2025-01-01T12:00:00Z, level=ERROR, msg="something failed"]
func splitKeyValue(line string) []string {
	var parts []string
	var current strings.Builder
	inQuotes := false

	for i, ch := range line {
		switch ch {
		case '"':
			inQuotes = !inQuotes
			current.WriteRune(ch)
		case ' ':
			if inQuotes {
				current.WriteRune(ch)
			} else {
				if current.Len() > 0 {
					parts = append(parts, current.String())
					current.Reset()
				}
			}
		default:
			current.WriteRune(ch)
		}

		// Add the last part
		if i == len(line)-1 && current.Len() > 0 {
			parts = append(parts, current.String())
		}
	}

	return parts
}

// parseTimestamp attempts to parse a timestamp string using common formats.
// Returns zero time if parsing fails.
func parseTimestamp(timeStr string) time.Time {
	formats := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		time.RFC1123,
		time.RFC1123Z,
	}

	for _, format := range formats {
		if t, err := time.Parse(format, timeStr); err == nil {
			return t
		}
	}

	return time.Time{}
}

// isErrorLevel checks if a log level is considered an error.
// Returns true for ERROR and FATAL levels (case-insensitive).
func isErrorLevel(level string) bool {
	upper := strings.ToUpper(level)
	return upper == "ERROR" || upper == "FATAL"
}
