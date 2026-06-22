package component

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// LogWriter provides an interface for writing component logs to persistent storage.
// Implementations must handle concurrent writes from stdout and stderr streams safely.
type LogWriter interface {
	// CreateWriter returns an io.WriteCloser for the given component and stream.
	// stream is either "stdout" or "stderr".
	CreateWriter(componentName string, stream string) (io.WriteCloser, error)

	// Close closes all writers for the component and flushes buffers.
	Close(componentName string) error
}

// DefaultLogWriter implements LogWriter by writing to files in a configured directory.
// It creates log files at <logDir>/<componentName>.log and prefixes each line with
// an RFC3339 timestamp and stream marker ([STDOUT] or [STDERR]).
//
// The implementation is thread-safe and supports concurrent writes from multiple streams
// (stdout and stderr) for the same component. It automatically rotates log files when
// they exceed the configured size threshold.
type DefaultLogWriter struct {
	logDir  string
	rotator LogRotator

	// mu protects the writers map
	mu sync.Mutex

	// writers tracks all open writers per component for cleanup
	// key: componentName, value: slice of open writers
	writers map[string][]*bufferedPrefixWriter
}

// NewDefaultLogWriter creates a new DefaultLogWriter that writes logs to the specified directory.
// The directory will be created with 0755 permissions if it doesn't exist.
// If rotator is nil, a DefaultLogRotator with default settings will be created.
func NewDefaultLogWriter(logDir string, rotator LogRotator) (*DefaultLogWriter, error) {
	// Create the log directory if it doesn't exist
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory %s: %w", logDir, err)
	}

	// Use default rotator if none provided
	if rotator == nil {
		rotator = NewDefaultLogRotator(0, 0) // Use default values
	}

	return &DefaultLogWriter{
		logDir:  logDir,
		rotator: rotator,
		writers: make(map[string][]*bufferedPrefixWriter),
	}, nil
}

// CreateWriter creates a new writer for the specified component and stream.
// The writer appends to <logDir>/<componentName>.log and prefixes each line with
// a timestamp and stream marker.
func (w *DefaultLogWriter) CreateWriter(componentName string, stream string) (io.WriteCloser, error) {
	logPath := filepath.Join(w.logDir, fmt.Sprintf("%s.log", componentName))

	// Open the log file in append mode, creating it if it doesn't exist
	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file %s: %w", logPath, err)
	}

	// Create a buffered writer with stream prefix and rotation support
	writer := &bufferedPrefixWriter{
		file:      file,
		buf:       bufio.NewWriterSize(file, defaultBufferSize),
		stream:    stream,
		logPath:   logPath,
		rotator:   w.rotator,
		logWriter: w,
	}

	// Track the writer for cleanup
	w.mu.Lock()
	w.writers[componentName] = append(w.writers[componentName], writer)
	w.mu.Unlock()

	return writer, nil
}

// Close closes all writers for the specified component and flushes any buffered data.
// It's safe to call Close multiple times or for components that don't have writers.
func (w *DefaultLogWriter) Close(componentName string) error {
	w.mu.Lock()
	writers := w.writers[componentName]
	delete(w.writers, componentName)
	w.mu.Unlock()

	var firstErr error
	for _, writer := range writers {
		if err := writer.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	return firstErr
}

const (
	// rotationCheckInterval defines how often to check if rotation is needed.
	// We check every 1MB of data written to avoid checking on every write.
	rotationCheckInterval = 1024 * 1024 // 1MB
)

// bufferedPrefixWriter wraps a file with a buffered writer and prefixes each line
// with an RFC3339 timestamp and stream marker ([STDOUT] or [STDERR]).
// It supports automatic log rotation when the file exceeds size thresholds.
type bufferedPrefixWriter struct {
	file      *os.File
	buf       *bufio.Writer
	stream    string
	logPath   string            // Path to the log file for rotation
	rotator   LogRotator        // Rotator for handling log rotation
	logWriter *DefaultLogWriter // Reference to parent for coordination

	// mu protects the writer for concurrent access
	mu sync.Mutex

	// lineStart tracks whether we're at the start of a line (need prefix)
	lineStart bool

	// bytesWritten tracks bytes written since last rotation check
	bytesWritten int64
}

// Write implements io.Writer by writing data with timestamp prefixes on each line.
// This method is thread-safe and can be called concurrently.
// It periodically checks if log rotation is needed based on file size.
func (w *bufferedPrefixWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if len(p) == 0 {
		return 0, nil
	}

	// Check if rotation is needed (every rotationCheckInterval bytes)
	if w.bytesWritten >= rotationCheckInterval {
		if err := w.checkAndRotate(); err != nil {
			// Log warning but continue writing to current file
			// We don't want to lose data due to rotation failures
			fmt.Fprintf(os.Stderr, "warning: log rotation check failed for %s: %v\n", w.logPath, err)
		}
		// Reset counter regardless of rotation result
		w.bytesWritten = 0
	}

	written := 0
	for len(p) > 0 {
		// Write prefix at the start of a new line
		if !w.lineStart {
			prefix := w.formatPrefix()
			if _, err := w.buf.WriteString(prefix); err != nil {
				return written, err
			}
			w.lineStart = true
		}

		// Find the next newline
		i := 0
		for i < len(p) && p[i] != '\n' {
			i++
		}

		// Write up to and including the newline (if found)
		chunk := p[:i]
		if i < len(p) {
			// Include the newline
			chunk = p[:i+1]
			w.lineStart = false // Next write needs a prefix
		}

		if _, err := w.buf.Write(chunk); err != nil {
			return written, err
		}

		written += len(chunk)
		p = p[len(chunk):]
	}

	// Track bytes written for rotation checking
	w.bytesWritten += int64(written)

	return written, nil
}

// checkAndRotate checks if rotation is needed and performs it if necessary.
// Must be called with w.mu held.
func (w *bufferedPrefixWriter) checkAndRotate() error {
	// Check if rotation is needed
	shouldRotate, err := w.rotator.ShouldRotate(w.logPath)
	if err != nil {
		return fmt.Errorf("rotation check failed: %w", err)
	}

	if !shouldRotate {
		return nil
	}

	// Flush the buffer before rotation
	if err := w.buf.Flush(); err != nil {
		return fmt.Errorf("failed to flush buffer before rotation: %w", err)
	}

	// Close the current file
	if err := w.file.Close(); err != nil {
		return fmt.Errorf("failed to close file before rotation: %w", err)
	}

	// Perform rotation - this returns a new file handle
	newFile, err := w.rotator.Rotate(w.logPath)
	if err != nil {
		// Rotation failed - try to reopen the original file to continue writing
		// This prevents data loss if rotation fails
		reopened, reopenErr := os.OpenFile(w.logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if reopenErr != nil {
			return fmt.Errorf("rotation failed and could not reopen file: rotate error: %w, reopen error: %v", err, reopenErr)
		}
		w.file = reopened
		w.buf = bufio.NewWriterSize(reopened, defaultBufferSize)
		return fmt.Errorf("rotation failed, reopened original file: %w", err)
	}

	// Update the writer to use the new file
	w.file = newFile
	w.buf = bufio.NewWriterSize(newFile, defaultBufferSize)

	return nil
}

// Close flushes the buffer and closes the underlying file.
func (w *bufferedPrefixWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Flush any remaining buffered data
	if err := w.buf.Flush(); err != nil {
		// Still try to close the file
		w.file.Close()
		return fmt.Errorf("failed to flush buffer: %w", err)
	}

	if err := w.file.Close(); err != nil {
		return fmt.Errorf("failed to close file: %w", err)
	}

	return nil
}

// formatPrefix creates the line prefix with timestamp and stream marker.
// Format: "2025-01-01T12:00:00-06:00 [STDOUT] "
func (w *bufferedPrefixWriter) formatPrefix() string {
	timestamp := time.Now().Format(time.RFC3339)
	streamMarker := "[STDOUT]"
	if w.stream == "stderr" {
		streamMarker = "[STDERR]"
	}
	return fmt.Sprintf("%s %s ", timestamp, streamMarker)
}
