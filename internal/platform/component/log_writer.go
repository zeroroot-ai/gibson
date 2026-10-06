// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"bufio"

	"os"

	"sync"
)

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
