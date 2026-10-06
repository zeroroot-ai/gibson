// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
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

	// mu protects the writers map
	mu sync.Mutex
}

// bufferedPrefixWriter wraps a file with a buffered writer and prefixes each line
// with an RFC3339 timestamp and stream marker ([STDOUT] or [STDERR]).
// It supports automatic log rotation when the file exceeds size thresholds.
type bufferedPrefixWriter struct {

	// mu protects the writer for concurrent access
	mu sync.Mutex
}
