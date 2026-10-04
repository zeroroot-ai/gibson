// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"os"
	"sync"
)

const (
	// DefaultLogMaxSize is the default maximum log file size before rotation (10MB).
	DefaultLogMaxSize = 10 * 1024 * 1024 // 10MB

	// DefaultLogMaxBackups is the default maximum number of old log files to retain.
	DefaultLogMaxBackups = 5

	// DefaultLogDirPerms is the default permission for log directories.
	DefaultLogDirPerms = 0755

	// DefaultLogFilePerms is the default permission for log files.
	DefaultLogFilePerms = 0644
)

// LogRotator defines the interface for log rotation strategies.
// Implementations handle when and how to rotate log files to prevent disk exhaustion.
type LogRotator interface {
	// ShouldRotate checks if the log file needs rotation based on size.
	// Returns true if rotation is needed, false otherwise.
	// Returns an error if the file cannot be accessed.
	ShouldRotate(path string) (bool, error)

	// Rotate performs log rotation, returning the new file handle.
	// The rotation process:
	//   1. Deletes the oldest backup (.log.N where N = maxBackups)
	//   2. Shifts existing backups up (.log.1 → .log.2, .log.2 → .log.3, etc.)
	//   3. Renames current .log to .log.1
	//   4. Creates and returns new empty .log file
	//
	// Returns the new file handle on success, or an error if rotation fails.
	Rotate(path string) (*os.File, error)
}

// DefaultLogRotator implements size-based log rotation with backup retention.
// It is safe for concurrent use by multiple goroutines.
type DefaultLogRotator struct {
	mu         sync.Mutex // Protects rotation operations
	maxSize    int64      // Maximum file size before rotation
	maxBackups int        // Maximum number of backup files to keep
}

// File doesn't exist, no rotation needed

// Delete the oldest backup if it exists

// Shift all existing backups up by one (.log.N-1 → .log.N)
// Start from the highest number and work backwards to avoid conflicts

// Check if the source file exists before attempting rename

// This backup doesn't exist, skip it

// Rename the backup file

// Rename current log to .log.1 (if it exists)

// Current log exists, rename it

// Some other error occurred

// If current log doesn't exist, that's fine - we'll create a new one

// Create new empty log file with appropriate permissions
