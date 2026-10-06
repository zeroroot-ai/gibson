// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"os"
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
