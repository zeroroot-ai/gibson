package component

import (
	"fmt"
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

// NewDefaultLogRotator creates a new DefaultLogRotator with the specified configuration.
// If maxSize is <= 0, DefaultLogMaxSize is used.
// If maxBackups is <= 0, DefaultLogMaxBackups is used.
func NewDefaultLogRotator(maxSize int64, maxBackups int) *DefaultLogRotator {
	if maxSize <= 0 {
		maxSize = DefaultLogMaxSize
	}
	if maxBackups <= 0 {
		maxBackups = DefaultLogMaxBackups
	}

	return &DefaultLogRotator{
		maxSize:    maxSize,
		maxBackups: maxBackups,
	}
}

// ShouldRotate checks if the log file at path exceeds maxSize.
// Returns false if the file doesn't exist or is smaller than maxSize.
// Returns an error only if stat fails for reasons other than file not existing.
func (r *DefaultLogRotator) ShouldRotate(path string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist, no rotation needed
			return false, nil
		}
		return false, fmt.Errorf("failed to stat log file %s: %w", path, err)
	}

	return info.Size() >= r.maxSize, nil
}

// Rotate performs the log rotation process atomically where possible.
// The rotation is thread-safe and handles missing intermediate backup files gracefully.
func (r *DefaultLogRotator) Rotate(path string) (*os.File, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Delete the oldest backup if it exists
	oldestBackup := fmt.Sprintf("%s.%d", path, r.maxBackups)
	if err := os.Remove(oldestBackup); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to remove oldest backup %s: %w", oldestBackup, err)
	}

	// Shift all existing backups up by one (.log.N-1 → .log.N)
	// Start from the highest number and work backwards to avoid conflicts
	for i := r.maxBackups - 1; i >= 1; i-- {
		oldPath := fmt.Sprintf("%s.%d", path, i)
		newPath := fmt.Sprintf("%s.%d", path, i+1)

		// Check if the source file exists before attempting rename
		if _, err := os.Stat(oldPath); err != nil {
			if os.IsNotExist(err) {
				// This backup doesn't exist, skip it
				continue
			}
			return nil, fmt.Errorf("failed to stat backup %s: %w", oldPath, err)
		}

		// Rename the backup file
		if err := os.Rename(oldPath, newPath); err != nil {
			return nil, fmt.Errorf("failed to rotate backup %s to %s: %w", oldPath, newPath, err)
		}
	}

	// Rename current log to .log.1 (if it exists)
	firstBackup := fmt.Sprintf("%s.1", path)
	if _, err := os.Stat(path); err == nil {
		// Current log exists, rename it
		if err := os.Rename(path, firstBackup); err != nil {
			return nil, fmt.Errorf("failed to rotate current log %s to %s: %w", path, firstBackup, err)
		}
	} else if !os.IsNotExist(err) {
		// Some other error occurred
		return nil, fmt.Errorf("failed to stat current log %s: %w", path, err)
	}
	// If current log doesn't exist, that's fine - we'll create a new one

	// Create new empty log file with appropriate permissions
	newFile, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, DefaultLogFilePerms)
	if err != nil {
		return nil, fmt.Errorf("failed to create new log file %s: %w", path, err)
	}

	return newFile, nil
}

// MaxSize returns the configured maximum file size before rotation.
func (r *DefaultLogRotator) MaxSize() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.maxSize
}

// MaxBackups returns the configured maximum number of backup files.
func (r *DefaultLogRotator) MaxBackups() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.maxBackups
}
