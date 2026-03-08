package daemon

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// WritePIDFile writes the process ID to the specified file with secure permissions.
//
// The file is created with 0600 permissions (owner read/write only) for security.
// Parent directories are created if they don't exist.
//
// Parameters:
//   - pidFile: Path to the PID file to write
//   - pid: Process ID to write
//
// Returns:
//   - error: Non-nil if file creation or writing fails
func WritePIDFile(pidFile string, pid int) error {
	// Create parent directories if they don't exist
	dir := filepath.Dir(pidFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Write PID to file with secure permissions
	content := fmt.Sprintf("%d\n", pid)
	if err := os.WriteFile(pidFile, []byte(content), 0600); err != nil {
		return fmt.Errorf("failed to write PID file: %w", err)
	}

	return nil
}

// ReadPIDFile reads the process ID from the specified file.
//
// Returns 0 and nil error if the file doesn't exist (not considered an error).
// Returns error if the file exists but contains invalid content.
//
// Parameters:
//   - pidFile: Path to the PID file to read
//
// Returns:
//   - int: Process ID from the file, or 0 if file doesn't exist
//   - error: Non-nil if file exists but cannot be read or parsed
func ReadPIDFile(pidFile string) (int, error) {
	content, err := os.ReadFile(pidFile)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("failed to read PID file: %w", err)
	}

	// Parse PID from content
	pidStr := strings.TrimSpace(string(content))
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return 0, fmt.Errorf("invalid PID in file: %w", err)
	}

	if pid <= 0 {
		return 0, fmt.Errorf("invalid PID value: %d", pid)
	}

	return pid, nil
}

// RemovePIDFile removes the PID file.
//
// Returns nil if the file doesn't exist (idempotent operation).
//
// Parameters:
//   - pidFile: Path to the PID file to remove
//
// Returns:
//   - error: Non-nil if removal fails for reasons other than file not existing
func RemovePIDFile(pidFile string) error {
	err := os.Remove(pidFile)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove PID file: %w", err)
	}
	return nil
}

// CheckPIDFile checks if a daemon is running based on the PID file.
//
// This function reads the PID from the file and checks if a process with that
// PID exists by sending signal 0 (no-op signal that only checks existence).
//
// Returns (false, 0, nil) if the file doesn't exist.
// Returns (true, pid, nil) if the process exists.
// Returns (false, pid, nil) if the process doesn't exist (stale PID file).
//
// Parameters:
//   - pidFile: Path to the PID file to check
//
// Returns:
//   - running: True if the process is currently running
//   - pid: Process ID from the file (0 if file doesn't exist)
//   - error: Non-nil if file reading fails (not for missing file or stale PID)
func CheckPIDFile(pidFile string) (running bool, pid int, err error) {
	pid, err = ReadPIDFile(pidFile)
	if err != nil {
		return false, 0, err
	}

	if pid == 0 {
		// File doesn't exist
		return false, 0, nil
	}

	// Check if process exists by sending signal 0
	process, err := os.FindProcess(pid)
	if err != nil {
		// On Unix, FindProcess always succeeds, so this shouldn't happen
		return false, pid, nil
	}

	// Send signal 0 to check if process exists
	err = process.Signal(syscall.Signal(0))
	if err == nil {
		// Process exists and we can signal it
		return true, pid, nil
	}

	// Check if error is EPERM (process exists but we can't signal it)
	if err == syscall.EPERM {
		// Process exists but we don't have permission to signal it
		return true, pid, nil
	}

	// Process doesn't exist (ESRCH) or other error
	return false, pid, nil
}

// WriteDaemonInfo writes daemon connection information to a JSON file.
//
// The file is created with 0600 permissions (owner read/write only) for security.
// Parent directories are created if they don't exist.
//
// Parameters:
//   - infoFile: Path to the daemon info file to write
//   - info: Daemon information to write
//
// Returns:
//   - error: Non-nil if info is nil or file writing fails
func WriteDaemonInfo(infoFile string, info *DaemonInfo) error {
	if info == nil {
		return fmt.Errorf("daemon info cannot be nil")
	}

	// Create parent directories if they don't exist
	dir := filepath.Dir(infoFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Serialize to JSON
	content, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal daemon info: %w", err)
	}

	// Write to file with secure permissions
	if err := os.WriteFile(infoFile, content, 0600); err != nil {
		return fmt.Errorf("failed to write daemon info file: %w", err)
	}

	return nil
}

// RemoveDaemonInfo removes the daemon info file.
//
// Returns nil if the file doesn't exist (idempotent operation).
//
// Parameters:
//   - infoFile: Path to the daemon info file to remove
//
// Returns:
//   - error: Non-nil if removal fails for reasons other than file not existing
func RemoveDaemonInfo(infoFile string) error {
	err := os.Remove(infoFile)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove daemon info file: %w", err)
	}
	return nil
}
