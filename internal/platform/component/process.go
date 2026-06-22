package component

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
)

// CheckProcessState checks the state of a process by its PID.
// It returns ProcessStateRunning if the process is alive and responding,
// ProcessStateZombie if the process exists but is a zombie (Linux only),
// or ProcessStateDead if the process doesn't exist or can't be signaled.
//
// On Linux, this function checks /proc/[pid]/status to detect zombie processes.
// On other platforms (macOS, Windows, etc.), zombie detection is not supported
// and only alive/dead state is returned.
//
// The function uses signal 0 (null signal) to check process existence without
// actually sending a signal that would affect the process.
func CheckProcessState(pid int) ProcessState {
	// First, check if the process exists using signal 0
	// Signal 0 is a special case that doesn't actually send a signal,
	// but performs error checking to verify the process exists and we have permission
	err := syscall.Kill(pid, 0)

	if err != nil {
		// If we get an error, the process is likely dead
		// ESRCH means "no such process"
		// EPERM means we don't have permission (but process exists)
		if err == syscall.ESRCH {
			return ProcessStateDead
		}
		// If we get EPERM, the process exists but we can't signal it
		// Treat this as running since we know it exists
		if err == syscall.EPERM {
			// Still try to check for zombie state on Linux
			if runtime.GOOS == "linux" {
				return checkLinuxProcStatus(pid)
			}
			return ProcessStateRunning
		}
		// Any other error, assume dead
		return ProcessStateDead
	}

	// Process exists and we can signal it
	// On Linux, check if it's a zombie
	if runtime.GOOS == "linux" {
		return checkLinuxProcStatus(pid)
	}

	// On non-Linux platforms, we can only determine running vs dead
	return ProcessStateRunning
}

// checkLinuxProcStatus checks the /proc/[pid]/status file to determine
// if a process is in zombie state. This is Linux-specific.
//
// The function reads the "State:" field from /proc/[pid]/status.
// State values include:
//   - R (running)
//   - S (sleeping)
//   - D (disk sleep)
//   - Z (zombie)
//   - T (stopped)
//   - t (tracing stop)
//   - W (paging)
//   - X (dead)
//   - x (dead)
//   - K (wakekill)
//   - P (parked)
//
// Returns ProcessStateZombie if state is "Z", ProcessStateRunning otherwise.
// If the file can't be read (process died between signal check and file read),
// returns ProcessStateDead.
func checkLinuxProcStatus(pid int) ProcessState {
	// Open /proc/[pid]/status file
	statusPath := fmt.Sprintf("/proc/%d/status", pid)
	file, err := os.Open(statusPath)
	if err != nil {
		// If we can't open the file, the process likely died
		// between our signal check and this file read
		return ProcessStateDead
	}
	defer file.Close()

	// Scan the file line by line looking for "State:" field
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// Look for the State: line
		// Example: "State:	S (sleeping)"
		if strings.HasPrefix(line, "State:") {
			// Extract the state character (first char after "State:\t")
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				state := fields[1]

				// Check if it's a zombie process
				if state == "Z" {
					return ProcessStateZombie
				}

				// Check if it's dead/defunct
				if state == "X" || state == "x" {
					return ProcessStateDead
				}

				// Any other state means the process is running
				// (R, S, D, T, t, W, K, P)
				return ProcessStateRunning
			}
		}
	}

	// If we couldn't find the State field, or scanner errored,
	// assume the process is running since we successfully opened the file
	if err := scanner.Err(); err != nil {
		return ProcessStateDead
	}

	return ProcessStateRunning
}

// FindProcess is a helper function that wraps os.FindProcess.
// It's provided for convenience and testing purposes.
//
// Note: os.FindProcess on Unix systems always succeeds even if the process
// doesn't exist. To actually verify existence, use CheckProcessState instead.
func FindProcess(pid int) (*os.Process, error) {
	return os.FindProcess(pid)
}
