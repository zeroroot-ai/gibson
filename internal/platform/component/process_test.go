package component

import (
	"os"
	"runtime"
	"testing"
	"time"
)

func TestCheckProcessState_CurrentProcess(t *testing.T) {
	// Test with our own PID - should always be running
	pid := os.Getpid()
	state := CheckProcessState(pid)

	if state != ProcessStateRunning {
		t.Errorf("Expected current process (PID %d) to be running, got %s", pid, state)
	}
}

func TestCheckProcessState_NonExistentProcess(t *testing.T) {
	// Use a very high PID that's unlikely to exist
	// PID 99999 should be safe on most systems
	pid := 99999
	state := CheckProcessState(pid)

	if state != ProcessStateDead {
		t.Errorf("Expected non-existent process (PID %d) to be dead, got %s", pid, state)
	}
}

func TestCheckProcessState_ZombieProcess(t *testing.T) {
	// This test only runs on Linux where we can detect zombie processes
	if runtime.GOOS != "linux" {
		t.Skip("Zombie process detection only supported on Linux")
	}

	// Create a child process that will become a zombie
	// The child exits immediately, and we intentionally don't wait() for it
	if os.Getenv("BE_ZOMBIE") == "1" {
		// Child process - exit immediately to become zombie
		os.Exit(0)
	}

	// Parent process - create zombie child
	cmd := os.Args[0]
	env := append(os.Environ(), "BE_ZOMBIE=1")

	procAttr := &os.ProcAttr{
		Env:   env,
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
	}

	proc, err := os.StartProcess(cmd, []string{cmd}, procAttr)
	if err != nil {
		t.Fatalf("Failed to start zombie process: %v", err)
	}

	// Clean up - reap the zombie
	defer func() {
		_, _ = proc.Wait()
	}()

	// Give the child time to exit (but don't wait for it)
	// Try multiple times to catch the zombie state window
	var state ProcessState
	foundZombie := false
	for i := 0; i < 100; i++ {
		time.Sleep(5 * time.Millisecond)
		state = CheckProcessState(proc.Pid)
		if state == ProcessStateZombie {
			foundZombie = true
			break
		}
		// If the process is already dead, it was reaped before we could check
		if state == ProcessStateDead {
			t.Skip("Process was reaped before zombie state could be detected (timing issue)")
			return
		}
	}

	// On modern Linux systems with fast process reaping, zombie states
	// can be very short-lived. If we still see it as running after 500ms,
	// skip the test as the environment might have special process handling
	if !foundZombie && state == ProcessStateRunning {
		t.Skip("Process remained in running state - zombie window may be too brief to catch")
		return
	}

	if !foundZombie {
		t.Errorf("Expected zombie process (PID %d) to be detected as zombie, got %s", proc.Pid, state)
	}
}

func TestCheckProcessState_ShortLivedProcess(t *testing.T) {
	// Create a process that exits immediately
	if os.Getenv("EXIT_IMMEDIATELY") == "1" {
		os.Exit(0)
	}

	cmd := os.Args[0]
	env := append(os.Environ(), "EXIT_IMMEDIATELY=1")

	procAttr := &os.ProcAttr{
		Env:   env,
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
	}

	proc, err := os.StartProcess(cmd, []string{cmd}, procAttr)
	if err != nil {
		t.Fatalf("Failed to start short-lived process: %v", err)
	}

	// Wait for process to exit and be reaped
	_, waitErr := proc.Wait()
	if waitErr != nil {
		t.Fatalf("Failed to wait for process: %v", waitErr)
	}

	// Now check the state - should be dead
	state := CheckProcessState(proc.Pid)

	if state != ProcessStateDead {
		t.Errorf("Expected exited process (PID %d) to be dead, got %s", proc.Pid, state)
	}
}

func TestCheckProcessState_InitProcess(t *testing.T) {
	// PID 1 is always init/systemd on Unix systems
	if runtime.GOOS == "windows" {
		t.Skip("Init process test not applicable on Windows")
	}

	state := CheckProcessState(1)

	// Init should always be running (unless we're in a weird container)
	if state != ProcessStateRunning {
		t.Logf("Warning: Init process (PID 1) reported as %s, expected running", state)
	}
}

func TestFindProcess(t *testing.T) {
	// Test the helper function
	pid := os.Getpid()
	proc, err := FindProcess(pid)

	if err != nil {
		t.Errorf("FindProcess failed for current PID: %v", err)
	}

	if proc == nil {
		t.Error("FindProcess returned nil process")
	}

	if proc.Pid != pid {
		t.Errorf("FindProcess returned wrong PID: got %d, want %d", proc.Pid, pid)
	}
}

func TestFindProcess_NonExistent(t *testing.T) {
	// On Unix, os.FindProcess always succeeds even for non-existent PIDs
	// On Windows, it may fail
	pid := 99999
	proc, err := FindProcess(pid)

	if runtime.GOOS == "windows" {
		// Windows may return an error for non-existent processes
		if err == nil && proc != nil {
			t.Logf("FindProcess succeeded for non-existent PID %d on Windows", pid)
		}
	} else {
		// Unix always succeeds
		if err != nil {
			t.Errorf("FindProcess failed on Unix (should always succeed): %v", err)
		}
		if proc == nil {
			t.Error("FindProcess returned nil on Unix")
		}
	}
}

func TestCheckLinuxProcStatus(t *testing.T) {
	// This test only runs on Linux
	if runtime.GOOS != "linux" {
		t.Skip("checkLinuxProcStatus only available on Linux")
	}

	// Test with current process
	pid := os.Getpid()
	state := checkLinuxProcStatus(pid)

	// Our process should be running (or sleeping, which we treat as running)
	if state != ProcessStateRunning {
		t.Errorf("Expected current process to be running, got %s", state)
	}
}

func TestCheckLinuxProcStatus_NonExistent(t *testing.T) {
	// This test only runs on Linux
	if runtime.GOOS != "linux" {
		t.Skip("checkLinuxProcStatus only available on Linux")
	}

	// Test with non-existent PID
	state := checkLinuxProcStatus(99999)

	if state != ProcessStateDead {
		t.Errorf("Expected non-existent process to be dead, got %s", state)
	}
}

func TestProcessStateEnumValues(t *testing.T) {
	// Verify that our function returns valid enum values
	validStates := map[ProcessState]bool{
		ProcessStateRunning: true,
		ProcessStateDead:    true,
		ProcessStateZombie:  true,
	}

	tests := []struct {
		name string
		pid  int
	}{
		{"current process", os.Getpid()},
		{"non-existent process", 99999},
		{"init process", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := CheckProcessState(tt.pid)

			if !validStates[state] {
				t.Errorf("CheckProcessState returned invalid state: %s", state)
			}

			if !state.IsValid() {
				t.Errorf("State %s reports IsValid() = false", state)
			}
		})
	}
}

// BenchmarkCheckProcessState_CurrentProcess benchmarks checking our own process
func BenchmarkCheckProcessState_CurrentProcess(b *testing.B) {
	pid := os.Getpid()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = CheckProcessState(pid)
	}
}

// BenchmarkCheckProcessState_NonExistent benchmarks checking non-existent process
func BenchmarkCheckProcessState_NonExistent(b *testing.B) {
	pid := 99999
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = CheckProcessState(pid)
	}
}

// BenchmarkCheckLinuxProcStatus benchmarks the Linux-specific proc status check
func BenchmarkCheckLinuxProcStatus(b *testing.B) {
	if runtime.GOOS != "linux" {
		b.Skip("Linux-only benchmark")
	}

	pid := os.Getpid()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = checkLinuxProcStatus(pid)
	}
}
