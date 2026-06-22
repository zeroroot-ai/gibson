package component

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDefaultLogRotator(t *testing.T) {
	rotator := NewDefaultLogRotator(0, 0)
	require.NotNil(t, rotator)

	// Should use defaults when values are <= 0
	assert.Equal(t, int64(DefaultLogMaxSize), rotator.MaxSize())
	assert.Equal(t, DefaultLogMaxBackups, rotator.MaxBackups())
}

func TestNewDefaultLogRotator_CustomValues(t *testing.T) {
	maxSize := int64(1024 * 1024) // 1MB
	maxBackups := 3

	rotator := NewDefaultLogRotator(maxSize, maxBackups)
	require.NotNil(t, rotator)

	assert.Equal(t, maxSize, rotator.MaxSize())
	assert.Equal(t, maxBackups, rotator.MaxBackups())
}

func TestShouldRotate_UnderThreshold(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	// Create a 500 byte file
	require.NoError(t, os.WriteFile(logFile, make([]byte, 500), 0644))

	rotator := NewDefaultLogRotator(1024, 5) // 1KB threshold
	shouldRotate, err := rotator.ShouldRotate(logFile)
	require.NoError(t, err)
	assert.False(t, shouldRotate, "file under threshold should not rotate")
}

func TestShouldRotate_OverThreshold(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	// Create a 2048 byte file
	require.NoError(t, os.WriteFile(logFile, make([]byte, 2048), 0644))

	rotator := NewDefaultLogRotator(1024, 5) // 1KB threshold
	shouldRotate, err := rotator.ShouldRotate(logFile)
	require.NoError(t, err)
	assert.True(t, shouldRotate, "file over threshold should rotate")
}

func TestShouldRotate_ExactThreshold(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	// Create a file exactly at threshold (1024 bytes)
	require.NoError(t, os.WriteFile(logFile, make([]byte, 1024), 0644))

	rotator := NewDefaultLogRotator(1024, 5) // 1KB threshold
	shouldRotate, err := rotator.ShouldRotate(logFile)
	require.NoError(t, err)
	assert.True(t, shouldRotate, "file at exact threshold should rotate (>= check)")
}

func TestShouldRotate_NonexistentFile(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "nonexistent.log")

	rotator := NewDefaultLogRotator(1024, 5)
	shouldRotate, err := rotator.ShouldRotate(logFile)
	require.NoError(t, err)
	assert.False(t, shouldRotate, "nonexistent file should not rotate")
}

func TestRotate_ShiftsFiles(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	// Create initial log file and two backups
	require.NoError(t, os.WriteFile(logFile, []byte("current log"), 0644))
	require.NoError(t, os.WriteFile(logFile+".1", []byte("backup 1"), 0644))
	require.NoError(t, os.WriteFile(logFile+".2", []byte("backup 2"), 0644))

	rotator := NewDefaultLogRotator(1024, 5)
	newFile, err := rotator.Rotate(logFile)
	require.NoError(t, err)
	require.NotNil(t, newFile)
	defer newFile.Close()

	// Verify current log was rotated to .1
	content, err := os.ReadFile(logFile + ".1")
	require.NoError(t, err)
	assert.Equal(t, "current log", string(content))

	// Verify .1 was shifted to .2
	content, err = os.ReadFile(logFile + ".2")
	require.NoError(t, err)
	assert.Equal(t, "backup 1", string(content))

	// Verify .2 was shifted to .3
	content, err = os.ReadFile(logFile + ".3")
	require.NoError(t, err)
	assert.Equal(t, "backup 2", string(content))

	// Verify new log file is empty
	info, err := os.Stat(logFile)
	require.NoError(t, err)
	assert.Equal(t, int64(0), info.Size())

	// Verify new log file has correct permissions
	assert.Equal(t, os.FileMode(DefaultLogFilePerms), info.Mode().Perm())
}

func TestRotate_DeletesOldest(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	// Create log file with maximum number of backups (5)
	require.NoError(t, os.WriteFile(logFile, []byte("current"), 0644))
	for i := 1; i <= 5; i++ {
		require.NoError(t, os.WriteFile(fmt.Sprintf("%s.%d", logFile, i), []byte(fmt.Sprintf("backup %d", i)), 0644))
	}

	rotator := NewDefaultLogRotator(1024, 5)
	newFile, err := rotator.Rotate(logFile)
	require.NoError(t, err)
	require.NotNil(t, newFile)
	defer newFile.Close()

	// Verify .5 was deleted (it was the oldest before rotation)
	// After rotation: current→.1, .1→.2, .2→.3, .3→.4, .4→.5, .5 deleted
	_, err = os.Stat(logFile + ".5")
	require.NoError(t, err, ".5 should exist (old .4)")

	// The original .5 should not exist in position .6
	_, err = os.Stat(logFile + ".6")
	require.True(t, os.IsNotExist(err), ".6 should not exist")

	// Verify the content shifted correctly
	content, err := os.ReadFile(logFile + ".5")
	require.NoError(t, err)
	assert.Equal(t, "backup 4", string(content), "old .4 should be in .5")

	content, err = os.ReadFile(logFile + ".1")
	require.NoError(t, err)
	assert.Equal(t, "current", string(content), "current log should be in .1")
}

func TestRotate_HandlesNewFile(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	// Don't create any log file - this is a fresh rotation
	rotator := NewDefaultLogRotator(1024, 5)
	newFile, err := rotator.Rotate(logFile)
	require.NoError(t, err)
	require.NotNil(t, newFile)
	defer newFile.Close()

	// Verify new log file was created
	info, err := os.Stat(logFile)
	require.NoError(t, err)
	assert.Equal(t, int64(0), info.Size())

	// Verify no .1 file was created (nothing to rotate)
	_, err = os.Stat(logFile + ".1")
	require.True(t, os.IsNotExist(err), ".1 should not exist when rotating non-existent log")
}

func TestRotate_HandlesMissingIntermediates(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	// Create current log and backups with gaps (.1 and .3 exist, but .2 is missing)
	require.NoError(t, os.WriteFile(logFile, []byte("current"), 0644))
	require.NoError(t, os.WriteFile(logFile+".1", []byte("backup 1"), 0644))
	// .2 is intentionally missing
	require.NoError(t, os.WriteFile(logFile+".3", []byte("backup 3"), 0644))

	rotator := NewDefaultLogRotator(1024, 5)
	newFile, err := rotator.Rotate(logFile)
	require.NoError(t, err)
	require.NotNil(t, newFile)
	defer newFile.Close()

	// Verify rotation succeeded despite missing .2
	content, err := os.ReadFile(logFile + ".1")
	require.NoError(t, err)
	assert.Equal(t, "current", string(content))

	// .1 should have been shifted to .2
	content, err = os.ReadFile(logFile + ".2")
	require.NoError(t, err)
	assert.Equal(t, "backup 1", string(content))

	// .3 should have been shifted to .4
	content, err = os.ReadFile(logFile + ".4")
	require.NoError(t, err)
	assert.Equal(t, "backup 3", string(content))

	// .3 should not exist anymore (it was shifted to .4)
	_, err = os.Stat(logFile + ".3")
	require.True(t, os.IsNotExist(err), ".3 should not exist after rotation")

	// New log file should be empty
	info, err := os.Stat(logFile)
	require.NoError(t, err)
	assert.Equal(t, int64(0), info.Size())
}

func TestRotate_ConcurrentAccess(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	// Create initial log file
	require.NoError(t, os.WriteFile(logFile, []byte("initial"), 0644))

	rotator := NewDefaultLogRotator(1024, 5)

	// Test that concurrent calls to Rotate are properly serialized
	// The mutex should prevent race conditions
	done := make(chan bool, 2)

	go func() {
		file, err := rotator.Rotate(logFile)
		assert.NoError(t, err)
		if file != nil {
			file.Close()
		}
		done <- true
	}()

	go func() {
		file, err := rotator.Rotate(logFile)
		assert.NoError(t, err)
		if file != nil {
			file.Close()
		}
		done <- true
	}()

	// Wait for both goroutines
	<-done
	<-done

	// Verify log file exists and is valid
	_, err := os.Stat(logFile)
	require.NoError(t, err)
}

func TestRotate_ConcurrentShouldRotate(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	// Create a file over the threshold
	require.NoError(t, os.WriteFile(logFile, make([]byte, 2048), 0644))

	rotator := NewDefaultLogRotator(1024, 5)

	// Test concurrent ShouldRotate calls
	done := make(chan bool, 5)

	for i := 0; i < 5; i++ {
		go func() {
			shouldRotate, err := rotator.ShouldRotate(logFile)
			assert.NoError(t, err)
			assert.True(t, shouldRotate)
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 5; i++ {
		<-done
	}
}

func TestRotate_PreservesFilePermissions(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	// Create log file with custom permissions
	require.NoError(t, os.WriteFile(logFile, []byte("test"), 0600))

	rotator := NewDefaultLogRotator(1024, 5)
	newFile, err := rotator.Rotate(logFile)
	require.NoError(t, err)
	require.NotNil(t, newFile)
	defer newFile.Close()

	// New file should have DefaultLogFilePerms (0644), not the old file's permissions
	info, err := os.Stat(logFile)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(DefaultLogFilePerms), info.Mode().Perm())

	// Backup should preserve original permissions
	info, err = os.Stat(logFile + ".1")
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestRotate_LargeBackupChain(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	maxBackups := 10
	rotator := NewDefaultLogRotator(1024, maxBackups)

	// Create initial log file
	require.NoError(t, os.WriteFile(logFile, []byte("initial"), 0644))

	// Rotate 15 times (more than maxBackups)
	for i := 0; i < 15; i++ {
		// Write something to the current log
		require.NoError(t, os.WriteFile(logFile, []byte(fmt.Sprintf("rotation %d", i)), 0644))

		newFile, err := rotator.Rotate(logFile)
		require.NoError(t, err)
		require.NotNil(t, newFile)
		newFile.Close()
	}

	// Verify we only have maxBackups backup files
	for i := 1; i <= maxBackups; i++ {
		_, err := os.Stat(fmt.Sprintf("%s.%d", logFile, i))
		require.NoError(t, err, "backup .%d should exist", i)
	}

	// Verify no backups beyond maxBackups
	_, err := os.Stat(fmt.Sprintf("%s.%d", logFile, maxBackups+1))
	require.True(t, os.IsNotExist(err), "backup .%d should not exist", maxBackups+1)
}

func TestRotate_EmptyCurrentLog(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	// Create an empty log file
	require.NoError(t, os.WriteFile(logFile, []byte(""), 0644))

	rotator := NewDefaultLogRotator(1024, 5)
	newFile, err := rotator.Rotate(logFile)
	require.NoError(t, err)
	require.NotNil(t, newFile)
	defer newFile.Close()

	// Empty file should still be rotated to .1
	_, err = os.Stat(logFile + ".1")
	require.NoError(t, err)

	info, err := os.Stat(logFile + ".1")
	require.NoError(t, err)
	assert.Equal(t, int64(0), info.Size())
}

// Benchmark tests
func BenchmarkShouldRotate_UnderThreshold(b *testing.B) {
	tmpDir := b.TempDir()
	logFile := filepath.Join(tmpDir, "bench.log")
	require.NoError(b, os.WriteFile(logFile, make([]byte, 500), 0644))

	rotator := NewDefaultLogRotator(1024, 5)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = rotator.ShouldRotate(logFile)
	}
}

func BenchmarkRotate_NoBackups(b *testing.B) {
	tmpDir := b.TempDir()
	logFile := filepath.Join(tmpDir, "bench.log")

	rotator := NewDefaultLogRotator(1024, 5)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		require.NoError(b, os.WriteFile(logFile, []byte("test"), 0644))
		b.StartTimer()

		file, err := rotator.Rotate(logFile)
		require.NoError(b, err)
		file.Close()
	}
}

func BenchmarkRotate_WithBackups(b *testing.B) {
	tmpDir := b.TempDir()
	logFile := filepath.Join(tmpDir, "bench.log")

	rotator := NewDefaultLogRotator(1024, 5)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		// Set up 3 existing backups
		require.NoError(b, os.WriteFile(logFile, []byte("current"), 0644))
		require.NoError(b, os.WriteFile(logFile+".1", []byte("backup1"), 0644))
		require.NoError(b, os.WriteFile(logFile+".2", []byte("backup2"), 0644))
		require.NoError(b, os.WriteFile(logFile+".3", []byte("backup3"), 0644))
		b.StartTimer()

		file, err := rotator.Rotate(logFile)
		require.NoError(b, err)
		file.Close()

		b.StopTimer()
		// Clean up for next iteration
		os.Remove(logFile + ".1")
		os.Remove(logFile + ".2")
		os.Remove(logFile + ".3")
		os.Remove(logFile + ".4")
	}
}
