// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package version

import (
	"runtime"
	"strings"
	"testing"
)

func TestString(t *testing.T) {
	// Save original values
	origVersion := Version
	origCommit := GitCommit
	origBuildTime := BuildTime

	// Restore after test
	defer func() {
		Version = origVersion
		GitCommit = origCommit
		BuildTime = origBuildTime
	}()

	// Test with development values
	Version = "dev"
	GitCommit = "unknown"
	BuildTime = "unknown"

	result := String()
	if !strings.Contains(result, "Gibson") {
		t.Errorf("String() should contain 'Gibson', got: %s", result)
	}
	if !strings.Contains(result, "dev") {
		t.Errorf("String() should contain version 'dev', got: %s", result)
	}
	if !strings.Contains(result, "unknown") {
		t.Errorf("String() should contain 'unknown', got: %s", result)
	}
	if !strings.Contains(result, runtime.Version()) {
		t.Errorf("String() should contain Go version, got: %s", result)
	}

	// Test with release values
	Version = "1.2.3"
	GitCommit = "abc123def"
	BuildTime = "2024-01-15T10:30:00Z"

	result = String()
	if !strings.Contains(result, "1.2.3") {
		t.Errorf("String() should contain version '1.2.3', got: %s", result)
	}
	if !strings.Contains(result, "abc123def") {
		t.Errorf("String() should contain commit 'abc123def', got: %s", result)
	}
	if !strings.Contains(result, "2024-01-15T10:30:00Z") {
		t.Errorf("String() should contain build time, got: %s", result)
	}
}

func TestInfo(t *testing.T) {
	// Save original values
	origVersion := Version
	origCommit := GitCommit
	origBuildTime := BuildTime

	// Restore after test
	defer func() {
		Version = origVersion
		GitCommit = origCommit
		BuildTime = origBuildTime
	}()

	// Set test values
	Version = "2.0.0"
	GitCommit = "fedcba987"
	BuildTime = "2024-02-20T15:45:30Z"

	info := Info()

	tests := []struct {
		key      string
		expected string
	}{
		{"version", "2.0.0"},
		{"commit", "fedcba987"},
		{"buildTime", "2024-02-20T15:45:30Z"},
		{"goVersion", runtime.Version()},
		{"platform", runtime.GOOS + "/" + runtime.GOARCH},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			if got, ok := info[tt.key]; !ok {
				t.Errorf("Info() missing key %q", tt.key)
			} else if got != tt.expected {
				t.Errorf("Info()[%q] = %q, want %q", tt.key, got, tt.expected)
			}
		})
	}
}

func TestDefaultValues(t *testing.T) {
	// This test verifies that default values are set correctly
	// when the binary is built without ldflags injection
	if Version == "" {
		t.Error("Version should not be empty, expected 'dev' as default")
	}
	if GitCommit == "" {
		t.Error("GitCommit should not be empty, expected 'unknown' as default")
	}
	if BuildTime == "" {
		t.Error("BuildTime should not be empty, expected 'unknown' as default")
	}
}
