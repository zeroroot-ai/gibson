// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"fmt"
)

// mockLogger implements the Logger interface for testing.
type mockLogger struct {
	warnings []string
}

func (m *mockLogger) Warnf(format string, args ...interface{}) {
	m.warnings = append(m.warnings, fmt.Sprintf(format, args...))
}

func (m *mockLogger) hasWarning(substr string) bool {
	for _, w := range m.warnings {
		if containsString(w, substr) {
			return true
		}
	}
	return false
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && stringContains(s, substr))
}

func stringContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// missing path

// Only valid ones

// Invalid source should be caught during validation and skipped

// Invalid one skipped silently

// This is valid - will use default branch
