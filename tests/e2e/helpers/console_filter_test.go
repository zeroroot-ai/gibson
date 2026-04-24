//go:build e2e
// +build e2e

package helpers_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/tests/e2e/helpers"
)

// writeAllowlistTemp writes an allowlist YAML to a temp file.
func writeAllowlistTemp(t *testing.T, content string) string {
	t.Helper()
	return writeTemp(t, content)
}

// ---------------------------------------------------------------------------
// LoadConsoleFilter
// ---------------------------------------------------------------------------

func TestLoadConsoleFilter_HappyPath(t *testing.T) {
	content := `
allowlist:
  - pattern: "\\[Fast Refresh\\]"
    level: "*"
    reason: "Next.js HMR"
    tracking: ""
  - pattern: "ResizeObserver loop"
    level: error
    reason: "Browser quirk"
    tracking: "https://example.com/issue/1"
`
	path := writeAllowlistTemp(t, content)
	cf, err := helpers.LoadConsoleFilter(path)
	require.NoError(t, err)
	require.NotNil(t, cf)
}

func TestLoadConsoleFilter_InvalidPattern(t *testing.T) {
	content := `
allowlist:
  - pattern: "[invalid("
    level: "*"
    reason: "bad regex"
    tracking: ""
`
	path := writeAllowlistTemp(t, content)
	_, err := helpers.LoadConsoleFilter(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pattern")
}

func TestLoadConsoleFilter_FileNotFound(t *testing.T) {
	_, err := helpers.LoadConsoleFilter("/nonexistent/path/allowlist.yaml")
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// Filter — allowlist match
// ---------------------------------------------------------------------------

func TestFilter_AllowlistedMessage_IsRemoved(t *testing.T) {
	content := `
allowlist:
  - pattern: "Fast Refresh"
    level: "*"
    reason: "Next.js HMR"
    tracking: ""
`
	path := writeAllowlistTemp(t, content)
	cf, err := helpers.LoadConsoleFilter(path)
	require.NoError(t, err)

	messages := []helpers.ConsoleMessage{
		{Level: "log", Text: "[Fast Refresh] Done in 2ms"},
		{Level: "error", Text: "Something broke"},
	}

	residue := cf.Filter(messages)
	// The Fast Refresh message should be filtered; the error should remain.
	require.Len(t, residue, 1)
	assert.Equal(t, "Something broke", residue[0].Text)
}

func TestFilter_ErrorLevel_RequiresTracking(t *testing.T) {
	// An error-level allowlist entry WITHOUT tracking should NOT filter errors.
	content := `
allowlist:
  - pattern: "Hydration failed"
    level: error
    reason: "Next.js hydration"
    tracking: ""
`
	path := writeAllowlistTemp(t, content)
	cf, err := helpers.LoadConsoleFilter(path)
	require.NoError(t, err)

	messages := []helpers.ConsoleMessage{
		{Level: "error", Text: "Error: Hydration failed because the server rendered HTML"},
	}

	residue := cf.Filter(messages)
	// No tracking → error should NOT be filtered.
	require.Len(t, residue, 1, "error without tracking should not be filtered")
}

func TestFilter_ErrorLevel_WithTracking_IsFiltered(t *testing.T) {
	content := `
allowlist:
  - pattern: "Hydration failed"
    level: error
    reason: "Next.js hydration"
    tracking: "https://github.com/vercel/next.js/issues/42218"
`
	path := writeAllowlistTemp(t, content)
	cf, err := helpers.LoadConsoleFilter(path)
	require.NoError(t, err)

	messages := []helpers.ConsoleMessage{
		{Level: "error", Text: "Error: Hydration failed because the server rendered HTML"},
	}

	residue := cf.Filter(messages)
	// Has tracking → error should be filtered.
	require.Empty(t, residue, "error with tracking should be filtered")
}

func TestFilter_WarnAlwaysFiltered(t *testing.T) {
	// Warn messages are filtered even without an explicit allowlist match.
	content := `
allowlist: []
`
	path := writeAllowlistTemp(t, content)
	cf, err := helpers.LoadConsoleFilter(path)
	require.NoError(t, err)

	messages := []helpers.ConsoleMessage{
		{Level: "warn", Text: "This is a warning nobody cares about"},
		{Level: "error", Text: "This is an error that matters"},
	}

	residue := cf.Filter(messages)
	// Warn is filtered; error is not.
	require.Len(t, residue, 1)
	assert.Equal(t, "error", residue[0].Level)
}

func TestFilter_EmptyMessage(t *testing.T) {
	content := `
allowlist:
  - pattern: ".*"
    level: "*"
    reason: "catch-all"
    tracking: ""
`
	path := writeAllowlistTemp(t, content)
	cf, err := helpers.LoadConsoleFilter(path)
	require.NoError(t, err)

	messages := []helpers.ConsoleMessage{
		{Level: "log", Text: ""},
	}

	// Empty text matches ".*" — filtered.
	residue := cf.Filter(messages)
	require.Empty(t, residue)
}

func TestFilter_NilFilter(t *testing.T) {
	// A nil filter returns messages unchanged.
	var cf *helpers.ConsoleFilter
	messages := []helpers.ConsoleMessage{
		{Level: "error", Text: "some error"},
	}
	residue := cf.Filter(messages)
	assert.Len(t, residue, 1)
}

func TestFilter_LevelWildcard(t *testing.T) {
	content := `
allowlist:
  - pattern: "benign"
    level: "*"
    reason: "catch-all benign"
    tracking: ""
`
	path := writeAllowlistTemp(t, content)
	cf, err := helpers.LoadConsoleFilter(path)
	require.NoError(t, err)

	messages := []helpers.ConsoleMessage{
		{Level: "log", Text: "benign log"},
		{Level: "warn", Text: "benign warning"},
		{Level: "info", Text: "benign info"},
		{Level: "error", Text: "benign error without tracking"},
	}

	residue := cf.Filter(messages)
	// log/warn/info: filtered by wildcard; error: wildcard match but no tracking → NOT filtered.
	require.Len(t, residue, 1)
	assert.Equal(t, "error", residue[0].Level)
}
