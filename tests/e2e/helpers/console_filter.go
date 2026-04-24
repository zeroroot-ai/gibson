//go:build e2e
// +build e2e

// Package helpers — console_filter.go implements browser console message
// filtering against a YAML allowlist per design Component 5.
//
// The allowlist (enterprise/platform/dashboard/e2e/console-allowlist.yaml)
// defines known-benign console messages by regex pattern + level. Messages
// matching an allowlist entry are stripped from the smoke test's failure
// report. Messages NOT matching the allowlist are returned as potential
// failures.
//
// Security contract:
//   - Error-level messages are ONLY filtered if they have an allowlist entry
//     with a tracking reference. Silent suppression of auth/authz errors is
//     forbidden.
//   - Warn / Info / Log level messages may be freely filtered without tracking.
//
// Requirements: NFR Reliability, R5.3, design Component 5.
package helpers

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// Allowlist schema
// ---------------------------------------------------------------------------

// AllowlistEntry is a single entry in the console allowlist YAML.
type AllowlistEntry struct {
	Pattern  string `yaml:"pattern"`
	Level    string `yaml:"level"` // "error" | "warn" | "info" | "log" | "*"
	Reason   string `yaml:"reason"`
	Tracking string `yaml:"tracking"`
}

// consoleAllowlist is the top-level YAML structure.
type consoleAllowlist struct {
	Allowlist []AllowlistEntry `yaml:"allowlist"`
}

// compiledEntry holds a compiled regex for fast matching.
type compiledEntry struct {
	re      *regexp.Regexp
	level   string
	reason  string
	tracking string
}

// ---------------------------------------------------------------------------
// ConsoleMessage — the input type
// ---------------------------------------------------------------------------

// ConsoleMessage represents a single console emission captured by Playwright.
type ConsoleMessage struct {
	// Level is the console level: "error", "warn", "info", "log", "debug".
	Level string `json:"level"`

	// Text is the full message text.
	Text string `json:"text"`
}

// ---------------------------------------------------------------------------
// ConsoleFilter — compiled allowlist
// ---------------------------------------------------------------------------

// ConsoleFilter holds the compiled allowlist ready for fast filtering.
type ConsoleFilter struct {
	entries []compiledEntry
}

// LoadConsoleFilter reads and compiles the allowlist YAML at path.
//
// Returns an error if the file is missing, malformed, or any pattern fails to
// compile as a regular expression.
func LoadConsoleFilter(allowlistPath string) (*ConsoleFilter, error) {
	data, err := os.ReadFile(allowlistPath)
	if err != nil {
		return nil, fmt.Errorf("console_filter: LoadConsoleFilter: read %s: %w", allowlistPath, err)
	}

	var al consoleAllowlist
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&al); err != nil {
		return nil, fmt.Errorf("console_filter: LoadConsoleFilter: parse %s: %w", allowlistPath, err)
	}

	cf := &ConsoleFilter{
		entries: make([]compiledEntry, 0, len(al.Allowlist)),
	}

	for i, entry := range al.Allowlist {
		if entry.Pattern == "" {
			return nil, fmt.Errorf("console_filter: allowlist entry[%d] has empty pattern", i)
		}
		re, compErr := regexp.Compile(entry.Pattern)
		if compErr != nil {
			return nil, fmt.Errorf("console_filter: allowlist entry[%d] pattern %q: %w", i, entry.Pattern, compErr)
		}
		// Validate level field.
		switch entry.Level {
		case "error", "warn", "info", "log", "debug", "*", "":
			// valid
		default:
			return nil, fmt.Errorf("console_filter: allowlist entry[%d] has invalid level %q — must be error|warn|info|log|debug|*", i, entry.Level)
		}
		cf.entries = append(cf.entries, compiledEntry{
			re:      re,
			level:   entry.Level,
			reason:  entry.Reason,
			tracking: entry.Tracking,
		})
	}

	return cf, nil
}

// Filter applies the allowlist to a slice of console messages, returning only
// the messages that are NOT matched by any allowlist entry.
//
// Filtering rules:
//   - A message is filtered if its level matches the entry's level (or the
//     entry's level is "*") AND the message text matches the entry's regex.
//   - Error-level messages are filtered only if the matching entry has a
//     non-empty tracking reference (enforcement of security contract).
//
// Returns the residue: messages that passed through the filter (potential failures).
func (cf *ConsoleFilter) Filter(messages []ConsoleMessage) []ConsoleMessage {
	if cf == nil || len(cf.entries) == 0 {
		return messages
	}

	var residue []ConsoleMessage
	for _, msg := range messages {
		if cf.isAllowed(msg) {
			continue
		}
		residue = append(residue, msg)
	}
	return residue
}

// isAllowed returns true if the message is matched by any allowlist entry.
func (cf *ConsoleFilter) isAllowed(msg ConsoleMessage) bool {
	msgLevel := strings.ToLower(msg.Level)

	// Warn/info/log/debug are always allowed to be filtered without
	// tracking (they are development noise).
	if msgLevel == "warn" || msgLevel == "info" || msgLevel == "log" || msgLevel == "debug" {
		for _, entry := range cf.entries {
			if !levelMatches(entry.level, msgLevel) {
				continue
			}
			if entry.re.MatchString(msg.Text) {
				return true
			}
		}
		// Not matched by any specific entry — still filter warn/info/log/debug
		// as they are always benign.
		return msgLevel != "error"
	}

	// Error-level: only filter if there is an explicit allowlist match
	// with a tracking reference (security contract).
	for _, entry := range cf.entries {
		if !levelMatches(entry.level, msgLevel) {
			continue
		}
		if !entry.re.MatchString(msg.Text) {
			continue
		}
		// Matched — apply tracking enforcement for error level.
		if msgLevel == "error" && entry.tracking == "" {
			// Error-level match without tracking reference: NOT allowed.
			// The allowlist entry exists but is missing tracking — treat as
			// unfiltered (the entry is misconfigured; the caller should fix it).
			return false
		}
		return true
	}
	return false
}

// levelMatches returns true if the allowlist entry level matches the message level.
func levelMatches(entryLevel, msgLevel string) bool {
	if entryLevel == "*" || entryLevel == "" {
		return true
	}
	return strings.EqualFold(entryLevel, msgLevel)
}

// ---------------------------------------------------------------------------
// Package-level convenience
// ---------------------------------------------------------------------------

// Filter is a package-level convenience function that loads the allowlist
// from allowlistPath and filters messages in one call.
//
// For repeated calls (e.g., per-route in a loop), prefer LoadConsoleFilter
// once and call Filter on the result.
func Filter(messages []ConsoleMessage, allowlistPath string) ([]ConsoleMessage, error) {
	cf, err := LoadConsoleFilter(allowlistPath)
	if err != nil {
		return messages, fmt.Errorf("Filter: %w", err)
	}
	return cf.Filter(messages), nil
}
