// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

const (
	// defaultBufferSize for reading log files efficiently
	defaultBufferSize = 64 * 1024 // 64KB

	// maxLineLength prevents excessive memory usage from malformed logs
	maxLineLength = 1024 * 1024 // 1MB
)

// Handle edge case: missing file

// If we can't open the file, treat it as missing

// Read all lines and parse errors

// Try parsing as JSON first, then fall back to key=value

// Silently skip malformed lines

// Check for scanner errors (but don't fail on them)

// Return what we've parsed so far

// Handle edge case: no errors found

// Sort by timestamp (newest first)

// Return the most recent 'count' errors

// Parse timestamp - try multiple common formats

// Simple key=value parser that handles quoted values

// Remove quotes from value if present

// Must have at least level and msg fields

// Parse timestamp if present

// Add the last part
