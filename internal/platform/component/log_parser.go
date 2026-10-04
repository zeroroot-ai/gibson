// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

const (
	// defaultBufferSize for reading log files efficiently
	defaultBufferSize = 64 * 1024 // 64KB

	// maxLineLength prevents excessive memory usage from malformed logs
	maxLineLength = 1024 * 1024 // 1MB
)
