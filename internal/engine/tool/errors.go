// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package tool

import "github.com/zeroroot-ai/gibson/internal/infra/types"

// Tool error codes
const (
	ErrToolNotFound        types.ErrorCode = "TOOL_NOT_FOUND"
	ErrToolExecutionFailed types.ErrorCode = "TOOL_EXECUTION_FAILED"
)
