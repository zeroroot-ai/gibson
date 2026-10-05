// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package observability_test

import (
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/infra/observability"
)

// Example demonstrates the event name constants for logging content.
func Example_eventNames() {
	// Use event name constants when adding events to spans
	fmt.Println("Prompt event:", observability.EventGenAIContentPrompt)
	fmt.Println("Completion event:", observability.EventGenAIContentCompletion)
	fmt.Println("Tool input event:", observability.EventGenAIToolCallInput)
	fmt.Println("Tool output event:", observability.EventGenAIToolCallOutput)

	// Output:
	// Prompt event: gen_ai.content.prompt
	// Completion event: gen_ai.content.completion
	// Tool input event: gen_ai.tool_call.input
	// Tool output event: gen_ai.tool_call.output
}
