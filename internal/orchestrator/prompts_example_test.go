package orchestrator_test

import (
	"fmt"
	"time"

	"github.com/zeroroot-ai/gibson/internal/orchestrator"
)

// ExampleBuildObservationPrompt demonstrates how to build an observation prompt
// from the current mission state.
func ExampleBuildObservationPrompt() {
	// Create a sample observation state
	state := &orchestrator.ObservationState{
		MissionInfo: orchestrator.MissionInfo{
			ID:          "mission-abc123",
			Name:        "Production API Security Audit",
			Objective:   "Discover security vulnerabilities in production LLM API",
			Status:      "running",
			TimeElapsed: "25.5m",
			StartedAt:   time.Now().Add(-25 * time.Minute),
		},
		GraphSummary: orchestrator.GraphSummary{
			TotalNodes:      15,
			CompletedNodes:  8,
			FailedNodes:     1,
			PendingNodes:    3,
			TotalDecisions:  9,
			TotalExecutions: 10,
		},
		ReadyNodes: []orchestrator.NodeSummary{
			{
				ID:          "node-exploit-1",
				Name:        "Exploit Discovered Vulnerability",
				Type:        "agent",
				AgentName:   "exploit-agent",
				Description: "Attempt to exploit SQL injection found in recon phase",
				Status:      "ready",
			},
			{
				ID:          "node-scan-alt",
				Name:        "Alternative Port Scan",
				Type:        "tool",
				ToolName:    "nmap",
				Description: "Scan alternative ports based on findings",
				Status:      "ready",
			},
		},
		RunningNodes: []orchestrator.NodeSummary{
			{
				ID:        "node-jailbreak",
				Name:      "Jailbreak Attempt",
				Type:      "agent",
				AgentName: "jailbreaker",
				Status:    "running",
				Attempt:   1,
			},
		},
		FailedNodes: []orchestrator.NodeSummary{
			{
				ID:        "node-auth-bypass",
				Name:      "Authentication Bypass",
				Type:      "agent",
				AgentName: "auth-bypass-agent",
				Status:    "failed",
				Attempt:   2,
			},
		},
		RecentDecisions: []orchestrator.DecisionSummary{
			{
				Iteration:  8,
				Action:     "execute_agent",
				Target:     "node-jailbreak",
				Reasoning:  "Recon discovered weak content filtering, attempting jailbreak",
				Confidence: 0.82,
				Timestamp:  time.Now().Add(-5 * time.Minute).Format(time.RFC3339),
			},
			{
				Iteration:  9,
				Action:     "skip_agent",
				Target:     "node-legacy-scan",
				Reasoning:  "Target confirmed to not use legacy protocols",
				Confidence: 0.95,
				Timestamp:  time.Now().Add(-2 * time.Minute).Format(time.RFC3339),
			},
		},
		ResourceConstraints: orchestrator.ResourceConstraints{
			MaxConcurrent:    5,
			CurrentRunning:   1,
			TotalIterations:  9,
			TimeElapsed:      25 * time.Minute,
			RemainingRetries: 1,
			ExecutionBudget: &orchestrator.BudgetInfo{
				MaxExecutions:       50,
				RemainingExecutions: 39,
			},
		},
		ObservedAt: time.Now(),
	}

	// Build the observation prompt
	prompt := orchestrator.BuildObservationPrompt(state)

	// Print first 500 characters to show structure
	if len(prompt) > 500 {
		fmt.Println(prompt[:500] + "...")
	} else {
		fmt.Println(prompt)
	}

	// Output will show:
	// # Current Mission State
	//
	// ## Mission Overview
	// **Objective**: Discover security vulnerabilities in production LLM API
	// **Mission ID**: mission-abc123
	// ...
}

// ExampleBuildFullPrompt demonstrates how to build a complete prompt
// including system instructions, observation state, and optional examples.
func ExampleBuildFullPrompt() {
	// Create a minimal observation state
	state := &orchestrator.ObservationState{
		MissionInfo: orchestrator.MissionInfo{
			ID:          "mission-demo",
			Name:        "Demo Mission",
			Objective:   "Demonstrate orchestrator prompts",
			Status:      "running",
			TimeElapsed: "5.0m",
		},
		GraphSummary: orchestrator.GraphSummary{
			TotalNodes:     5,
			CompletedNodes: 2,
		},
		ReadyNodes: []orchestrator.NodeSummary{
			{
				ID:        "node-next",
				Name:      "Next Step",
				Type:      "agent",
				AgentName: "test-agent",
			},
		},
		RunningNodes:    []orchestrator.NodeSummary{},
		CompletedNodes:  []orchestrator.CompletedNodeSummary{},
		FailedNodes:     []orchestrator.NodeSummary{},
		RecentDecisions: []orchestrator.DecisionSummary{},
		ResourceConstraints: orchestrator.ResourceConstraints{
			MaxConcurrent: 10,
		},
		ObservedAt: time.Now(),
	}

	// Build full prompt without examples (more concise)
	promptNoExamples := orchestrator.BuildFullPrompt(state, false)
	fmt.Printf("Prompt without examples: %d characters\n", len(promptNoExamples))

	// Build full prompt with examples (for initial few-shot learning)
	promptWithExamples := orchestrator.BuildFullPrompt(state, true)
	fmt.Printf("Prompt with examples: %d characters\n", len(promptWithExamples))

	// Estimate token usage
	tokensNoExamples := orchestrator.EstimatePromptTokens(promptNoExamples)
	tokensWithExamples := orchestrator.EstimatePromptTokens(promptWithExamples)

	fmt.Printf("Estimated tokens (no examples): ~%d\n", tokensNoExamples)
	fmt.Printf("Estimated tokens (with examples): ~%d\n", tokensWithExamples)
}

// ExampleBuildDecisionSchema demonstrates how to get the JSON schema
// for Decision objects to enable structured output from LLMs.
func ExampleBuildDecisionSchema() {
	// Get the decision schema
	schema := orchestrator.BuildDecisionSchema()

	// Parse to show it's valid JSON
	fmt.Printf("Schema length: %d characters\n", len(schema))
	fmt.Println("Schema includes conditional validation rules")
	fmt.Println("Use this schema with LLM providers that support structured output")

	// This schema can be used with:
	// - Anthropic Claude (response_format parameter)
	// - OpenAI GPT (function calling / structured outputs)
	// - Other providers with JSON schema support
}

// ExampleFormatDecisionExample demonstrates the decision examples
// that can be included in prompts for few-shot learning.
func ExampleFormatDecisionExample() {
	// Get formatted examples
	executeExample := orchestrator.FormatDecisionExample()
	completeExample := orchestrator.FormatCompleteExample()
	spawnExample := orchestrator.FormatSpawnExample()

	fmt.Println("Execute Agent Example:")
	fmt.Println(executeExample)
	fmt.Println("\nComplete Mission Example:")
	fmt.Println(completeExample)
	fmt.Println("\nSpawn Agent Example:")
	fmt.Println(spawnExample)

	// These examples help guide the LLM toward properly formatted decisions
}
