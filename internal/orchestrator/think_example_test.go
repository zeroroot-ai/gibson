package orchestrator_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/zeroroot-ai/gibson/internal/llm"
	"github.com/zeroroot-ai/gibson/internal/orchestrator"
)

// ExampleLLMClient demonstrates a basic implementation of the LLMClient interface
type ExampleLLMClient struct {
	// In a real implementation, this would wrap an actual LLM provider
}

func (c *ExampleLLMClient) Complete(ctx context.Context, slot string, messages []llm.Message, opts ...orchestrator.CompletionOption) (*llm.CompletionResponse, error) {
	// In production, this would call the actual LLM
	// For this example, we return a mock decision
	decision := orchestrator.Decision{
		Reasoning:    "Based on completed reconnaissance, port 443 scan is ready and has high priority",
		Action:       orchestrator.ActionExecuteAgent,
		TargetNodeID: "port-scan-443",
		Confidence:   0.88,
	}

	decisionJSON, _ := json.Marshal(decision)
	return &llm.CompletionResponse{
		ID:    "example-response",
		Model: "claude-3-opus",
		Message: llm.Message{
			Role:    llm.RoleAssistant,
			Content: string(decisionJSON),
		},
		Usage: llm.CompletionTokenUsage{
			PromptTokens:     850,
			CompletionTokens: 120,
			TotalTokens:      970,
		},
		FinishReason: llm.FinishReasonStop,
	}, nil
}

func (c *ExampleLLMClient) CompleteStructuredAny(ctx context.Context, slot string, messages []llm.Message, schemaType any, opts ...orchestrator.CompletionOption) (any, error) {
	// Structured output version (preferred when available)
	decision := &orchestrator.Decision{
		Reasoning:    "Based on completed reconnaissance, port 443 scan is ready and has high priority",
		Action:       orchestrator.ActionExecuteAgent,
		TargetNodeID: "port-scan-443",
		Confidence:   0.88,
	}
	return decision, nil
}

func (c *ExampleLLMClient) CompleteStructuredAnyWithUsage(ctx context.Context, slot string, messages []llm.Message, schemaType any, opts ...orchestrator.CompletionOption) (*orchestrator.StructuredCompletionResult, error) {
	// Structured output version with token usage (preferred)
	decision := &orchestrator.Decision{
		Reasoning:    "Based on completed reconnaissance, port 443 scan is ready and has high priority",
		Action:       orchestrator.ActionExecuteAgent,
		TargetNodeID: "port-scan-443",
		Confidence:   0.88,
	}
	decisionJSON, _ := json.Marshal(decision)
	return &orchestrator.StructuredCompletionResult{
		Result:           decision,
		Model:            "claude-3-opus",
		RawJSON:          string(decisionJSON),
		PromptTokens:     850,
		CompletionTokens: 120,
		TotalTokens:      970,
	}, nil
}

// Example_thinkerBasicUsage demonstrates the basic usage of the Thinker
func Example_thinkerBasicUsage() {
	// Create an LLM client (in production, use harness.AgentHarness)
	llmClient := &ExampleLLMClient{}

	// Create a Thinker with custom options
	thinker := orchestrator.NewThinker(
		llmClient,
		orchestrator.WithMaxRetries(3),
		orchestrator.WithThinkerTemperature(0.2),
	)

	// Create observation state (normally from Observer)
	now := time.Now()
	state := &orchestrator.ObservationState{
		MissionInfo: orchestrator.MissionInfo{
			ID:          "mission-001",
			Name:        "Web Application Security Assessment",
			Objective:   "Discover security vulnerabilities in target web application",
			Status:      "running",
			StartedAt:   now.Add(-10 * time.Minute),
			TimeElapsed: "10.0m",
		},
		GraphSummary: orchestrator.GraphSummary{
			TotalNodes:      5,
			CompletedNodes:  2,
			FailedNodes:     0,
			PendingNodes:    3,
			TotalDecisions:  2,
			TotalExecutions: 2,
		},
		ReadyNodes: []orchestrator.NodeSummary{
			{
				ID:          "port-scan-443",
				Name:        "HTTPS Port Scan",
				Type:        "agent",
				Description: "Scan HTTPS service for vulnerabilities",
				AgentName:   "port-scanner",
				Status:      "ready",
			},
			{
				ID:          "port-scan-80",
				Name:        "HTTP Port Scan",
				Type:        "agent",
				Description: "Scan HTTP service for vulnerabilities",
				AgentName:   "port-scanner",
				Status:      "ready",
			},
		},
		CompletedNodes: []orchestrator.CompletedNodeSummary{
			{
				NodeSummary: orchestrator.NodeSummary{
					ID:          "recon",
					Name:        "Reconnaissance",
					Type:        "agent",
					Description: "Initial reconnaissance",
					AgentName:   "recon-agent",
					Status:      "completed",
				},
			},
		},
		RecentDecisions: []orchestrator.DecisionSummary{
			{
				Iteration:  1,
				Action:     "execute_agent",
				Target:     "recon",
				Reasoning:  "Starting with reconnaissance phase",
				Confidence: 0.95,
				Timestamp:  now.Add(-8 * time.Minute).Format(time.RFC3339),
			},
		},
		ResourceConstraints: orchestrator.ResourceConstraints{
			MaxConcurrent:   2,
			CurrentRunning:  0,
			TimeElapsed:     10 * time.Minute,
			TotalIterations: 2,
		},
		ObservedAt: now,
	}

	// Execute the think phase
	ctx := context.Background()
	result, err := thinker.Think(ctx, state)
	if err != nil {
		log.Fatalf("Think failed: %v", err)
	}

	// Process the decision
	fmt.Printf("Action: %s\n", result.Decision.Action)
	fmt.Printf("Target: %s\n", result.Decision.TargetNodeID)
	fmt.Printf("Confidence: %.2f\n", result.Decision.Confidence)
	fmt.Printf("Tokens: %d\n", result.TotalTokens)

	// Output:
	// Action: execute_agent
	// Target: port-scan-443
	// Confidence: 0.88
	// Tokens: 970
}

// Example_thinkerWithRetries demonstrates retry behavior on parse failures
func Example_thinkerWithRetries() {
	llmClient := &ExampleLLMClient{}

	// Create thinker with specific retry configuration
	thinker := orchestrator.NewThinker(
		llmClient,
		orchestrator.WithMaxRetries(5), // Allow more retries
	)

	// Minimal observation state for demonstration
	state := &orchestrator.ObservationState{
		MissionInfo: orchestrator.MissionInfo{
			ID:        "mission-002",
			Name:      "Quick Test",
			Objective: "Test retry behavior",
			Status:    "running",
			StartedAt: time.Now().Add(-1 * time.Minute),
		},
		ReadyNodes: []orchestrator.NodeSummary{
			{
				ID:        "test-node",
				Name:      "Test Node",
				Type:      "agent",
				AgentName: "test-agent",
			},
		},
		ObservedAt: time.Now(),
	}

	result, err := thinker.Think(context.Background(), state)
	if err != nil {
		log.Fatalf("Think failed: %v", err)
	}

	fmt.Printf("Decision made after %d retries\n", result.RetryCount)
	fmt.Printf("Latency: %v\n", result.Latency > 0)

	// Output:
	// Decision made after 0 retries
	// Latency: true
}

// Example_thinkerDecisionTypes demonstrates different decision types
func Example_thinkerDecisionTypes() {
	// Example 1: Execute Agent Decision
	executeDecision := &orchestrator.Decision{
		Reasoning:    "Reconnaissance completed successfully, proceeding to exploitation",
		Action:       orchestrator.ActionExecuteAgent,
		TargetNodeID: "exploit-node",
		Confidence:   0.92,
	}
	fmt.Printf("Execute: %s (confidence: %.2f)\n",
		executeDecision.TargetNodeID, executeDecision.Confidence)

	// Example 2: Skip Agent Decision
	skipDecision := &orchestrator.Decision{
		Reasoning:    "This node is not applicable to the target type",
		Action:       orchestrator.ActionSkipAgent,
		TargetNodeID: "windows-specific-node",
		Confidence:   0.85,
	}
	fmt.Printf("Skip: %s\n", skipDecision.TargetNodeID)

	// Example 3: Modify Parameters Decision
	modifyDecision := &orchestrator.Decision{
		Reasoning:    "Adjusting scan intensity based on discovered services",
		Action:       orchestrator.ActionModifyParams,
		TargetNodeID: "port-scanner",
		Modifications: map[string]interface{}{
			"scan_intensity": "aggressive",
			"target_ports":   []int{80, 443, 8080, 8443},
		},
		Confidence: 0.78,
	}
	fmt.Printf("Modify: %s (%d modifications)\n",
		modifyDecision.TargetNodeID, len(modifyDecision.Modifications))

	// Example 4: Complete Decision
	completeDecision := &orchestrator.Decision{
		Reasoning:  "All reconnaissance complete, 5 vulnerabilities discovered, mission objective achieved",
		Action:     orchestrator.ActionComplete,
		Confidence: 0.95,
		StopReason: "Mission objective achieved: discovered 5 high-severity vulnerabilities",
	}
	fmt.Printf("Complete: %s (terminal: %v)\n",
		completeDecision.StopReason, completeDecision.IsTerminal())

	// Output:
	// Execute: exploit-node (confidence: 0.92)
	// Skip: windows-specific-node
	// Modify: port-scanner (2 modifications)
	// Complete: Mission objective achieved: discovered 5 high-severity vulnerabilities (terminal: true)
}
