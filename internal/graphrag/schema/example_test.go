package schema_test

import (
	"fmt"
	"time"

	"github.com/zero-day-ai/gibson/internal/graphrag/schema"
	"github.com/zero-day-ai/gibson/internal/types"
)

// ExampleAgentExecution demonstrates creating and managing an agent execution.
func ExampleAgentExecution() {
	// Create a new agent execution
	missionID := types.NewID()
	exec := schema.NewAgentExecution("reconnaissance_agent", missionID).
		WithConfig(map[string]any{
			"timeout": 300,
			"depth":   3,
		}).
		WithAttempt(1).
		WithLangfuseSpanID("span_12345")

	fmt.Println("Status:", exec.Status)
	fmt.Println("Attempt:", exec.Attempt)
	fmt.Println("Has Config:", len(exec.ConfigUsed) > 0)

	// Simulate completion
	exec.WithResult(map[string]any{
		"hosts_found": 5,
		"ports_open":  12,
	}).MarkCompleted()

	fmt.Println("Completed:", exec.IsComplete())

	// Output:
	// Status: running
	// Attempt: 1
	// Has Config: true
	// Completed: true
}

// ExampleAgentExecution_retry demonstrates retry handling.
func ExampleAgentExecution_retry() {
	missionID := types.NewID()

	// First attempt fails
	exec1 := schema.NewAgentExecution("scanner_agent", missionID).
		WithAttempt(1).
		MarkFailed("connection timeout")

	fmt.Println("Attempt 1 Status:", exec1.Status)
	fmt.Println("Attempt 1 Error:", exec1.Error)

	// Second attempt succeeds
	exec2 := schema.NewAgentExecution("scanner_agent", missionID).
		WithAttempt(2).
		MarkCompleted()

	fmt.Println("Attempt 2 Status:", exec2.Status)
	fmt.Println("Retry successful:", exec2.Attempt > 1 && exec2.Status == schema.ExecutionStatusCompleted)

	// Output:
	// Attempt 1 Status: failed
	// Attempt 1 Error: connection timeout
	// Attempt 2 Status: completed
	// Retry successful: true
}

// ExampleDecision demonstrates creating orchestrator decisions.
func ExampleDecision() {
	missionID := types.NewID()

	// Orchestrator decides to execute an agent
	decision := schema.NewDecision(missionID, 1, schema.DecisionActionExecuteAgent).
		WithTargetNode("vulnerability_scanner").
		WithReasoning("Initial reconnaissance completed successfully. Target has web services exposed. Need to scan for vulnerabilities.").
		WithConfidence(0.92).
		WithTokenUsage(450, 120).
		WithLatency(850).
		WithLangfuseSpanID("decision_span_789")

	fmt.Println("Action:", decision.Action)
	fmt.Println("Target:", decision.TargetNodeID)
	fmt.Println("Confidence:", decision.Confidence)
	fmt.Println("Total Tokens:", decision.TotalTokens())

	// Output:
	// Action: execute_agent
	// Target: vulnerability_scanner
	// Confidence: 0.92
	// Total Tokens: 570
}

// ExampleDecision_modifyParams demonstrates parameter modification decisions.
func ExampleDecision_modifyParams() {
	missionID := types.NewID()

	// Orchestrator decides to modify agent parameters
	decision := schema.NewDecision(missionID, 3, schema.DecisionActionModifyParams).
		WithTargetNode("deep_scan_agent").
		WithReasoning("Previous scan was too shallow. Increasing depth to find hidden vulnerabilities.").
		WithConfidence(0.88).
		WithModifications(map[string]any{
			"max_depth":    5,
			"timeout":      600,
			"aggressive":   true,
			"skip_cdn_ips": false,
		})

	fmt.Println("Action:", decision.Action)
	fmt.Println("Has Modifications:", len(decision.Modifications) > 0)
	fmt.Println("Modified max_depth:", decision.Modifications["max_depth"])

	// Output:
	// Action: modify_params
	// Has Modifications: true
	// Modified max_depth: 5
}

// ExampleToolExecution demonstrates tool execution tracking.
func ExampleToolExecution() {
	agentExecID := types.NewID()

	// Create tool execution
	toolExec := schema.NewToolExecution(agentExecID, "nmap_scan").
		WithInput(map[string]any{
			"target": "192.168.1.1",
			"ports":  "1-1000",
			"flags":  "-sV",
		}).
		WithLangfuseSpanID("tool_span_abc")

	fmt.Println("Tool:", toolExec.ToolName)
	fmt.Println("Status:", toolExec.Status)

	// Simulate successful completion
	toolExec.WithOutput(map[string]any{
		"open_ports": []int{22, 80, 443},
		"services": map[string]string{
			"22":  "ssh",
			"80":  "http",
			"443": "https",
		},
	}).MarkCompleted()

	fmt.Println("Final Status:", toolExec.Status)
	fmt.Println("Has Output:", len(toolExec.Output) > 0)

	// Output:
	// Tool: nmap_scan
	// Status: running
	// Final Status: completed
	// Has Output: true
}

// ExampleToolExecution_failure demonstrates handling tool failures.
func ExampleToolExecution_failure() {
	agentExecID := types.NewID()

	toolExec := schema.NewToolExecution(agentExecID, "web_crawler").
		WithInput(map[string]any{
			"url":       "https://example.com",
			"max_depth": 3,
		})

	// Simulate failure
	toolExec.MarkFailed("HTTP 503: Service Unavailable")

	fmt.Println("Status:", toolExec.Status)
	fmt.Println("Error:", toolExec.Error)
	fmt.Println("Is Complete:", toolExec.IsComplete())

	// Output:
	// Status: failed
	// Error: HTTP 503: Service Unavailable
	// Is Complete: true
}

// Example demonstrates a complete orchestrator mission.
func Example() {
	missionID := types.NewID()

	// 1. Orchestrator makes initial decision
	decision1 := schema.NewDecision(missionID, 1, schema.DecisionActionExecuteAgent).
		WithTargetNode("recon_agent").
		WithReasoning("Starting reconnaissance phase").
		WithConfidence(1.0)

	fmt.Println("Decision 1:", decision1.Action, "->", decision1.TargetNodeID)

	// 2. Execute the agent
	exec1 := schema.NewAgentExecution("recon_agent", missionID).
		WithConfig(map[string]any{"depth": 2})

	// 3. Agent uses tools
	tool1 := schema.NewToolExecution(exec1.ID, "dns_lookup").
		WithInput(map[string]any{"domain": "example.com"}).
		MarkCompleted()

	tool2 := schema.NewToolExecution(exec1.ID, "port_scan").
		WithInput(map[string]any{"target": "192.168.1.1"}).
		MarkCompleted()

	// 4. Agent completes
	exec1.WithResult(map[string]any{
		"findings": 3,
		"severity": "medium",
	}).MarkCompleted()

	// 5. Orchestrator makes next decision
	decision2 := schema.NewDecision(missionID, 2, schema.DecisionActionExecuteAgent).
		WithTargetNode("vuln_scanner").
		WithReasoning("Reconnaissance found exposed services, proceeding with vulnerability scan").
		WithConfidence(0.95)

	fmt.Println("Tool 1:", tool1.ToolName, "-", tool1.Status)
	fmt.Println("Tool 2:", tool2.ToolName, "-", tool2.Status)
	fmt.Println("Agent 1:", exec1.Status)
	fmt.Println("Decision 2:", decision2.Action, "->", decision2.TargetNodeID)

	// Output:
	// Decision 1: execute_agent -> recon_agent
	// Tool 1: dns_lookup - completed
	// Tool 2: port_scan - completed
	// Agent 1: completed
	// Decision 2: execute_agent -> vuln_scanner
}

// ExampleAgentExecution_Duration demonstrates duration tracking.
func ExampleAgentExecution_Duration() {
	exec := schema.NewAgentExecution("test_agent", types.NewID())

	// Duration is 0 while running
	fmt.Println("Initial duration:", exec.Duration())

	// Simulate some execution time
	time.Sleep(50 * time.Millisecond)
	exec.MarkCompleted()

	// Now duration is available
	fmt.Printf("Final duration: >0ms: %v\n", exec.Duration() > 0)

	// Output:
	// Initial duration: 0s
	// Final duration: >0ms: true
}
