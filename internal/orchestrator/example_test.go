package orchestrator_test

import (
	"fmt"

	"github.com/zero-day-ai/gibson/internal/orchestrator"
)

// Example demonstrates parsing a Decision from LLM JSON output
func ExampleParseDecision() {
	// Simulated LLM structured output
	llmResponse := `{
		"reasoning": "The reconnaissance agent has completed successfully and gathered target information. The next logical step is to execute the vulnerability scanning agent to identify potential weaknesses.",
		"action": "execute_agent",
		"target_node_id": "vuln-scanner-1",
		"confidence": 0.92
	}`

	decision, err := orchestrator.ParseDecision(llmResponse)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Action: %s\n", decision.Action)
	fmt.Printf("Target: %s\n", decision.TargetNodeID)
	fmt.Printf("Confidence: %.2f\n", decision.Confidence)
	// Output:
	// Action: execute_agent
	// Target: vuln-scanner-1
	// Confidence: 0.92
}

// Example demonstrates creating a spawn agent decision
func ExampleDecision_spawnAgent() {
	decision := &orchestrator.Decision{
		Reasoning: "Discovered multiple web servers during reconnaissance. Need to spawn a specialized web vulnerability scanner for thorough analysis.",
		Action:    orchestrator.ActionSpawnAgent,
		SpawnConfig: &orchestrator.SpawnNodeConfig{
			AgentName:   "web-vuln-scanner",
			Description: "Specialized scanner for web application vulnerabilities",
			TaskConfig: map[string]interface{}{
				"urls":    []string{"http://192.168.1.10", "http://192.168.1.20"},
				"depth":   3,
				"timeout": 300,
			},
			DependsOn: []string{"recon-1", "port-scan-1"},
		},
		Confidence: 0.88,
	}

	if err := decision.Validate(); err != nil {
		fmt.Printf("Validation error: %v\n", err)
		return
	}

	fmt.Printf("Decision: %s\n", decision.String())
	fmt.Printf("Spawning: %s\n", decision.SpawnConfig.AgentName)
	// Output:
	// Decision: Decision{Action: spawn_agent, SpawnAgent: web-vuln-scanner, Confidence: 0.88}
	// Spawning: web-vuln-scanner
}

// Example demonstrates a completion decision
func ExampleDecision_complete() {
	decision := &orchestrator.Decision{
		Reasoning:  "All mission nodes have been executed successfully. Reconnaissance identified 5 hosts, vulnerability scanning found 3 exploitable services, and exploitation was successful on 2 targets. All mission objectives have been achieved.",
		Action:     orchestrator.ActionComplete,
		Confidence: 0.98,
		StopReason: "Successfully compromised target infrastructure and established persistent access",
	}

	if err := decision.Validate(); err != nil {
		fmt.Printf("Validation error: %v\n", err)
		return
	}

	fmt.Printf("Terminal: %v\n", decision.IsTerminal())
	fmt.Printf("Reason: %s\n", decision.StopReason)
	// Output:
	// Terminal: true
	// Reason: Successfully compromised target infrastructure and established persistent access
}

// Example demonstrates parameter modification
func ExampleDecision_modifyParams() {
	decision := &orchestrator.Decision{
		Reasoning:    "Initial port scan timed out. Reducing scan range and increasing timeout to improve reliability.",
		Action:       orchestrator.ActionModifyParams,
		TargetNodeID: "port-scan-1",
		Modifications: map[string]interface{}{
			"port_range": "1-1000", // Reduced from 1-65535
			"timeout":    600,      // Increased from 300
			"threads":    10,       // Reduced from 50
		},
		Confidence: 0.85,
	}

	if err := decision.Validate(); err != nil {
		fmt.Printf("Validation error: %v\n", err)
		return
	}

	fmt.Printf("Modifying node: %s\n", decision.TargetNodeID)
	fmt.Printf("Modifications: %d parameters\n", len(decision.Modifications))
	// Output:
	// Modifying node: port-scan-1
	// Modifications: 3 parameters
}

// Example demonstrates retry decision
func ExampleDecision_retry() {
	decision := &orchestrator.Decision{
		Reasoning:    "Exploit attempt failed due to network instability. Conditions have improved. Retrying exploitation with same parameters.",
		Action:       orchestrator.ActionRetry,
		TargetNodeID: "exploit-1",
		Confidence:   0.75,
	}

	if err := decision.Validate(); err != nil {
		fmt.Printf("Validation error: %v\n", err)
		return
	}

	fmt.Printf("Retrying: %s\n", decision.TargetNodeID)
	fmt.Printf("Confidence: %.2f\n", decision.Confidence)
	// Output:
	// Retrying: exploit-1
	// Confidence: 0.75
}

// Example demonstrates JSON serialization
func ExampleDecision_ToJSON() {
	decision := &orchestrator.Decision{
		Reasoning:    "Skip this agent as prerequisites are not met",
		Action:       orchestrator.ActionSkipAgent,
		TargetNodeID: "exploit-2",
		Confidence:   0.90,
	}

	jsonStr, err := decision.ToJSON()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("JSON length: %d bytes\n", len(jsonStr))
	fmt.Printf("Valid JSON: true\n")
	// Output:
	// JSON length: 145 bytes
	// Valid JSON: true
}
