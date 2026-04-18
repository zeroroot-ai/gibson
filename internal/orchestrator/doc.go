// Package orchestrator provides the decision-making types and schema for
// Gibson's LLM-driven mission orchestration.
//
// The orchestrator uses structured output from an LLM to make intelligent
// decisions about mission execution. The Decision type represents the output
// of the orchestrator's reasoning process.
//
// # Decision Actions
//
// The orchestrator can take several types of actions:
//
//   - execute_agent: Run a specific mission node/agent
//   - skip_agent: Skip execution of a mission node
//   - modify_params: Modify parameters for a target node before execution
//   - retry: Retry execution of a failed node
//   - spawn_agent: Dynamically create and add a new node to the mission
//   - complete: Mark the mission as complete and stop orchestration
//
// # JSON Schema
//
// The Decision type is designed to be JSON serializable for LLM structured output.
// Example decision JSON:
//
//	{
//	  "reasoning": "Reconnaissance completed. Need to scan for vulnerabilities.",
//	  "action": "execute_agent",
//	  "target_node_id": "vuln-scanner-1",
//	  "confidence": 0.92
//	}
//
// # Usage Example
//
// Parse an LLM's structured output:
//
//	decision, err := orchestrator.ParseDecision(llmResponse)
//	if err != nil {
//	    return fmt.Errorf("invalid decision: %w", err)
//	}
//
//	if decision.IsTerminal() {
//	    log.Printf("Mission complete: %s", decision.StopReason)
//	    return nil
//	}
//
//	switch decision.Action {
//	case orchestrator.ActionExecuteAgent:
//	    return executor.RunNode(decision.TargetNodeID)
//	case orchestrator.ActionSpawnAgent:
//	    return mission.AddNode(decision.SpawnConfig)
//	// ... handle other actions
//	}
//
// # Validation
//
// All decisions are validated to ensure required fields are present:
//
//   - Reasoning is always required
//   - Action must be a valid DecisionAction constant
//   - Confidence must be between 0.0 and 1.0
//   - Action-specific fields are validated (e.g., target_node_id for execute_agent)
//
// # Thread Safety
//
// Decision types are immutable after creation and safe for concurrent use.
// ParseDecision performs validation and returns an error for invalid input.
package orchestrator
