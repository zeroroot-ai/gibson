// Package schema provides graph schema types for the Gibson orchestrator refactor.
//
// This package defines the core data structures that represent mission execution
// state in the Neo4j graph database. These types enable the orchestrator to track
// mission execution, dependencies, and state transitions in a graph-native way.
//
// # Mission Node
//
// The Mission node represents the top-level execution unit. It tracks:
//   - Mission metadata (name, description, objective, target)
//   - Execution status (pending, running, completed, failed)
//   - Temporal lifecycle (created_at, started_at, completed_at)
//   - Original YAML source for reconstruction
//
// Example usage:
//
//	mission := schema.NewMission(
//	    types.NewID(),
//	    "web-api-scan",
//	    "Scan web API for vulnerabilities",
//	    "Identify security weaknesses",
//	    "target-123",
//	    yamlSource,
//	)
//	mission.MarkStarted()
//	// ... execute mission ...
//	mission.MarkCompleted()
//
// # MissionNode Node
//
// The MissionNode represents individual tasks within a mission. Each node
// can be either an agent execution or a tool invocation. Nodes track:
//   - Parent mission relationship
//   - Task type (agent or tool)
//   - Execution configuration (timeout, retry policy)
//   - Task-specific parameters (agent_name or tool_name)
//   - Execution status and lifecycle
//   - Dynamic spawning metadata for runtime-created tasks
//
// Example usage:
//
//	// Create an agent node
//	agentNode := schema.NewAgentNode(
//	    types.NewID(),
//	    missionID,
//	    "nmap-scan",
//	    "Run nmap port scan",
//	    "nmap-agent",
//	)
//	agentNode.
//	    WithTimeout(5 * time.Minute).
//	    WithRetryPolicy(&schema.RetryPolicy{
//	        MaxRetries: 3,
//	        Backoff:    time.Second,
//	        Strategy:   "exponential",
//	    })
//
//	// Create a tool node
//	toolNode := schema.NewToolNode(
//	    types.NewID(),
//	    missionID,
//	    "parse-results",
//	    "Parse scan results",
//	    "json-parser",
//	)
//
// # Status Enums
//
// The package provides strongly-typed status enums with validation:
//
//   - MissionStatus: pending, running, completed, failed
//   - MissionNodeStatus: pending, ready, running, completed, failed, skipped
//   - MissionNodeType: agent, tool
//
// All status enums implement Validate() for runtime safety.
//
// # RetryPolicy
//
// The RetryPolicy struct configures retry behavior for mission nodes:
//
//	policy := &schema.RetryPolicy{
//	    MaxRetries: 5,
//	    Backoff:    2 * time.Second,
//	    Strategy:   "exponential",
//	    MaxBackoff: time.Minute,
//	}
//
// Supports both linear and exponential backoff strategies.
//
// # JSON Serialization
//
// Complex fields (retry_policy, task_config) are stored as JSON strings in Neo4j
// for flexibility. Helper methods simplify serialization:
//
//	jsonStr, err := node.RetryPolicyJSON()
//	configStr, err := node.TaskConfigJSON()
//
// # Integration with GraphRAG
//
// These types integrate with the existing graphrag package:
//
//   - Use types.ID for consistent UUID-based identification
//   - Follow similar patterns to graphrag.GraphNode
//   - Support method chaining for fluent API
//   - Include comprehensive validation
//
// # Neo4j Labels
//
// The package exports label constants for Cypher queries:
//
//	const (
//	    LabelMission           = "Mission"
//	    LabelMissionNode      = "MissionNode"
//	    NodeLabelAgentExecution = "AgentExecution"
//	    NodeLabelDecision      = "Decision"
//	    NodeLabelToolExecution = "ToolExecution"
//	)
//
// These constants ensure consistency between Go code and Cypher queries.
//
// # Execution Tracking Types
//
// The package provides execution tracking types for observability and debugging:
//
//   - AgentExecution: Tracks individual agent execution instances including configuration,
//     status, timing, results, and retry attempts. Each execution is linked to a mission
//     node and mission.
//
//   - Decision: Captures orchestrator decision points including the reasoning process,
//     action taken (execute, skip, modify parameters, etc.), confidence scores, and
//     observability metrics (tokens, latency).
//
//   - ToolExecution: Tracks individual tool invocations within an agent execution,
//     including input parameters, output results, timing, and error states.
//
// # Execution Status
//
// All execution types use the ExecutionStatus enum with three states:
//   - running: Execution is currently in progress
//   - completed: Execution finished successfully
//   - failed: Execution failed with an error
//
// # Observability Integration
//
// All execution types include LangfuseSpanID fields for correlation with Langfuse
// observability traces. This enables end-to-end tracing from orchestrator decisions
// through agent executions to individual tool invocations.
//
// Example usage:
//
//	// Track agent execution
//	exec := schema.NewAgentExecution("recon_agent", missionID).
//	    WithConfig(map[string]any{"depth": 3}).
//	    WithLangfuseSpanID("span_123")
//	exec.MarkCompleted()
//
//	// Record orchestrator decision
//	decision := schema.NewDecision(missionID, 1, schema.DecisionActionExecuteAgent).
//	    WithTargetNode("vuln_scanner").
//	    WithReasoning("Reconnaissance found exposed services").
//	    WithConfidence(0.92)
//
//	// Track tool invocation
//	toolExec := schema.NewToolExecution(agentExecID, "nmap_scan").
//	    WithInput(map[string]any{"target": "192.168.1.1"}).
//	    MarkCompleted()
//
// # Decision Actions
//
// The Decision type supports multiple orchestrator actions:
//   - execute_agent: Execute a mission agent
//   - skip_agent: Skip an agent based on graph state
//   - modify_params: Modify agent parameters before execution
//   - complete: Complete the mission
//   - spawn_agent: Dynamically spawn a new agent
package schema
