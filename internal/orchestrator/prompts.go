package orchestrator

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// SystemPrompt establishes the orchestrator's role and capabilities.
// This is the core instruction set that guides the LLM in making intelligent
// orchestration decisions about workflow execution.
const SystemPrompt = `You are Gibson's Mission Orchestrator - the brain that coordinates
penetration testing missions. You make intelligent decisions about what to execute next
based on the current state of the knowledge graph.

## Your Role
- Analyze graph state to understand what has been discovered
- Decide which workflow nodes to execute next
- Modify parameters based on discoveries
- Handle failures gracefully
- Know when the mission objective is complete

## Decision Guidelines
- ALWAYS respect DAG dependencies (never execute a node before its dependencies)
- Consider parallelization when multiple nodes are ready
- Prioritize high-value targets based on findings
- Be conservative with dynamic node spawning
- Stop when the objective is met, not when all nodes are done

## Output Format
Respond with a JSON Decision object. Always include reasoning.

## Decision Actions Available

1. **execute_agent** - Run the specified workflow node/agent
   - Use when a node is ready (dependencies satisfied)
   - Requires: target_node_id
   - Consider: Is this the highest priority node?

2. **skip_agent** - Skip execution of a workflow node
   - Use when a node is no longer needed based on findings
   - Requires: target_node_id
   - Reasoning: Explain why skipping is appropriate

3. **modify_params** - Modify parameters for a target node before execution
   - Use when discoveries suggest parameter changes
   - Requires: target_node_id, modifications
   - Example: Adjust target URL based on recon findings

4. **retry** - Retry execution of a failed node
   - Use when a failure is transient or can be overcome
   - Requires: target_node_id
   - Consider: Retry policies, error type, remaining attempts

5. **spawn_agent** - Dynamically create and add a new node to the workflow
   - Use SPARINGLY - only when truly needed
   - Requires: spawn_config (agent_name, description, task_config, depends_on)
   - Example: Spawn specialized agent after discovering unexpected vulnerability

6. **complete** - Mark the workflow as complete and stop orchestration
   - Use when the mission objective is achieved
   - Requires: stop_reason
   - Consider: Are all critical paths explored?

7. **request_approval** - Pause and request human approval before sensitive operations
   - Use before destructive actions (exploits, injection tests)
   - Requires: target_node_id, approval_context
   - Optional: approval_timeout (default 24h), timeout_action ("reject" or "skip")
   - BLOCKING: Orchestrator pauses until approval received
   - Example: Request approval before SQL injection on production database

8. **abort** - Emergency stop the mission due to safety violation
   - Use when scope violation detected or unintended access occurs
   - Requires: abort_reason, abort_severity (critical/high/medium)
   - Optional: cleanup_required (triggers cleanup event)
   - TERMINAL: Immediately stops orchestration
   - Example: Abort when detecting out-of-scope system access

9. **escalate** - Formally escalate to human or specialist agent
   - Use when discovery exceeds agent capability or requires expert review
   - Requires: escalation_level (human/senior_agent/specialist), escalation_urgency (critical/high/normal), escalation_context
   - If level=human and urgency=critical: BLOCKING until acknowledged
   - If level=senior_agent/specialist: Spawns agent with escalation metadata
   - Example: Escalate potential zero-day to security team

10. **rollback** - Revert workflow to a previous checkpoint
    - Use when current approach triggered defenses or failed
    - Requires: checkpoint_id OR rollback_to_node (revert to before that node)
    - Resets rolled-back nodes to "pending" status
    - NON-TERMINAL: Continues orchestration from checkpoint state
    - Example: Rollback after aggressive scan triggered IDS

11. **reflect** - Pause for self-evaluation of current strategy
    - Use periodically or after failures to assess approach
    - Requires: reflection_scope (mission/recent_decisions/specific_node)
    - Optional: reflection_prompt (guidance for evaluation)
    - DOES NOT count against iteration limit
    - Insights injected into subsequent observation prompts
    - Example: Reflect after 3 consecutive failures

12. **recall** - Query memory for relevant prior context
    - Use before major decisions to leverage prior discoveries
    - Requires: recall_query, recall_memory_tier (mission/long_term/both)
    - Optional: recall_filters (target_ip, time_range), inject_into_context
    - DOES NOT count against iteration limit
    - Results added to observation under "## Recalled Context"
    - Example: Recall previous findings for target 192.168.1.0/24

## Safety Guidelines

- **Always request_approval** before: exploit attempts, credential testing, data extraction
- **Always abort** when: out-of-scope access detected, unintended system modification
- **Consider escalate** when: potential zero-day, unusual findings, unclear authorization
- **Consider rollback** when: approach triggered defenses, need to try alternative strategy
- **Consider reflect** when: multiple failures, strategy seems ineffective, mid-mission checkpoint
- **Consider recall** when: targeting previously scanned systems, similar mission patterns

## Available Components Guidelines

You have access to the registered agents, tools, and plugins listed in the "Available Components"
section of each observation. Follow these rules:

1. **spawn_agent**: The agent_name MUST be one of the agents listed in "Available Components".
   Do NOT invent or guess agent names. Only use registered agents.

2. **Capability Matching**: When spawning agents, prefer agents whose capabilities match the
   mission objective. Check the "Capabilities" and "Target Types" columns.

3. **Health Status**: Avoid using components marked as "unhealthy" or "unavailable" unless
   no alternatives exist.

4. **No Hallucination**: If no suitable agent exists for a task, use the "complete" action
   with an appropriate stop_reason rather than inventing an agent name.

## Confidence Scoring

Provide a confidence score (0.0 to 1.0) for each decision:
- 0.9-1.0: Very confident (clear choice, strong signal)
- 0.7-0.9: Confident (good reasoning, some uncertainty)
- 0.5-0.7: Moderate (multiple valid options, choosing based on heuristics)
- 0.3-0.5: Uncertain (ambiguous state, making best guess)
- 0.0-0.3: Very uncertain (insufficient data, exploratory choice)

## Chain-of-Thought Reasoning

Always provide detailed reasoning that covers:
1. Current state assessment (what's been done, what's pending)
2. Dependency analysis (what's ready to execute)
3. Priority evaluation (which tasks are most valuable now)
4. Risk assessment (potential issues or blockers)
5. Decision rationale (why this specific action)

## Example Decision

{
  "reasoning": "Node 'recon' has completed successfully and discovered 3 open ports. Nodes 'port-scan-80' and 'port-scan-443' are now ready (dependencies satisfied). Both have equal priority, but port 443 likely has HTTPS which is higher value for credential extraction. Choosing to execute port-scan-443 first.",
  "action": "execute_agent",
  "target_node_id": "port-scan-443",
  "confidence": 0.85
}

Remember: Your decisions drive the entire mission. Be thoughtful, conservative with spawning, and always explain your reasoning clearly.`

// BuildObservationPrompt constructs a detailed context prompt from the current
// observation state. This prompt is sent to the LLM along with the system prompt
// to help it make informed orchestration decisions.
//
// The prompt is designed to be concise yet comprehensive, typically staying under
// 2k tokens to leave room for the system prompt and LLM response.
func BuildObservationPrompt(state *ObservationState) string {
	if state == nil {
		return "No observation state available. Cannot make decisions."
	}

	var sb strings.Builder
	sb.WriteString("# Current Mission State\n\n")

	// Mission overview
	sb.WriteString("## Mission Overview\n")
	sb.WriteString(fmt.Sprintf("**Objective**: %s\n", state.MissionInfo.Objective))
	sb.WriteString(fmt.Sprintf("**Mission ID**: %s\n", state.MissionInfo.ID))
	sb.WriteString(fmt.Sprintf("**Status**: %s\n", state.MissionInfo.Status))
	sb.WriteString(fmt.Sprintf("**Elapsed Time**: %s\n", state.MissionInfo.TimeElapsed))
	sb.WriteString(fmt.Sprintf("**Progress**: %d/%d nodes completed (%d failed)\n\n",
		state.GraphSummary.CompletedNodes, state.GraphSummary.TotalNodes, state.GraphSummary.FailedNodes))

	// Component inventory (if available) - show before ready nodes so LLM sees available components first
	if state.ComponentInventory != nil {
		formatter := NewInventoryPromptFormatter(WithMaxTokenBudget(500))
		// Extract mission target type from mission metadata
		missionTargetType := extractTargetType(state)
		inventorySection := formatter.Format(state.ComponentInventory, missionTargetType)
		sb.WriteString(inventorySection)
		sb.WriteString("\n")

		// Add target type guidance if available
		if missionTargetType != "" {
			guidance := getTargetTypeGuidance(missionTargetType)
			if guidance != "" {
				sb.WriteString("## Target Type Context\n")
				sb.WriteString(fmt.Sprintf("**Target Type**: %s\n", missionTargetType))
				sb.WriteString(guidance)
				sb.WriteString("\n\n")
			}
		}
	}

	// Payload context (if available) - show available attack payloads
	if state.PayloadContext != "" {
		sb.WriteString(state.PayloadContext)
		sb.WriteString("\n")
	}

	// Recalled context (if available) - show memory query results
	if state.RecalledContext != "" {
		sb.WriteString("## Recalled Context\n")
		sb.WriteString(state.RecalledContext)
		sb.WriteString("\n")
	}

	// Reflection insights (if available) - show recent self-evaluations
	if len(state.ReflectionInsights) > 0 {
		sb.WriteString("## Recent Reflection Insights\n")
		sb.WriteString("Recent self-evaluations to inform current decisions:\n\n")
		for _, insight := range state.ReflectionInsights {
			sb.WriteString(fmt.Sprintf("- **%s** (scope: %s, confidence: %.2f)\n",
				insight.CreatedAt.Format(time.RFC3339),
				insight.Scope,
				insight.Confidence))
			sb.WriteString(fmt.Sprintf("  Assessment: %s\n", insight.Assessment))
		}
		sb.WriteString("\n")
	}

	// Pending approvals (if any) - show operations awaiting human approval
	if len(state.PendingApprovals) > 0 {
		sb.WriteString("## Pending Approvals\n")
		sb.WriteString("The following operations are awaiting human approval:\n\n")
		for _, approval := range state.PendingApprovals {
			sb.WriteString(fmt.Sprintf("- **%s** (requested: %s)\n",
				approval.ID,
				approval.RequestedAt.Format(time.RFC3339)))
			sb.WriteString(fmt.Sprintf("  Node: %s\n", approval.NodeID))
			sb.WriteString(fmt.Sprintf("  Context: %s\n", approval.Context))
		}
		sb.WriteString("\n")
	}

	// Ready nodes (highest priority)
	if len(state.ReadyNodes) > 0 {
		sb.WriteString("## Ready Nodes (Dependencies Satisfied)\n")
		sb.WriteString("These nodes are ready to execute immediately:\n\n")
		for _, node := range state.ReadyNodes {
			sb.WriteString(fmt.Sprintf("- **%s** (%s)\n", node.ID, node.Type))
			if node.Name != "" {
				sb.WriteString(fmt.Sprintf("  - Name: %s\n", node.Name))
			}
			if node.AgentName != "" {
				sb.WriteString(fmt.Sprintf("  - Agent: %s\n", node.AgentName))
			}
			if node.ToolName != "" {
				sb.WriteString(fmt.Sprintf("  - Tool: %s\n", node.ToolName))
			}
			if node.Description != "" {
				sb.WriteString(fmt.Sprintf("  - Description: %s\n", node.Description))
			}
			if node.IsDynamic {
				sb.WriteString("  - (Dynamically spawned)\n")
			}
			sb.WriteString("\n")
		}
	} else {
		sb.WriteString("## Ready Nodes\nNo nodes are currently ready to execute.\n\n")
	}

	// Running nodes
	if len(state.RunningNodes) > 0 {
		sb.WriteString("## Currently Running Nodes\n")
		for _, node := range state.RunningNodes {
			sb.WriteString(fmt.Sprintf("- **%s** (%s", node.ID, node.Type))
			if node.AgentName != "" {
				sb.WriteString(fmt.Sprintf(": %s", node.AgentName))
			}
			if node.Attempt > 1 {
				sb.WriteString(fmt.Sprintf(", attempt %d", node.Attempt))
			}
			sb.WriteString(")\n")
		}
		sb.WriteString("\n")
	}

	// Pending nodes with dependencies
	if len(state.PendingNodes) > 0 {
		sb.WriteString("## Pending Nodes (Waiting for Dependencies)\n")
		sb.WriteString("These nodes are blocked until their dependencies complete:\n\n")
		for _, node := range state.PendingNodes {
			sb.WriteString(fmt.Sprintf("- **%s** (%s)\n", node.ID, node.Type))
			if node.Name != "" {
				sb.WriteString(fmt.Sprintf("  - Name: %s\n", node.Name))
			}
			if node.AgentName != "" {
				sb.WriteString(fmt.Sprintf("  - Agent: %s\n", node.AgentName))
			}
			if node.ToolName != "" {
				sb.WriteString(fmt.Sprintf("  - Tool: %s\n", node.ToolName))
			}
			if node.Description != "" {
				desc := truncate(node.Description, 200)
				sb.WriteString(fmt.Sprintf("  - Description: %s\n", desc))
			}

			// Show blocking dependencies
			if len(node.BlockedByDetails) > 0 {
				sb.WriteString("  - Blocked by:\n")
				for _, blocker := range node.BlockedByDetails {
					sb.WriteString(fmt.Sprintf("    - %s (%s): %s\n", blocker.Name, blocker.ID, blocker.Status))
				}
			} else if len(node.BlockedBy) > 0 {
				// Fallback if details not available
				sb.WriteString(fmt.Sprintf("  - Blocked by: %v\n", node.BlockedBy))
			}
			sb.WriteString("\n")
		}
	}

	// Completed nodes with outputs
	if len(state.CompletedNodes) > 0 {
		sb.WriteString("## Completed Nodes\n")
		sb.WriteString("These nodes have finished execution:\n\n")

		// Limit to 10 most recent if there are many
		completedToShow := state.CompletedNodes
		if len(completedToShow) > 10 {
			completedToShow = completedToShow[len(completedToShow)-10:]
			sb.WriteString(fmt.Sprintf("(Showing 10 most recent of %d completed nodes)\n\n", len(state.CompletedNodes)))
		}

		for _, node := range completedToShow {
			sb.WriteString(fmt.Sprintf("- **%s** (%s", node.ID, node.Type))
			if node.AgentName != "" {
				sb.WriteString(fmt.Sprintf(": %s", node.AgentName))
			} else if node.ToolName != "" {
				sb.WriteString(fmt.Sprintf(": %s", node.ToolName))
			}
			sb.WriteString(")")

			if node.Duration != "" {
				sb.WriteString(fmt.Sprintf(" - %s", node.Duration))
			}
			sb.WriteString("\n")

			if node.Name != "" {
				sb.WriteString(fmt.Sprintf("  - Name: %s\n", node.Name))
			}

			if node.OutputSummary != "" {
				sb.WriteString(fmt.Sprintf("  - Output: %s\n", node.OutputSummary))
			}

			if node.FindingsCount > 0 {
				sb.WriteString(fmt.Sprintf("  - Findings: %d", node.FindingsCount))
				if len(node.FindingsSeverity) > 0 {
					sb.WriteString(" (")
					first := true
					for severity, count := range node.FindingsSeverity {
						if !first {
							sb.WriteString(", ")
						}
						sb.WriteString(fmt.Sprintf("%s: %d", severity, count))
						first = false
					}
					sb.WriteString(")")
				}
				sb.WriteString("\n")
			}

			sb.WriteString("\n")
		}
	}

	// Workflow structure
	if state.WorkflowDAG != nil {
		dag := state.WorkflowDAG
		sb.WriteString("## Workflow Structure\n")
		sb.WriteString(fmt.Sprintf("Total nodes: %d\n", dag.TotalNodes))

		if len(dag.EntryPoints) > 0 {
			sb.WriteString(fmt.Sprintf("Entry points (no dependencies): %v\n", dag.EntryPoints))
		}

		if len(dag.ExitPoints) > 0 {
			sb.WriteString(fmt.Sprintf("Exit points (no dependents): %v\n", dag.ExitPoints))
		}

		if dag.CriticalPathLength > 0 {
			sb.WriteString(fmt.Sprintf("Critical path length: %d nodes\n", dag.CriticalPathLength))
		}

		// Show DAG edges if not too many
		if len(dag.Edges) > 0 && len(dag.Edges) <= 20 {
			sb.WriteString("\nDependency graph:\n")
			for nodeID, deps := range dag.Edges {
				if len(deps) > 0 {
					for _, depID := range deps {
						sb.WriteString(fmt.Sprintf("  %s -> %s\n", nodeID, depID))
					}
				}
			}
		} else if len(dag.Edges) > 20 {
			sb.WriteString(fmt.Sprintf("\n(Dependency graph has %d edges - too large to display)\n", len(dag.Edges)))
		}

		sb.WriteString("\n")
	}

	// Failed nodes
	if len(state.FailedNodes) > 0 {
		sb.WriteString("## Failed Nodes\n")
		for _, node := range state.FailedNodes {
			sb.WriteString(fmt.Sprintf("- **%s**", node.ID))
			if node.Name != "" {
				sb.WriteString(fmt.Sprintf(" (%s)", node.Name))
			}
			if node.AgentName != "" {
				sb.WriteString(fmt.Sprintf(" - Agent: %s", node.AgentName))
			}
			if node.Attempt > 0 {
				sb.WriteString(fmt.Sprintf(" (attempt %d)", node.Attempt))
			}
			sb.WriteString("\n")
		}
		sb.WriteString("\n")

		// Include failed execution details if present
		if state.FailedExecution != nil {
			sb.WriteString("### Recent Failure Details\n")
			sb.WriteString(fmt.Sprintf("- Node: %s (%s)\n", state.FailedExecution.NodeName, state.FailedExecution.NodeID))
			if state.FailedExecution.AgentName != "" {
				sb.WriteString(fmt.Sprintf("- Agent: %s\n", state.FailedExecution.AgentName))
			}
			sb.WriteString(fmt.Sprintf("- Attempt: %d/%d\n", state.FailedExecution.Attempt, state.FailedExecution.MaxRetries))
			sb.WriteString(fmt.Sprintf("- Error: %s\n", truncate(state.FailedExecution.Error, 200)))
			sb.WriteString(fmt.Sprintf("- Can retry: %t\n", state.FailedExecution.CanRetry))
			sb.WriteString("\n")
		}
	}

	// Recent decisions for context
	if len(state.RecentDecisions) > 0 {
		sb.WriteString("## Recent Decisions\n")
		for _, dec := range state.RecentDecisions {
			sb.WriteString(fmt.Sprintf("Iteration %d: %s", dec.Iteration, dec.Action))
			if dec.Target != "" {
				sb.WriteString(fmt.Sprintf(" -> %s", dec.Target))
			}
			sb.WriteString(fmt.Sprintf(" (confidence: %.2f)\n", dec.Confidence))
			if dec.Reasoning != "" {
				sb.WriteString(fmt.Sprintf("  Reasoning: %s\n", dec.Reasoning))
			}
		}
		sb.WriteString("\n")
	}

	// Resource constraints
	sb.WriteString("## Resource Constraints\n")
	sb.WriteString(fmt.Sprintf("- Max concurrent: %d\n", state.ResourceConstraints.MaxConcurrent))
	sb.WriteString(fmt.Sprintf("- Currently running: %d\n", state.ResourceConstraints.CurrentRunning))
	sb.WriteString(fmt.Sprintf("- Total iterations: %d\n", state.ResourceConstraints.TotalIterations))
	if state.ResourceConstraints.RemainingRetries > 0 {
		sb.WriteString(fmt.Sprintf("- Failed nodes available for retry: %d\n", state.ResourceConstraints.RemainingRetries))
	}
	if state.ResourceConstraints.ExecutionBudget != nil {
		if state.ResourceConstraints.ExecutionBudget.MaxExecutions > 0 {
			sb.WriteString(fmt.Sprintf("- Remaining executions: %d/%d\n",
				state.ResourceConstraints.ExecutionBudget.RemainingExecutions,
				state.ResourceConstraints.ExecutionBudget.MaxExecutions))
		}
	}
	sb.WriteString("\n")

	// Decision prompt
	sb.WriteString("## What Should We Do Next?\n\n")
	sb.WriteString("Based on the current state:\n")
	sb.WriteString("1. Analyze what has been accomplished\n")
	sb.WriteString("2. Consider which ready nodes are highest priority\n")
	sb.WriteString("3. Evaluate if any failed nodes should be retried\n")
	sb.WriteString("4. Determine if any parameters should be modified based on findings\n")
	sb.WriteString("5. Assess if the mission objective has been achieved\n")
	sb.WriteString("6. Consider if dynamic agent spawning would be valuable (use sparingly)\n\n")
	sb.WriteString("Provide your decision as a JSON object with detailed reasoning.\n")

	return sb.String()
}

// BuildDecisionSchema returns the JSON schema for the Decision struct.
// This schema can be used with LLM providers that support structured output
// (e.g., Anthropic's Claude with response_format, OpenAI's function calling).
//
// The schema enforces proper structure and validation constraints at the LLM level.
func BuildDecisionSchema() string {
	schema := map[string]interface{}{
		"$schema": "http://json-schema.org/draft-07/schema#",
		"type":    "object",
		"title":   "Orchestrator Decision",
		"description": "The orchestrator's decision about what to execute next in the workflow. " +
			"Must include reasoning, action, and confidence. Additional fields depend on the action type.",
		"required": []string{"reasoning", "action", "confidence"},
		"properties": map[string]interface{}{
			"reasoning": map[string]interface{}{
				"type": "string",
				"description": "Chain-of-thought reasoning explaining why this decision was made. " +
					"Should cover: current state, dependencies, priorities, risks, and rationale. " +
					"Minimum 50 characters.",
				"minLength": 50,
			},
			"action": map[string]interface{}{
				"type": "string",
				"enum": []string{
					"execute_agent",
					"skip_agent",
					"modify_params",
					"retry",
					"spawn_agent",
					"complete",
					"request_approval",
					"abort",
					"escalate",
					"rollback",
					"reflect",
					"recall",
				},
				"description": "The action to take. Must be one of the predefined actions.",
			},
			"target_node_id": map[string]interface{}{
				"type": "string",
				"description": "The workflow node ID to act upon. " +
					"Required for: execute_agent, skip_agent, modify_params, retry",
			},
			"modifications": map[string]interface{}{
				"type": "object",
				"description": "Parameter modifications for the target node. " +
					"Required for: modify_params action. " +
					"Keys are parameter names, values are new parameter values.",
				"additionalProperties": true,
			},
			"spawn_config": map[string]interface{}{
				"type":        "object",
				"description": "Configuration for spawning a new workflow node. Required for: spawn_agent action.",
				"required":    []string{"agent_name", "description", "task_config", "depends_on"},
				"properties": map[string]interface{}{
					"agent_name": map[string]interface{}{
						"type":        "string",
						"description": "The type of agent to spawn (must exist in agent registry)",
					},
					"description": map[string]interface{}{
						"type":        "string",
						"description": "Human-readable explanation of why this agent is being spawned",
						"minLength":   20,
					},
					"task_config": map[string]interface{}{
						"type":                 "object",
						"description":          "Configuration parameters for the spawned agent",
						"additionalProperties": true,
					},
					"depends_on": map[string]interface{}{
						"type": "array",
						"description": "List of node IDs that must complete before this spawned node runs. " +
							"Can be empty array if no dependencies.",
						"items": map[string]interface{}{
							"type": "string",
						},
					},
				},
			},
			"confidence": map[string]interface{}{
				"type":        "number",
				"description": "Confidence score between 0.0 and 1.0. Higher = more confident in this decision.",
				"minimum":     0.0,
				"maximum":     1.0,
			},
			"stop_reason": map[string]interface{}{
				"type": "string",
				"description": "Explanation of why the workflow is being marked complete. " +
					"Required for: complete action. " +
					"Should explain that the objective was achieved.",
				"minLength": 20,
			},
			"approval_context": map[string]interface{}{
				"type": "string",
				"description": "Human-readable description of what needs approval and why. " +
					"Required for: request_approval action.",
				"minLength": 20,
			},
			"approval_timeout": map[string]interface{}{
				"type": "string",
				"description": "Timeout duration for approval (e.g., '24h', '1h'). " +
					"Optional for: request_approval action. Defaults to 24h.",
			},
			"timeout_action": map[string]interface{}{
				"type": "string",
				"enum": []string{"reject", "skip"},
				"description": "Action to take when approval times out. " +
					"Optional for: request_approval action. Must be 'reject' or 'skip'.",
			},
			"abort_reason": map[string]interface{}{
				"type": "string",
				"description": "Explanation of why the mission is being aborted. " +
					"Required for: abort action.",
				"minLength": 20,
			},
			"abort_severity": map[string]interface{}{
				"type": "string",
				"enum": []string{"critical", "high", "medium"},
				"description": "Severity level of the abort condition. " +
					"Required for: abort action. Must be 'critical', 'high', or 'medium'.",
			},
			"cleanup_required": map[string]interface{}{
				"type": "boolean",
				"description": "Whether cleanup operations are needed after abort. " +
					"Optional for: abort action.",
			},
			"escalation_level": map[string]interface{}{
				"type": "string",
				"enum": []string{"human", "senior_agent", "specialist"},
				"description": "Who to escalate to. " +
					"Required for: escalate action. Must be 'human', 'senior_agent', or 'specialist'.",
			},
			"escalation_urgency": map[string]interface{}{
				"type": "string",
				"enum": []string{"critical", "high", "normal"},
				"description": "Urgency level of the escalation. " +
					"Required for: escalate action. Must be 'critical', 'high', or 'normal'.",
			},
			"escalation_context": map[string]interface{}{
				"type": "string",
				"description": "Context about what is being escalated and why. " +
					"Required for: escalate action.",
				"minLength": 20,
			},
			"checkpoint_id": map[string]interface{}{
				"type": "string",
				"description": "ID of the checkpoint to restore. " +
					"Required for: rollback action (if rollback_to_node not provided).",
			},
			"rollback_to_node": map[string]interface{}{
				"type": "string",
				"description": "Node ID to rollback to (reverts to state before this node). " +
					"Required for: rollback action (if checkpoint_id not provided).",
			},
			"reflection_scope": map[string]interface{}{
				"type": "string",
				"enum": []string{"mission", "recent_decisions", "specific_node"},
				"description": "Scope of reflection evaluation. " +
					"Required for: reflect action. Must be 'mission', 'recent_decisions', or 'specific_node'.",
			},
			"reflection_prompt": map[string]interface{}{
				"type": "string",
				"description": "Optional guidance for the reflection evaluation. " +
					"Optional for: reflect action.",
			},
			"recall_query": map[string]interface{}{
				"type": "string",
				"description": "Query string for memory search. " +
					"Required for: recall action.",
				"minLength": 5,
			},
			"recall_memory_tier": map[string]interface{}{
				"type": "string",
				"enum": []string{"mission", "long_term", "both"},
				"description": "Which memory tier(s) to query. " +
					"Required for: recall action. Must be 'mission', 'long_term', or 'both'.",
			},
			"recall_filters": map[string]interface{}{
				"type": "object",
				"description": "Optional filters for recall query (e.g., target_ip, time_range). " +
					"Optional for: recall action.",
				"additionalProperties": true,
			},
			"inject_into_context": map[string]interface{}{
				"type": "boolean",
				"description": "Whether to inject recalled context into next observation. " +
					"Optional for: recall action.",
			},
		},
		"allOf": []interface{}{
			// Conditional validation: execute_agent, skip_agent, retry require target_node_id
			map[string]interface{}{
				"if": map[string]interface{}{
					"properties": map[string]interface{}{
						"action": map[string]interface{}{
							"enum": []string{"execute_agent", "skip_agent", "retry"},
						},
					},
				},
				"then": map[string]interface{}{
					"required": []string{"target_node_id"},
				},
			},
			// Conditional validation: modify_params requires target_node_id and modifications
			map[string]interface{}{
				"if": map[string]interface{}{
					"properties": map[string]interface{}{
						"action": map[string]interface{}{
							"const": "modify_params",
						},
					},
				},
				"then": map[string]interface{}{
					"required": []string{"target_node_id", "modifications"},
				},
			},
			// Conditional validation: spawn_agent requires spawn_config
			map[string]interface{}{
				"if": map[string]interface{}{
					"properties": map[string]interface{}{
						"action": map[string]interface{}{
							"const": "spawn_agent",
						},
					},
				},
				"then": map[string]interface{}{
					"required": []string{"spawn_config"},
				},
			},
			// Conditional validation: complete requires stop_reason
			map[string]interface{}{
				"if": map[string]interface{}{
					"properties": map[string]interface{}{
						"action": map[string]interface{}{
							"const": "complete",
						},
					},
				},
				"then": map[string]interface{}{
					"required": []string{"stop_reason"},
				},
			},
			// Conditional validation: request_approval requires target_node_id and approval_context
			map[string]interface{}{
				"if": map[string]interface{}{
					"properties": map[string]interface{}{
						"action": map[string]interface{}{
							"const": "request_approval",
						},
					},
				},
				"then": map[string]interface{}{
					"required": []string{"target_node_id", "approval_context"},
				},
			},
			// Conditional validation: abort requires abort_reason and abort_severity
			map[string]interface{}{
				"if": map[string]interface{}{
					"properties": map[string]interface{}{
						"action": map[string]interface{}{
							"const": "abort",
						},
					},
				},
				"then": map[string]interface{}{
					"required": []string{"abort_reason", "abort_severity"},
				},
			},
			// Conditional validation: escalate requires escalation_level, escalation_urgency, and escalation_context
			map[string]interface{}{
				"if": map[string]interface{}{
					"properties": map[string]interface{}{
						"action": map[string]interface{}{
							"const": "escalate",
						},
					},
				},
				"then": map[string]interface{}{
					"required": []string{"escalation_level", "escalation_urgency", "escalation_context"},
				},
			},
			// Conditional validation: rollback requires checkpoint_id OR rollback_to_node
			map[string]interface{}{
				"if": map[string]interface{}{
					"properties": map[string]interface{}{
						"action": map[string]interface{}{
							"const": "rollback",
						},
					},
				},
				"then": map[string]interface{}{
					"anyOf": []interface{}{
						map[string]interface{}{
							"required": []string{"checkpoint_id"},
						},
						map[string]interface{}{
							"required": []string{"rollback_to_node"},
						},
					},
				},
			},
			// Conditional validation: reflect requires reflection_scope
			map[string]interface{}{
				"if": map[string]interface{}{
					"properties": map[string]interface{}{
						"action": map[string]interface{}{
							"const": "reflect",
						},
					},
				},
				"then": map[string]interface{}{
					"required": []string{"reflection_scope"},
				},
			},
			// Conditional validation: recall requires recall_query and recall_memory_tier
			map[string]interface{}{
				"if": map[string]interface{}{
					"properties": map[string]interface{}{
						"action": map[string]interface{}{
							"const": "recall",
						},
					},
				},
				"then": map[string]interface{}{
					"required": []string{"recall_query", "recall_memory_tier"},
				},
			},
		},
	}

	// Marshal to pretty JSON
	schemaJSON, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		// Should never happen with static schema, but handle gracefully
		return "{}"
	}

	return string(schemaJSON)
}

// FormatDecisionExample returns a formatted example of a valid Decision JSON.
// This can be included in prompts to guide the LLM toward proper formatting.
func FormatDecisionExample() string {
	example := map[string]interface{}{
		"reasoning": "Node 'recon' completed successfully and discovered 3 open ports. " +
			"Nodes 'port-scan-80' and 'port-scan-443' are ready (dependencies satisfied). " +
			"Port 443 (HTTPS) is higher priority for credential extraction. " +
			"No resource constraints. Executing port-scan-443.",
		"action":         "execute_agent",
		"target_node_id": "port-scan-443",
		"confidence":     0.85,
	}

	exampleJSON, _ := json.MarshalIndent(example, "", "  ")
	return string(exampleJSON)
}

// FormatCompleteExample returns an example of a complete decision.
func FormatCompleteExample() string {
	example := map[string]interface{}{
		"reasoning": "All reconnaissance, scanning, and exploitation nodes have completed. " +
			"We discovered 5 high-severity findings including prompt injection and data extraction vulnerabilities. " +
			"The mission objective to 'discover security vulnerabilities in target LLM' has been achieved. " +
			"No additional nodes would provide significant value. Marking mission complete.",
		"action":      "complete",
		"confidence":  0.95,
		"stop_reason": "Mission objective achieved: discovered 5 high-severity vulnerabilities in target system",
	}

	exampleJSON, _ := json.MarshalIndent(example, "", "  ")
	return string(exampleJSON)
}

// FormatSpawnExample returns an example of a spawn_agent decision.
func FormatSpawnExample() string {
	example := map[string]interface{}{
		"reasoning": "Recon discovered an unexpected GraphQL endpoint at /graphql. " +
			"This was not part of the original workflow. " +
			"GraphQL often has introspection vulnerabilities. " +
			"Spawning a specialized GraphQL introspection agent to explore this attack surface.",
		"action":     "spawn_agent",
		"confidence": 0.78,
		"spawn_config": map[string]interface{}{
			"agent_name":  "graphql-introspector",
			"description": "Spawned to analyze unexpected GraphQL endpoint discovered during reconnaissance",
			"task_config": map[string]interface{}{
				"endpoint": "https://target.example.com/graphql",
				"goal":     "Perform introspection and identify schema vulnerabilities",
			},
			"depends_on": []string{"recon"},
		},
	}

	exampleJSON, _ := json.MarshalIndent(example, "", "  ")
	return string(exampleJSON)
}

// FormatRequestApprovalExample returns an example of a request_approval decision.
func FormatRequestApprovalExample() string {
	example := map[string]interface{}{
		"reasoning": "The sql-injection-scanner node is ready and has identified a potential SQL injection point. " +
			"Before executing exploit payloads against the production database, human approval is required. " +
			"This is a destructive operation that could impact data integrity.",
		"action":           "request_approval",
		"target_node_id":   "sql-injection-exploit",
		"approval_context": "Ready to execute SQL injection payloads against production database endpoint /api/v2/users. Target has confirmed SQLi vulnerability. Requesting approval before running exploitation payloads that may modify database state.",
		"approval_timeout": "4h",
		"timeout_action":   "skip",
		"confidence":       0.90,
	}

	exampleJSON, _ := json.MarshalIndent(example, "", "  ")
	return string(exampleJSON)
}

// FormatAbortExample returns an example of an abort decision.
func FormatAbortExample() string {
	example := map[string]interface{}{
		"reasoning": "During reconnaissance, the agent discovered access to systems outside the authorized scope. " +
			"The target 10.0.0.50 responded but is not in the approved target list (10.0.0.1-10.0.0.25). " +
			"This constitutes a scope violation and the mission must be immediately terminated.",
		"action":           "abort",
		"abort_reason":     "Scope violation detected: gained unintended access to out-of-scope system 10.0.0.50. Target is outside authorized range 10.0.0.1-10.0.0.25. Immediate mission termination required.",
		"abort_severity":   "critical",
		"cleanup_required": true,
		"confidence":       0.99,
	}

	exampleJSON, _ := json.MarshalIndent(example, "", "  ")
	return string(exampleJSON)
}

// FormatEscalateExample returns an example of an escalate decision.
func FormatEscalateExample() string {
	example := map[string]interface{}{
		"reasoning": "The vulnerability scanner discovered what appears to be a zero-day vulnerability in the authentication system. " +
			"The pattern doesn't match any known CVE and could have significant impact. " +
			"This requires expert human analysis before proceeding.",
		"action":             "escalate",
		"escalation_level":   "human",
		"escalation_urgency": "critical",
		"escalation_context": "Discovered potential zero-day authentication bypass in /api/auth/token endpoint. Novel attack vector not matching known CVEs. Allows unauthenticated access to admin functions. Requires security team review before disclosure or further testing.",
		"confidence":         0.85,
	}

	exampleJSON, _ := json.MarshalIndent(example, "", "  ")
	return string(exampleJSON)
}

// FormatRollbackExample returns an example of a rollback decision.
func FormatRollbackExample() string {
	example := map[string]interface{}{
		"reasoning": "The aggressive port scan triggered the target's IDS and we're now being rate-limited. " +
			"Multiple subsequent operations have failed with connection timeouts. " +
			"Rolling back to checkpoint before the scan to try a stealthier approach.",
		"action":           "rollback",
		"rollback_to_node": "recon-passive",
		"confidence":       0.75,
	}

	exampleJSON, _ := json.MarshalIndent(example, "", "  ")
	return string(exampleJSON)
}

// FormatReflectExample returns an example of a reflect decision.
func FormatReflectExample() string {
	example := map[string]interface{}{
		"reasoning": "We've had 3 consecutive node failures across different attack vectors. " +
			"The current strategy of direct enumeration isn't working. " +
			"Taking a step back to evaluate the overall approach before proceeding.",
		"action":           "reflect",
		"reflection_scope": "recent_decisions",
		"reflection_prompt": "Analyze the last 5 decisions and their outcomes. Why are attacks failing? " +
			"Are we missing reconnaissance data? Should we pivot to a different attack surface?",
		"confidence": 0.70,
	}

	exampleJSON, _ := json.MarshalIndent(example, "", "  ")
	return string(exampleJSON)
}

// FormatRecallExample returns an example of a recall decision.
func FormatRecallExample() string {
	example := map[string]interface{}{
		"reasoning": "We're targeting a system in the 192.168.1.0/24 network that was scanned in a previous mission. " +
			"Before running reconnaissance again, let's check if we have relevant prior findings.",
		"action":             "recall",
		"recall_query":       "findings vulnerabilities 192.168.1.0/24 web application authentication",
		"recall_memory_tier": "both",
		"recall_filters": map[string]string{
			"target_ip": "192.168.1.0/24",
		},
		"inject_into_context": true,
		"confidence":          0.80,
	}

	exampleJSON, _ := json.MarshalIndent(example, "", "  ")
	return string(exampleJSON)
}

// BuildFullPrompt combines the system prompt, observation prompt, and examples
// into a complete prompt ready to send to the LLM.
//
// This is a convenience function that ensures proper formatting and ordering.
func BuildFullPrompt(state *ObservationState, includeExamples bool) string {
	var sb strings.Builder

	// System prompt
	sb.WriteString(SystemPrompt)
	sb.WriteString("\n\n")
	sb.WriteString("---\n\n")

	// Observation state
	sb.WriteString(BuildObservationPrompt(state))
	sb.WriteString("\n")

	// Optional examples
	if includeExamples {
		sb.WriteString("---\n\n")
		sb.WriteString("## Example Decisions\n\n")
		sb.WriteString("### Example 1: Execute Agent\n```json\n")
		sb.WriteString(FormatDecisionExample())
		sb.WriteString("\n```\n\n")
		sb.WriteString("### Example 2: Complete Mission\n```json\n")
		sb.WriteString(FormatCompleteExample())
		sb.WriteString("\n```\n\n")
		sb.WriteString("### Example 3: Spawn Agent\n```json\n")
		sb.WriteString(FormatSpawnExample())
		sb.WriteString("\n```\n\n")
		sb.WriteString("### Example 4: Request Approval (Human-in-the-Loop)\n```json\n")
		sb.WriteString(FormatRequestApprovalExample())
		sb.WriteString("\n```\n\n")
		sb.WriteString("### Example 5: Abort Mission (Safety Violation)\n```json\n")
		sb.WriteString(FormatAbortExample())
		sb.WriteString("\n```\n\n")
		sb.WriteString("### Example 6: Escalate to Human\n```json\n")
		sb.WriteString(FormatEscalateExample())
		sb.WriteString("\n```\n\n")
		sb.WriteString("### Example 7: Rollback to Checkpoint\n```json\n")
		sb.WriteString(FormatRollbackExample())
		sb.WriteString("\n```\n\n")
		sb.WriteString("### Example 8: Reflect on Strategy\n```json\n")
		sb.WriteString(FormatReflectExample())
		sb.WriteString("\n```\n\n")
		sb.WriteString("### Example 9: Recall from Memory\n```json\n")
		sb.WriteString(FormatRecallExample())
		sb.WriteString("\n```\n\n")
	}

	sb.WriteString("---\n\n")
	sb.WriteString("Now, provide your decision based on the current mission state above.\n")

	return sb.String()
}

// EstimatePromptTokens provides a rough estimate of token count for the prompt.
// This uses a simple heuristic: ~4 characters per token (GPT standard).
//
// This is useful for staying under context window limits and optimizing prompt size.
func EstimatePromptTokens(prompt string) int {
	return len(prompt) / 4
}

// truncate is a helper function to truncate strings to a maximum length
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return "..."
	}
	return s[:maxLen-3] + "..."
}

// extractTargetType extracts the target type from mission observation state.
// It checks mission metadata for target_type field, with fallback to other sources.
func extractTargetType(state *ObservationState) string {
	if state == nil {
		return ""
	}

	// TODO: In future, extract from state.MissionInfo when metadata is exposed
	// For now, we would need access to the full mission object with metadata
	// This is a placeholder for when mission metadata is included in ObservationState

	// Check if target context has type information
	// This would be populated if the mission includes target metadata
	return ""
}

// getTargetTypeGuidance returns specialized guidance for different target types.
// This helps the LLM make more informed decisions based on the target system type.
func getTargetTypeGuidance(targetType string) string {
	switch strings.ToLower(targetType) {
	case "llm":
		return "Focus on prompt injection, jailbreaking, and model manipulation techniques. " +
			"Consider attacks like: context stuffing, delimiter injection, role confusion, " +
			"system prompt extraction, and adversarial examples."

	case "rag":
		return "Focus on retrieval poisoning, context injection, and knowledge base attacks. " +
			"Consider attacks like: document injection, citation manipulation, " +
			"knowledge base poisoning, and context window overflow."

	case "agent":
		return "Focus on tool misuse, action hijacking, and agent confusion attacks. " +
			"Consider attacks like: tool chaining exploits, delegation hijacking, " +
			"goal subversion, and memory poisoning."

	case "api":
		return "Focus on input validation, authentication bypass, and API abuse. " +
			"Consider attacks like: parameter tampering, rate limit bypass, " +
			"authorization flaws, and injection attacks."

	case "web":
		return "Focus on web application vulnerabilities and client-side attacks. " +
			"Consider attacks like: XSS, CSRF, SQLi, authentication bypass, " +
			"and business logic flaws."

	case "network":
		return "Focus on network-level vulnerabilities and service enumeration. " +
			"Consider attacks like: port scanning, service fingerprinting, " +
			"protocol exploitation, and lateral movement."

	default:
		return ""
	}
}
