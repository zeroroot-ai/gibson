package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// DebugLogWriter implements DecisionLogWriter for raw debug output to stdout.
// It prints all orchestrator data in plain text for debugging purposes.
type DebugLogWriter struct {
	w io.Writer
}

// NewDebugLogWriter creates a new DebugLogWriter that writes to stdout.
func NewDebugLogWriter() *DebugLogWriter {
	return &DebugLogWriter{w: os.Stdout}
}

// NewDebugLogWriterWithOutput creates a DebugLogWriter with a custom writer.
// Useful for testing or redirecting output.
func NewDebugLogWriterWithOutput(w io.Writer) *DebugLogWriter {
	return &DebugLogWriter{w: w}
}

// LogObservation prints the observation state at the start of an iteration.
// This is called before Think to show what the orchestrator sees.
func (d *DebugLogWriter) LogObservation(iteration int, missionID string, state *ObservationState) {
	if state == nil {
		return
	}

	d.printIterationHeader(iteration, missionID)
	d.printSection("OBSERVE")

	fmt.Fprintf(d.w, "Mission: %s (%s)\n", state.MissionInfo.Name, state.MissionInfo.ID)
	fmt.Fprintf(d.w, "Objective: %s\n", state.MissionInfo.Objective)
	fmt.Fprintf(d.w, "Status: %s\n", state.MissionInfo.Status)
	fmt.Fprintf(d.w, "Observed at: %s\n\n", state.ObservedAt.Format(time.RFC3339))

	// Graph summary
	fmt.Fprintf(d.w, "Graph Summary:\n")
	fmt.Fprintf(d.w, "  Total nodes: %d\n", state.GraphSummary.TotalNodes)
	fmt.Fprintf(d.w, "  Completed: %d\n", state.GraphSummary.CompletedNodes)
	fmt.Fprintf(d.w, "  Failed: %d\n", state.GraphSummary.FailedNodes)
	fmt.Fprintf(d.w, "  Pending: %d\n", state.GraphSummary.PendingNodes)
	fmt.Fprintf(d.w, "  Total decisions: %d\n", state.GraphSummary.TotalDecisions)
	fmt.Fprintf(d.w, "  Total executions: %d\n\n", state.GraphSummary.TotalExecutions)

	// Node states
	d.printNodeList("Ready nodes", state.ReadyNodes)
	d.printNodeList("Running nodes", state.RunningNodes)
	d.printCompletedNodeList("Completed nodes", state.CompletedNodes)
	d.printNodeList("Failed nodes", state.FailedNodes)

	// Resource constraints
	fmt.Fprintf(d.w, "Resource Constraints:\n")
	fmt.Fprintf(d.w, "  Max concurrent: %d\n", state.ResourceConstraints.MaxConcurrent)
	fmt.Fprintf(d.w, "  Current running: %d\n", state.ResourceConstraints.CurrentRunning)
	fmt.Fprintf(d.w, "  Total iterations: %d\n", state.ResourceConstraints.TotalIterations)
	fmt.Fprintf(d.w, "  Time elapsed: %s\n", state.ResourceConstraints.TimeElapsed)
	if state.ResourceConstraints.ExecutionBudget != nil {
		budget := state.ResourceConstraints.ExecutionBudget
		fmt.Fprintf(d.w, "  Execution budget: %d/%d remaining\n",
			budget.RemainingExecutions, budget.MaxExecutions)
		if budget.MaxTokens > 0 {
			fmt.Fprintf(d.w, "  Token budget: %d/%d used\n", budget.UsedTokens, budget.MaxTokens)
		}
	}
	fmt.Fprintln(d.w)

	// Failed execution details if present
	if state.FailedExecution != nil {
		fmt.Fprintf(d.w, "Failed Execution:\n")
		fmt.Fprintf(d.w, "  Node: %s (%s)\n", state.FailedExecution.NodeID, state.FailedExecution.NodeName)
		fmt.Fprintf(d.w, "  Agent: %s\n", state.FailedExecution.AgentName)
		fmt.Fprintf(d.w, "  Error: %s\n", state.FailedExecution.Error)
		fmt.Fprintf(d.w, "  Attempt: %d/%d\n", state.FailedExecution.Attempt, state.FailedExecution.MaxRetries)
		fmt.Fprintf(d.w, "  Can retry: %v\n\n", state.FailedExecution.CanRetry)
	}
}

// LogDecision implements DecisionLogWriter. It prints the full LLM interaction
// including prompt, response, tokens, and the parsed decision.
func (d *DebugLogWriter) LogDecision(ctx context.Context, decision *Decision, result *ThinkResult, iteration int, missionID string) error {
	if decision == nil || result == nil {
		return nil
	}

	d.printSection("THINK")

	// LLM metadata
	fmt.Fprintf(d.w, "Model: %s\n", result.Model)
	fmt.Fprintf(d.w, "Tokens: %d prompt + %d completion = %d total\n",
		result.PromptTokens, result.CompletionTokens, result.TotalTokens)
	fmt.Fprintf(d.w, "Latency: %s\n", result.Latency)
	if result.RetryCount > 0 {
		fmt.Fprintf(d.w, "Retries: %d\n", result.RetryCount)
	}
	fmt.Fprintln(d.w)

	// Raw LLM response - prefix with space to prevent log collectors from parsing as JSON
	fmt.Fprintf(d.w, "--- RAW RESPONSE ---\n %s\n--- END RESPONSE ---\n\n", result.RawResponse)

	// Parsed decision
	d.printSection("DECIDE")

	fmt.Fprintf(d.w, "Action: %s\n", decision.Action)
	if decision.TargetNodeID != "" {
		fmt.Fprintf(d.w, "Target: %s\n", decision.TargetNodeID)
	}
	fmt.Fprintf(d.w, "Confidence: %.2f\n", decision.Confidence)
	fmt.Fprintf(d.w, "Reasoning: %s\n", decision.Reasoning)

	if decision.StopReason != "" {
		fmt.Fprintf(d.w, "Stop reason: %s\n", decision.StopReason)
	}

	if decision.SpawnConfig != nil {
		fmt.Fprintf(d.w, "Spawn config:\n")
		d.printJSON("  ", decision.SpawnConfig)
	}

	if len(decision.Modifications) > 0 {
		fmt.Fprintf(d.w, "Modifications:\n")
		d.printJSON("  ", decision.Modifications)
	}

	fmt.Fprintln(d.w)
	return nil
}

// LogAction implements DecisionLogWriter. It prints action execution details.
func (d *DebugLogWriter) LogAction(ctx context.Context, action *ActionResult, iteration int, missionID string) error {
	if action == nil {
		return nil
	}

	d.printSection("ACT")

	fmt.Fprintf(d.w, "Action: %s\n", action.Action)
	if action.TargetNodeID != "" {
		fmt.Fprintf(d.w, "Target: %s\n", action.TargetNodeID)
	}
	fmt.Fprintf(d.w, "Terminal: %v\n", action.IsTerminal)

	if action.Error != nil {
		fmt.Fprintf(d.w, "Status: FAILED\n")
		fmt.Fprintf(d.w, "Error: %s\n", action.Error)
	} else {
		fmt.Fprintf(d.w, "Status: SUCCESS\n")
	}

	// Agent execution details
	if action.AgentExecution != nil {
		exec := action.AgentExecution
		fmt.Fprintf(d.w, "\nAgent Execution:\n")
		fmt.Fprintf(d.w, "  ID: %s\n", exec.ID)
		fmt.Fprintf(d.w, "  Workflow Node: %s\n", exec.WorkflowNodeID)
		fmt.Fprintf(d.w, "  Status: %s\n", exec.Status)
		fmt.Fprintf(d.w, "  Attempt: %d\n", exec.Attempt)
		if !exec.StartedAt.IsZero() {
			fmt.Fprintf(d.w, "  Started: %s\n", exec.StartedAt.Format(time.RFC3339))
		}
		if exec.CompletedAt != nil {
			fmt.Fprintf(d.w, "  Completed: %s\n", exec.CompletedAt.Format(time.RFC3339))
		}
		if exec.Error != "" {
			fmt.Fprintf(d.w, "  Error: %s\n", exec.Error)
			if exec.ErrorClass != "" {
				fmt.Fprintf(d.w, "  Error class: %s\n", exec.ErrorClass)
			}
		}
	}

	// New spawned node
	if action.NewNode != nil {
		fmt.Fprintf(d.w, "\nSpawned Node:\n")
		fmt.Fprintf(d.w, "  ID: %s\n", action.NewNode.ID)
		fmt.Fprintf(d.w, "  Agent: %s\n", action.NewNode.AgentName)
		fmt.Fprintf(d.w, "  Status: %s\n", action.NewNode.Status)
	}

	// Metadata
	if len(action.Metadata) > 0 {
		fmt.Fprintf(d.w, "\nMetadata:\n")
		d.printJSON("  ", action.Metadata)
	}

	fmt.Fprintln(d.w)
	d.printSeparator()
	return nil
}

// printIterationHeader prints the iteration header banner.
func (d *DebugLogWriter) printIterationHeader(iteration int, missionID string) {
	d.printSeparator()
	fmt.Fprintf(d.w, "ITERATION %d | Mission: %s\n", iteration, missionID)
	d.printSeparator()
	fmt.Fprintln(d.w)
}

// printSection prints a section header.
func (d *DebugLogWriter) printSection(name string) {
	fmt.Fprintf(d.w, "=== %s ===\n", name)
}

// printSeparator prints a horizontal separator line.
func (d *DebugLogWriter) printSeparator() {
	fmt.Fprintln(d.w, strings.Repeat("=", 80))
}

// printNodeList prints a list of node summaries.
func (d *DebugLogWriter) printNodeList(label string, nodes []NodeSummary) {
	if len(nodes) == 0 {
		fmt.Fprintf(d.w, "%s: [none]\n", label)
		return
	}

	fmt.Fprintf(d.w, "%s:\n", label)
	for _, node := range nodes {
		fmt.Fprintf(d.w, "  - %s (%s): %s\n", node.ID, node.AgentName, node.Status)
	}
	fmt.Fprintln(d.w)
}

// printCompletedNodeList prints a list of completed nodes with their enhanced details.
func (d *DebugLogWriter) printCompletedNodeList(label string, nodes []CompletedNodeSummary) {
	if len(nodes) == 0 {
		fmt.Fprintf(d.w, "%s: [none]\n", label)
		return
	}

	fmt.Fprintf(d.w, "%s:\n", label)
	for _, node := range nodes {
		fmt.Fprintf(d.w, "  - %s (%s): %s", node.ID, node.AgentName, node.Status)
		if node.Duration != "" {
			fmt.Fprintf(d.w, " [%s]", node.Duration)
		}
		fmt.Fprintln(d.w)
	}
	fmt.Fprintln(d.w)
}

// printJSON prints a value as indented JSON.
func (d *DebugLogWriter) printJSON(prefix string, v any) {
	data, err := json.MarshalIndent(v, prefix, "  ")
	if err != nil {
		fmt.Fprintf(d.w, "%s<error marshaling: %v>\n", prefix, err)
		return
	}
	fmt.Fprintf(d.w, "%s%s\n", prefix, string(data))
}

// Compile-time interface check
var _ DecisionLogWriter = (*DebugLogWriter)(nil)
