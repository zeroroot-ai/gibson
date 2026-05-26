package plan_test

import (
	"encoding/json"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/agent"
	"github.com/zeroroot-ai/gibson/internal/plan"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// ExampleExecutionStep_tool demonstrates creating a tool execution step
func ExampleExecutionStep_tool() {
	step := plan.ExecutionStep{
		ID:          types.NewID(),
		Sequence:    1,
		Type:        plan.StepTypeTool,
		Name:        "Port Scan",
		Description: "Scan target for open ports",
		ToolName:    "nmap",
		ToolInput: map[string]any{
			"target": "192.168.1.1",
			"ports":  "1-1000",
		},
		RiskLevel:        plan.RiskLevelLow,
		RequiresApproval: false,
		Status:           plan.StepStatusPending,
		DependsOn:        []types.ID{},
		Metadata: map[string]any{
			"timeout": "5m",
		},
	}

	data, _ := json.MarshalIndent(step, "", "  ")
	fmt.Printf("Tool Step:\n%s\n", data)
}

// ExampleExecutionStep_agent demonstrates creating an agent execution step
func ExampleExecutionStep_agent() {
	task := agent.NewTask(
		"Analyze vulnerabilities",
		"Review scan results and identify critical vulnerabilities",
		map[string]any{
			"scan_results": "scan_id_123",
		},
	)

	step := plan.ExecutionStep{
		ID:          types.NewID(),
		Sequence:    2,
		Type:        plan.StepTypeAgent,
		Name:        "Vulnerability Analysis",
		Description: "Analyze scan results for vulnerabilities",
		AgentName:   "vulnerability-analyzer",
		AgentTask:   &task,
		RiskLevel:   plan.RiskLevelMedium,
		Status:      plan.StepStatusPending,
	}

	data, _ := json.MarshalIndent(step, "", "  ")
	fmt.Printf("Agent Step:\n%s\n", data)
}

// ExampleExecutionStep_condition demonstrates creating a conditional step
func ExampleExecutionStep_condition() {
	step := plan.ExecutionStep{
		ID:          types.NewID(),
		Sequence:    3,
		Type:        plan.StepTypeCondition,
		Name:        "Check Vulnerability Severity",
		Description: "Branch based on vulnerability severity",
		Condition: &plan.StepCondition{
			Expression: "vulnerabilities.severity == 'critical'",
			TrueSteps:  []types.ID{types.NewID()},
			FalseSteps: []types.ID{types.NewID()},
		},
		RiskLevel: plan.RiskLevelLow,
		Status:    plan.StepStatusPending,
	}

	data, _ := json.MarshalIndent(step, "", "  ")
	fmt.Printf("Condition Step:\n%s\n", data)
}

// ExampleExecutionStep_parallel demonstrates creating a parallel execution step
func ExampleExecutionStep_parallel() {
	step := plan.ExecutionStep{
		ID:          types.NewID(),
		Sequence:    4,
		Type:        plan.StepTypeParallel,
		Name:        "Parallel Scans",
		Description: "Run multiple scans in parallel",
		ParallelSteps: []plan.ExecutionStep{
			{
				ID:       types.NewID(),
				Sequence: 1,
				Type:     plan.StepTypeTool,
				Name:     "Port Scan",
				ToolName: "nmap",
				ToolInput: map[string]any{
					"target": "192.168.1.1",
				},
				RiskLevel: plan.RiskLevelLow,
				Status:    plan.StepStatusPending,
			},
			{
				ID:       types.NewID(),
				Sequence: 2,
				Type:     plan.StepTypeTool,
				Name:     "Web Scan",
				ToolName: "nikto",
				ToolInput: map[string]any{
					"url": "http://192.168.1.1",
				},
				RiskLevel: plan.RiskLevelLow,
				Status:    plan.StepStatusPending,
			},
		},
		RiskLevel: plan.RiskLevelMedium,
		Status:    plan.StepStatusPending,
	}

	data, _ := json.MarshalIndent(step, "", "  ")
	fmt.Printf("Parallel Step:\n%s\n", data)
}

// ExampleRiskLevel_IsHighRisk demonstrates the IsHighRisk helper method
func ExampleRiskLevel_IsHighRisk() {
	riskLevels := []plan.RiskLevel{
		plan.RiskLevelLow,
		plan.RiskLevelMedium,
		plan.RiskLevelHigh,
		plan.RiskLevelCritical,
	}

	for _, level := range riskLevels {
		fmt.Printf("%s is high risk: %v\n", level, level.IsHighRisk())
	}

	// Output:
	// low is high risk: false
	// medium is high risk: false
	// high is high risk: true
	// critical is high risk: true
}

// ExampleStepStatus_IsTerminal demonstrates the IsTerminal helper method
func ExampleStepStatus_IsTerminal() {
	statuses := []plan.StepStatus{
		plan.StepStatusPending,
		plan.StepStatusApproved,
		plan.StepStatusRunning,
		plan.StepStatusCompleted,
		plan.StepStatusFailed,
		plan.StepStatusSkipped,
	}

	for _, status := range statuses {
		fmt.Printf("%s is terminal: %v\n", status, status.IsTerminal())
	}

	// Output:
	// pending is terminal: false
	// approved is terminal: false
	// running is terminal: false
	// completed is terminal: true
	// failed is terminal: true
	// skipped is terminal: true
}
