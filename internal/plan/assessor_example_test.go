package plan_test

import (
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/plan"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// ExampleRiskAssessor demonstrates how to use the RiskAssessor to evaluate
// execution steps for risk levels and approval requirements.
func ExampleRiskAssessor() {
	// Create a risk assessor with default rules
	assessor := plan.NewRiskAssessor(plan.WithDefaultRules())

	// Create a high-risk step (destructive operation)
	step := &plan.ExecutionStep{
		ID:          types.NewID(),
		Name:        "Delete temporary files",
		Description: "Remove all files in the /tmp directory",
		Type:        plan.StepTypeTool,
	}

	// Assess the step
	assessment := assessor.AssessStep(step, plan.RiskContext{})

	fmt.Printf("Risk Level: %s\n", assessment.Level)
	fmt.Printf("Requires Approval: %t\n", assessment.RequiresApproval)
	fmt.Printf("Number of Risk Factors: %d\n", len(assessment.Factors))

	// Output:
	// Risk Level: high
	// Requires Approval: true
	// Number of Risk Factors: 7
}

// ExampleRiskAssessor_customRule demonstrates how to add custom risk rules
// to the assessor.
func ExampleRiskAssessor_customRule() {
	// Create a custom rule that checks for database operations
	databaseRule := plan.RiskRule{
		Name:        "database_modification",
		Description: "Evaluates whether the step modifies database",
		Evaluate: func(step *plan.ExecutionStep, ctx plan.RiskContext) (plan.RiskLevel, string) {
			if step.ToolName == "database" || step.PluginName == "db" {
				return plan.RiskLevelHigh, "step modifies database"
			}
			return plan.RiskLevelLow, ""
		},
	}

	// Create assessor with both default rules and custom rule
	assessor := plan.NewRiskAssessor(
		plan.WithDefaultRules(),
		plan.WithRule(databaseRule),
	)

	// Create a database modification step
	step := &plan.ExecutionStep{
		ID:       types.NewID(),
		Name:     "Update user records",
		Type:     plan.StepTypeTool,
		ToolName: "database",
	}

	// Assess the step
	assessment := assessor.AssessStep(step, plan.RiskContext{})

	fmt.Printf("Risk Level: %s\n", assessment.Level)
	fmt.Printf("Requires Approval: %t\n", assessment.RequiresApproval)

	// Output:
	// Risk Level: high
	// Requires Approval: true
}

// ExampleRiskAssessor_AssessPlan demonstrates how to assess an entire
// execution plan for risk.
func ExampleRiskAssessor_AssessPlan() {
	assessor := plan.NewRiskAssessor(plan.WithDefaultRules())

	// Create a plan with multiple steps
	execPlan := &plan.ExecutionPlan{
		ID:        types.NewID(),
		MissionID: types.NewID(),
		Steps: []plan.ExecutionStep{
			{
				ID:          types.NewID(),
				Name:        "Reconnaissance",
				Description: "Gather information about the target",
				Type:        plan.StepTypeTool,
			},
			{
				ID:          types.NewID(),
				Name:        "Extract credentials",
				Description: "Download password hashes from the system",
				Type:        plan.StepTypeTool,
			},
			{
				ID:          types.NewID(),
				Name:        "Escalate privileges",
				Description: "Use sudo to gain root access",
				Type:        plan.StepTypeTool,
			},
		},
	}

	// Assess the entire plan
	summary := assessor.AssessPlan(execPlan, plan.RiskContext{})

	fmt.Printf("Overall Risk Level: %s\n", summary.OverallLevel)
	fmt.Printf("High Risk Steps: %d\n", summary.HighRiskSteps)
	fmt.Printf("Critical Steps: %d\n", summary.CriticalSteps)
	fmt.Printf("Approval Required: %t\n", summary.ApprovalRequired)

	// Output:
	// Overall Risk Level: critical
	// High Risk Steps: 3
	// Critical Steps: 1
	// Approval Required: true
}

// ExampleWithDefaultRules demonstrates the default risk rules that are
// included with the assessor.
func ExampleWithDefaultRules() {
	assessor := plan.NewRiskAssessor(plan.WithDefaultRules())

	// Test various scenarios
	scenarios := []struct {
		name        string
		description string
		expectedMin plan.RiskLevel
	}{
		{"Safe operation", "Read a configuration file", plan.RiskLevelLow},
		{"Delete files", "Remove old logs", plan.RiskLevelHigh},
		{"Sudo command", "Run command as root", plan.RiskLevelCritical},
		{"Network change", "Update firewall rules", plan.RiskLevelMedium},
	}

	for _, scenario := range scenarios {
		step := &plan.ExecutionStep{
			ID:          types.NewID(),
			Name:        scenario.name,
			Description: scenario.description,
			Type:        plan.StepTypeTool,
		}

		assessment := assessor.AssessStep(step, plan.RiskContext{})
		fmt.Printf("%s: %s (approval: %t)\n",
			scenario.name,
			assessment.Level,
			assessment.RequiresApproval)
	}

	// Output:
	// Safe operation: low (approval: false)
	// Delete files: high (approval: true)
	// Sudo command: critical (approval: true)
	// Network change: medium (approval: false)
}
