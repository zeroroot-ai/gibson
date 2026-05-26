package plan

import (
	"testing"

	"github.com/zeroroot-ai/gibson/internal/types"
)

func TestNewRiskAssessor(t *testing.T) {
	t.Run("creates assessor with no rules", func(t *testing.T) {
		assessor := NewRiskAssessor()
		if assessor == nil {
			t.Fatal("expected non-nil assessor")
		}
		if len(assessor.rules) != 0 {
			t.Errorf("expected 0 rules, got %d", len(assessor.rules))
		}
	})

	t.Run("creates assessor with default rules", func(t *testing.T) {
		assessor := NewRiskAssessor(WithDefaultRules())
		if assessor == nil {
			t.Fatal("expected non-nil assessor")
		}
		if len(assessor.rules) == 0 {
			t.Error("expected default rules to be configured")
		}
	})

	t.Run("creates assessor with custom rule", func(t *testing.T) {
		customRule := RiskRule{
			Name:        "test_rule",
			Description: "A test rule",
			Evaluate: func(step *ExecutionStep, ctx RiskContext) (RiskLevel, string) {
				return RiskLevelLow, ""
			},
		}

		assessor := NewRiskAssessor(WithRule(customRule))
		if assessor == nil {
			t.Fatal("expected non-nil assessor")
		}
		if len(assessor.rules) != 1 {
			t.Errorf("expected 1 rule, got %d", len(assessor.rules))
		}
		if assessor.rules[0].Name != "test_rule" {
			t.Errorf("expected rule name 'test_rule', got '%s'", assessor.rules[0].Name)
		}
	})
}

func TestRiskAssessor_AssessStep(t *testing.T) {
	t.Run("assesses step with no rules as low risk", func(t *testing.T) {
		assessor := NewRiskAssessor()
		step := ExecutionStep{
			ID:          types.NewID(),
			Name:        "Safe operation",
			Description: "This is a safe operation",
			Type:        StepTypeTool,
		}

		assessment := assessor.AssessStep(&step, RiskContext{})

		if assessment.Level != RiskLevelLow {
			t.Errorf("expected low risk, got %s", assessment.Level)
		}
		if assessment.RequiresApproval {
			t.Error("expected no approval required")
		}
	})

	t.Run("detects destructive operations", func(t *testing.T) {
		assessor := NewRiskAssessor(WithDefaultRules())
		step := ExecutionStep{
			ID:          types.NewID(),
			Name:        "Delete files",
			Description: "Delete temporary files",
			Type:        StepTypeTool,
		}

		assessment := assessor.AssessStep(&step, RiskContext{})

		if assessment.Level != RiskLevelHigh {
			t.Errorf("expected high risk, got %s", assessment.Level)
		}
		if !assessment.RequiresApproval {
			t.Error("expected approval required for destructive operation")
		}
	})

	t.Run("detects privilege escalation", func(t *testing.T) {
		assessor := NewRiskAssessor(WithDefaultRules())
		step := ExecutionStep{
			ID:          types.NewID(),
			Name:        "Escalate privileges",
			Description: "Use sudo to gain root access",
			Type:        StepTypeTool,
		}

		assessment := assessor.AssessStep(&step, RiskContext{})

		if assessment.Level != RiskLevelCritical {
			t.Errorf("expected critical risk, got %s", assessment.Level)
		}
		if !assessment.RequiresApproval {
			t.Error("expected approval required for privilege escalation")
		}
	})

	t.Run("detects agent delegation", func(t *testing.T) {
		assessor := NewRiskAssessor(WithDefaultRules())
		step := ExecutionStep{
			ID:          types.NewID(),
			Name:        "Delegate to agent",
			Description: "Delegate task to another agent",
			Type:        StepTypeAgent,
		}

		assessment := assessor.AssessStep(&step, RiskContext{})

		if assessment.Level == RiskLevelLow {
			t.Error("expected elevated risk for agent delegation")
		}
	})

	t.Run("uses highest risk level from multiple rules", func(t *testing.T) {
		assessor := NewRiskAssessor(
			WithRule(RiskRule{
				Name:        "low_rule",
				Description: "Returns low risk",
				Evaluate: func(step *ExecutionStep, ctx RiskContext) (RiskLevel, string) {
					return RiskLevelLow, ""
				},
			}),
			WithRule(RiskRule{
				Name:        "high_rule",
				Description: "Returns high risk",
				Evaluate: func(step *ExecutionStep, ctx RiskContext) (RiskLevel, string) {
					return RiskLevelHigh, "high risk detected"
				},
			}),
			WithRule(RiskRule{
				Name:        "medium_rule",
				Description: "Returns medium risk",
				Evaluate: func(step *ExecutionStep, ctx RiskContext) (RiskLevel, string) {
					return RiskLevelMedium, "medium risk detected"
				},
			}),
		)

		step := ExecutionStep{
			ID:   types.NewID(),
			Name: "Test step",
			Type: StepTypeTool,
		}

		assessment := assessor.AssessStep(&step, RiskContext{})

		if assessment.Level != RiskLevelHigh {
			t.Errorf("expected highest risk level (high), got %s", assessment.Level)
		}
	})
}

func TestRiskAssessor_AssessPlan(t *testing.T) {
	t.Run("assesses plan with all low risk steps", func(t *testing.T) {
		assessor := NewRiskAssessor(WithDefaultRules())
		plan := &ExecutionPlan{
			ID:        types.NewID(),
			MissionID: types.NewID(),
			Steps: []ExecutionStep{
				{
					ID:          types.NewID(),
					Name:        "Step 1",
					Description: "Safe operation",
					Type:        StepTypeTool,
				},
				{
					ID:          types.NewID(),
					Name:        "Step 2",
					Description: "Another safe operation",
					Type:        StepTypeTool,
				},
			},
		}

		summary := assessor.AssessPlan(plan, RiskContext{})

		if summary.OverallLevel != RiskLevelLow {
			t.Errorf("expected overall low risk, got %s", summary.OverallLevel)
		}
		if summary.HighRiskSteps != 0 {
			t.Errorf("expected 0 high risk steps, got %d", summary.HighRiskSteps)
		}
		if summary.CriticalSteps != 0 {
			t.Errorf("expected 0 critical steps, got %d", summary.CriticalSteps)
		}
		if summary.ApprovalRequired {
			t.Error("expected no approval required")
		}
	})

	t.Run("assesses plan with mixed risk levels", func(t *testing.T) {
		assessor := NewRiskAssessor(WithDefaultRules())
		plan := &ExecutionPlan{
			ID:        types.NewID(),
			MissionID: types.NewID(),
			Steps: []ExecutionStep{
				{
					ID:          types.NewID(),
					Name:        "Safe step",
					Description: "Safe operation",
					Type:        StepTypeTool,
				},
				{
					ID:          types.NewID(),
					Name:        "Delete files",
					Description: "Remove temporary files",
					Type:        StepTypeTool,
				},
				{
					ID:          types.NewID(),
					Name:        "Escalate",
					Description: "Use sudo to run command",
					Type:        StepTypeTool,
				},
			},
		}

		summary := assessor.AssessPlan(plan, RiskContext{})

		if summary.OverallLevel != RiskLevelCritical {
			t.Errorf("expected overall critical risk, got %s", summary.OverallLevel)
		}
		if summary.CriticalSteps != 1 {
			t.Errorf("expected 1 critical step, got %d", summary.CriticalSteps)
		}
		if summary.HighRiskSteps < 1 {
			t.Errorf("expected at least 1 high risk step, got %d", summary.HighRiskSteps)
		}
		if !summary.ApprovalRequired {
			t.Error("expected approval required")
		}
	})

	t.Run("aggregates factors from all steps", func(t *testing.T) {
		assessor := NewRiskAssessor(WithDefaultRules())
		plan := &ExecutionPlan{
			ID:        types.NewID(),
			MissionID: types.NewID(),
			Steps: []ExecutionStep{
				{
					ID:          types.NewID(),
					Name:        "Delete files",
					Description: "Remove files",
					Type:        StepTypeTool,
				},
				{
					ID:          types.NewID(),
					Name:        "Copy data",
					Description: "Extract information",
					Type:        StepTypeTool,
				},
			},
		}

		summary := assessor.AssessPlan(plan, RiskContext{})

		if len(summary.Factors) == 0 {
			t.Error("expected factors to be aggregated")
		}
	})
}

func TestRiskLevelOrdinal(t *testing.T) {
	tests := []struct {
		level    RiskLevel
		expected int
	}{
		{RiskLevelLow, 0},
		{RiskLevelMedium, 1},
		{RiskLevelHigh, 2},
		{RiskLevelCritical, 3},
	}

	for _, tt := range tests {
		t.Run(string(tt.level), func(t *testing.T) {
			result := riskLevelOrdinal(tt.level)
			if result != tt.expected {
				t.Errorf("expected ordinal %d, got %d", tt.expected, result)
			}
		})
	}
}

func TestRiskLevelToScore(t *testing.T) {
	tests := []struct {
		level    RiskLevel
		expected float64
	}{
		{RiskLevelLow, 0.25},
		{RiskLevelMedium, 0.50},
		{RiskLevelHigh, 0.75},
		{RiskLevelCritical, 1.0},
	}

	for _, tt := range tests {
		t.Run(string(tt.level), func(t *testing.T) {
			result := riskLevelToScore(tt.level)
			if result != tt.expected {
				t.Errorf("expected score %f, got %f", tt.expected, result)
			}
		})
	}
}

func TestDefaultRiskRules(t *testing.T) {
	rules := defaultRiskRules()

	if len(rules) == 0 {
		t.Fatal("expected default rules to be defined")
	}

	// Verify each rule has required fields
	for i, rule := range rules {
		if rule.Name == "" {
			t.Errorf("rule %d has empty name", i)
		}
		if rule.Description == "" {
			t.Errorf("rule %d has empty description", i)
		}
		if rule.Evaluate == nil {
			t.Errorf("rule %d has nil evaluate function", i)
		}
	}

	// Test that rules are actually functional
	step := ExecutionStep{
		ID:   types.NewID(),
		Name: "Test step",
		Type: StepTypeTool,
	}

	for _, rule := range rules {
		t.Run(rule.Name, func(t *testing.T) {
			level, _ := rule.Evaluate(&step, RiskContext{})
			if level == "" {
				t.Error("rule returned empty risk level")
			}
		})
	}
}
