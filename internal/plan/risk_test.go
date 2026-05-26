package plan

import (
	"testing"

	"github.com/zeroroot-ai/gibson/internal/harness"
	"github.com/zeroroot-ai/gibson/internal/types"
)

func TestRiskAssessment_Score(t *testing.T) {
	tests := []struct {
		name       string
		assessment RiskAssessment
		want       float64
	}{
		{
			name: "empty factors returns zero",
			assessment: RiskAssessment{
				Level:            RiskLevelLow,
				RequiresApproval: false,
				Rationale:        "test",
				Factors:          []RiskFactor{},
			},
			want: 0.0,
		},
		{
			name: "single factor with weight 1.0 and value 0.5",
			assessment: RiskAssessment{
				Level:            RiskLevelMedium,
				RequiresApproval: false,
				Rationale:        "test",
				Factors: []RiskFactor{
					{Name: "test", Description: "test factor", Weight: 1.0, Value: 0.5},
				},
			},
			want: 0.5,
		},
		{
			name: "multiple factors with equal weights",
			assessment: RiskAssessment{
				Level:            RiskLevelHigh,
				RequiresApproval: true,
				Rationale:        "test",
				Factors: []RiskFactor{
					{Name: "factor1", Description: "first factor", Weight: 1.0, Value: 0.6},
					{Name: "factor2", Description: "second factor", Weight: 1.0, Value: 0.4},
				},
			},
			want: 0.5,
		},
		{
			name: "multiple factors with different weights",
			assessment: RiskAssessment{
				Level:            RiskLevelHigh,
				RequiresApproval: true,
				Rationale:        "test",
				Factors: []RiskFactor{
					{Name: "factor1", Description: "heavy factor", Weight: 0.8, Value: 1.0},
					{Name: "factor2", Description: "light factor", Weight: 0.2, Value: 0.0},
				},
			},
			want: 0.8,
		},
		{
			name: "zero total weight returns zero",
			assessment: RiskAssessment{
				Level:            RiskLevelLow,
				RequiresApproval: false,
				Rationale:        "test",
				Factors: []RiskFactor{
					{Name: "factor1", Description: "zero weight", Weight: 0.0, Value: 1.0},
				},
			},
			want: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.assessment.Score()
			if got != tt.want {
				t.Errorf("RiskAssessment.Score() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPlanRiskSummary_RequiresStepApproval(t *testing.T) {
	tests := []struct {
		name    string
		summary PlanRiskSummary
		want    bool
	}{
		{
			name: "approval required",
			summary: PlanRiskSummary{
				OverallLevel:     RiskLevelCritical,
				HighRiskSteps:    5,
				CriticalSteps:    2,
				ApprovalRequired: true,
				Factors:          []RiskFactor{},
			},
			want: true,
		},
		{
			name: "approval not required",
			summary: PlanRiskSummary{
				OverallLevel:     RiskLevelLow,
				HighRiskSteps:    0,
				CriticalSteps:    0,
				ApprovalRequired: false,
				Factors:          []RiskFactor{},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.summary.RequiresStepApproval()
			if got != tt.want {
				t.Errorf("PlanRiskSummary.RequiresStepApproval() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRiskContext_Initialization(t *testing.T) {
	missionCtx := harness.NewMissionContext(
		types.NewID(),
		"test-mission",
		"test-agent",
	)

	targetInfo := harness.NewTargetInfo(
		types.NewID(),
		"test-target",
		"https://example.com",
		"web-service",
	)

	ctx := RiskContext{
		Mission:    &missionCtx,
		Target:     &targetInfo,
		PriorSteps: []StepResult{},
	}

	if ctx.Mission == nil {
		t.Error("Expected Mission to be set")
	}
	if ctx.Target == nil {
		t.Error("Expected Target to be set")
	}
	if ctx.Mission.Name != "test-mission" {
		t.Errorf("Expected mission name to be 'test-mission', got %s", ctx.Mission.Name)
	}
	if ctx.Target.Name != "test-target" {
		t.Errorf("Expected target name to be 'test-target', got %s", ctx.Target.Name)
	}
}

func TestRiskFactor_Fields(t *testing.T) {
	factor := RiskFactor{
		Name:        "data_exposure",
		Description: "Risk of exposing sensitive data",
		Weight:      0.8,
		Value:       0.6,
	}

	if factor.Name != "data_exposure" {
		t.Errorf("Expected Name to be 'data_exposure', got %s", factor.Name)
	}
	if factor.Description != "Risk of exposing sensitive data" {
		t.Errorf("Unexpected Description: %s", factor.Description)
	}
	if factor.Weight != 0.8 {
		t.Errorf("Expected Weight to be 0.8, got %f", factor.Weight)
	}
	if factor.Value != 0.6 {
		t.Errorf("Expected Value to be 0.6, got %f", factor.Value)
	}
}
