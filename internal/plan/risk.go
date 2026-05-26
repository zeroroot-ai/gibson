package plan

import "github.com/zeroroot-ai/gibson/internal/harness"

// RiskFactor represents an individual factor contributing to risk assessment.
// Multiple factors are combined to calculate an overall risk score.
type RiskFactor struct {
	// Name is the identifier for this risk factor
	Name string `json:"name"`

	// Description provides details about what this factor measures
	Description string `json:"description"`

	// Weight determines how much this factor contributes to overall risk (0.0 - 1.0)
	Weight float64 `json:"weight"`

	// Value is the assessed value for this factor (0.0 - 1.0)
	Value float64 `json:"value"`
}

// RiskAssessment provides a comprehensive evaluation of risk for a plan step.
// It combines multiple factors, determines approval requirements, and provides
// justification for the risk determination.
type RiskAssessment struct {
	// Level is the overall risk classification
	Level RiskLevel `json:"level"`

	// RequiresApproval indicates whether this step needs explicit approval before execution
	RequiresApproval bool `json:"requires_approval"`

	// Rationale explains the reasoning behind this risk assessment
	Rationale string `json:"rationale"`

	// Factors are the individual risk components that contribute to this assessment
	Factors []RiskFactor `json:"factors"`
}

// Score calculates the weighted risk score from all factors.
// Returns a value between 0.0 (no risk) and 1.0 (maximum risk).
func (r *RiskAssessment) Score() float64 {
	if len(r.Factors) == 0 {
		return 0.0
	}

	var totalWeight float64
	var weightedSum float64

	for _, factor := range r.Factors {
		weightedSum += factor.Weight * factor.Value
		totalWeight += factor.Weight
	}

	// Avoid division by zero
	if totalWeight == 0 {
		return 0.0
	}

	return weightedSum / totalWeight
}

// PlanRiskSummary aggregates risk information across an entire execution plan.
// It provides a high-level overview of risk exposure and approval requirements.
type PlanRiskSummary struct {
	// OverallLevel is the highest risk level found in any step
	OverallLevel RiskLevel `json:"overall_level"`

	// HighRiskSteps counts steps with high or critical risk levels
	HighRiskSteps int `json:"high_risk_steps"`

	// CriticalSteps counts steps with critical risk level specifically
	CriticalSteps int `json:"critical_steps"`

	// ApprovalRequired indicates whether any step in the plan requires approval
	ApprovalRequired bool `json:"approval_required"`

	// Factors are aggregated risk factors across all steps
	Factors []RiskFactor `json:"factors"`
}

// RequiresStepApproval returns true if any step in the plan requires approval.
func (p *PlanRiskSummary) RequiresStepApproval() bool {
	return p.ApprovalRequired
}

// RiskContext provides contextual information for risk assessment calculations.
// It includes mission details, target information, and execution history to
// enable informed risk evaluation.
type RiskContext struct {
	// Mission contains the broader mission context
	Mission *harness.MissionContext `json:"mission,omitempty"`

	// Target contains information about the target system
	Target *harness.TargetInfo `json:"target,omitempty"`

	// PriorSteps contains results from previously executed steps
	PriorSteps []StepResult `json:"prior_steps,omitempty"`
}
