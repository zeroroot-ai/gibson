package mission

import (
	"context"
	"fmt"
	"time"

	"github.com/zeroroot-ai/gibson/internal/agent"
	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

// ConstraintAction defines what action to take when a constraint is violated.
// SeverityAction is intentionally NOT a field on missionv1.MissionConstraints —
// it is a platform-policy decision (pause vs fail on severity exceeded) that
// belongs in the daemon's runtime configuration, not in the wire shape.
// The DefaultConstraintChecker accepts it as a construction-time parameter.
//
// ADR 0004 mandates missionv1.MissionConstraints as the single platform-wide
// constraint shape; any daemon-local augmentation goes here or in config.
type ConstraintAction string

const (
	// ConstraintActionPause suspends mission execution until manual intervention.
	ConstraintActionPause ConstraintAction = "pause"

	// ConstraintActionFail immediately fails the mission with constraint violation error.
	ConstraintActionFail ConstraintAction = "fail"
)

// String returns the string representation of the constraint action.
func (a ConstraintAction) String() string {
	return string(a)
}

// ConstraintViolation describes a violated constraint.
// This is returned when a constraint check fails and contains information
// about what was violated and what action should be taken.
type ConstraintViolation struct {
	// Constraint is the name of the violated constraint.
	Constraint string `json:"constraint"`

	// Message is a human-readable description of the violation.
	Message string `json:"message"`

	// Action is the action to take (pause or fail).
	Action ConstraintAction `json:"action"`

	// CurrentValue is the current value that violated the constraint (optional).
	CurrentValue any `json:"current_value,omitempty"`

	// ThresholdValue is the threshold that was exceeded (optional).
	ThresholdValue any `json:"threshold_value,omitempty"`
}

// Error implements the error interface for ConstraintViolation.
func (v *ConstraintViolation) Error() string {
	return fmt.Sprintf("constraint violation: %s - %s (action: %s)", v.Constraint, v.Message, v.Action)
}

// ConstraintChecker evaluates mission constraints against current metrics.
type ConstraintChecker interface {
	// Check evaluates all constraints and returns a violation if any constraint is violated.
	// Returns nil if all constraints are satisfied.
	Check(ctx context.Context, constraints *missionv1.MissionConstraints, metrics *MissionMetrics) (*ConstraintViolation, error)
}

// DefaultConstraintChecker implements ConstraintChecker with standard validation logic.
//
// SeverityAction is a daemon runtime-policy decision: when a finding breaches the
// severity threshold declared on the proto constraints, the checker uses
// DefaultSeverityAction to decide whether to pause or fail the mission.
// This keeps the wire shape (missionv1.MissionConstraints) free of policy knobs
// while letting operators configure the daemon's response behaviour.
type DefaultConstraintChecker struct {
	// DefaultSeverityAction is the action taken when the severity threshold is breached.
	// Defaults to ConstraintActionPause if not set.
	DefaultSeverityAction ConstraintAction
}

// NewDefaultConstraintChecker creates a new DefaultConstraintChecker with pause
// as the default severity action.
func NewDefaultConstraintChecker() *DefaultConstraintChecker {
	return &DefaultConstraintChecker{
		DefaultSeverityAction: ConstraintActionPause,
	}
}

// Check evaluates all constraints and returns the first violation found.
// Constraints are checked in order of severity (cost, duration, findings, severity).
func (c *DefaultConstraintChecker) Check(ctx context.Context, constraints *missionv1.MissionConstraints, metrics *MissionMetrics) (*ConstraintViolation, error) {
	if constraints == nil || metrics == nil {
		return nil, nil
	}

	// Check max cost constraint (highest priority)
	if constraints.GetMaxCost() > 0 && metrics.TotalCost > constraints.GetMaxCost() {
		return &ConstraintViolation{
			Constraint:     "max_cost",
			Message:        fmt.Sprintf("Mission cost %.2f exceeds maximum allowed cost %.2f", metrics.TotalCost, constraints.GetMaxCost()),
			Action:         ConstraintActionPause, // Cost violations always pause for approval
			CurrentValue:   metrics.TotalCost,
			ThresholdValue: constraints.GetMaxCost(),
		}, nil
	}

	// Check max tokens constraint
	if constraints.GetMaxTokens() > 0 && metrics.TotalTokens > constraints.GetMaxTokens() {
		return &ConstraintViolation{
			Constraint:     "max_tokens",
			Message:        fmt.Sprintf("Mission tokens %d exceeds maximum allowed tokens %d", metrics.TotalTokens, constraints.GetMaxTokens()),
			Action:         ConstraintActionPause, // Token violations always pause for approval
			CurrentValue:   metrics.TotalTokens,
			ThresholdValue: constraints.GetMaxTokens(),
		}, nil
	}

	// Check max duration constraint
	if maxDur := constraints.GetMaxDuration(); maxDur != nil {
		maxDuration := maxDur.AsDuration()
		if maxDuration > 0 && metrics.Duration > maxDuration {
			return &ConstraintViolation{
				Constraint:     "max_duration",
				Message:        fmt.Sprintf("Mission duration %s exceeds maximum allowed duration %s", metrics.Duration, maxDuration),
				Action:         ConstraintActionFail, // Duration violations always fail
				CurrentValue:   metrics.Duration.String(),
				ThresholdValue: maxDuration.String(),
			}, nil
		}
	}

	// Check max findings constraint
	if constraints.GetMaxFindings() > 0 && int64(metrics.TotalFindings) >= int64(constraints.GetMaxFindings()) {
		return &ConstraintViolation{
			Constraint:     "max_findings",
			Message:        fmt.Sprintf("Mission findings %d reached maximum allowed findings %d", metrics.TotalFindings, constraints.GetMaxFindings()),
			Action:         ConstraintActionPause, // Findings limit pauses to allow review
			CurrentValue:   metrics.TotalFindings,
			ThresholdValue: constraints.GetMaxFindings(),
		}, nil
	}

	// Check severity threshold constraint
	if threshold := constraints.GetSeverityThreshold(); threshold != "" && metrics.FindingsBySeverity != nil {
		if c.checkSeverityThreshold(agent.FindingSeverity(threshold), metrics.FindingsBySeverity) {
			action := c.DefaultSeverityAction
			if action == "" {
				action = ConstraintActionPause
			}
			return &ConstraintViolation{
				Constraint:     "severity_threshold",
				Message:        fmt.Sprintf("Finding with severity %s or higher discovered", threshold),
				Action:         action,
				CurrentValue:   metrics.FindingsBySeverity,
				ThresholdValue: threshold,
			}, nil
		}
	}

	return nil, nil
}

// checkSeverityThreshold checks if any findings meet or exceed the severity threshold.
func (c *DefaultConstraintChecker) checkSeverityThreshold(threshold agent.FindingSeverity, findingsBySeverity map[string]int) bool {
	// Define severity ordering (higher index = more severe)
	severities := []agent.FindingSeverity{
		agent.SeverityInfo,
		agent.SeverityLow,
		agent.SeverityMedium,
		agent.SeverityHigh,
		agent.SeverityCritical,
	}

	// Find threshold index
	thresholdIdx := -1
	for i, sev := range severities {
		if sev == threshold {
			thresholdIdx = i
			break
		}
	}

	if thresholdIdx == -1 {
		return false // Invalid threshold
	}

	// Check if any findings at or above threshold exist
	for i := thresholdIdx; i < len(severities); i++ {
		if count, ok := findingsBySeverity[string(severities[i])]; ok && count > 0 {
			return true
		}
	}

	return false
}

// ValidateConstraints checks if the proto MissionConstraints are valid.
// This replaces the method formerly on the deleted daemon-local MissionConstraints struct.
func ValidateConstraints(c *missionv1.MissionConstraints) error {
	if c == nil {
		return nil
	}

	if maxDur := c.GetMaxDuration(); maxDur != nil {
		if d := maxDur.AsDuration(); d < 0 {
			return fmt.Errorf("max_duration cannot be negative")
		}
	}

	if c.GetMaxFindings() < 0 {
		return fmt.Errorf("max_findings cannot be negative")
	}

	if c.GetMaxTokens() < 0 {
		return fmt.Errorf("max_tokens cannot be negative")
	}

	if c.GetMaxCost() < 0 {
		return fmt.Errorf("max_cost cannot be negative")
	}

	// Validate severity threshold if set
	if threshold := c.GetSeverityThreshold(); threshold != "" {
		validSeverities := []agent.FindingSeverity{
			agent.SeverityInfo,
			agent.SeverityLow,
			agent.SeverityMedium,
			agent.SeverityHigh,
			agent.SeverityCritical,
		}
		valid := false
		for _, sev := range validSeverities {
			if agent.FindingSeverity(threshold) == sev {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("invalid severity_threshold: %s", threshold)
		}
	}

	return nil
}

// DefaultConstraintsProto returns a proto MissionConstraints with reasonable defaults.
// Per ADR 0004, zero-value proto fields mean "unlimited"; this function exists only
// when an explicit default baseline is required by callers.
func DefaultConstraintsProto() *missionv1.MissionConstraints {
	return &missionv1.MissionConstraints{
		MaxTokens:         10000000, // 10M tokens (generous default)
		MaxCost:           100.0,    // $100 max cost
		MaxFindings:       1000,
		SeverityThreshold: string(agent.SeverityCritical),
		// MaxDuration uses durationpb.New(24 * time.Hour) if callers need it;
		// omitting here keeps the proto zero-safe.
	}
}

// Ensure DefaultConstraintChecker implements ConstraintChecker at compile time
var _ ConstraintChecker = (*DefaultConstraintChecker)(nil)

// constraintsDuration is a helper to extract the MaxDuration as a Go time.Duration.
// Returns 0 if unset (meaning no duration limit).
func constraintsDuration(c *missionv1.MissionConstraints) time.Duration {
	if c == nil {
		return 0
	}
	if d := c.GetMaxDuration(); d != nil {
		return d.AsDuration()
	}
	return 0
}
