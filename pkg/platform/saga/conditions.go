package saga

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Standard condition reasons used across all Gibson reconcilers. Step
// implementations may add their own reasons; these are the ones the
// runner itself emits.
const (
	ReasonPending          = "Pending"
	ReasonInProgress       = "InProgress"
	ReasonReady            = "Ready"
	ReasonSkipped          = "Skipped"
	ReasonUnreachable      = "Unreachable"
	ReasonRateLimited      = "RateLimited"
	ReasonConflict         = "Conflict"
	ReasonInvalidSpec      = "InvalidSpec"
	ReasonAllStepsComplete = "AllStepsComplete"
	ReasonStepFailed       = "StepFailed"
	ReasonStartupGate      = "StartupGate"
)

// SetCondition updates or inserts a condition in the given slice. Preserves
// LastTransitionTime if the status is unchanged.
func SetCondition(conditions *[]metav1.Condition, newCond metav1.Condition) {
	if conditions == nil {
		return
	}
	if newCond.LastTransitionTime.IsZero() {
		newCond.LastTransitionTime = metav1.Now()
	}
	for i, existing := range *conditions {
		if existing.Type != newCond.Type {
			continue
		}
		// Preserve LastTransitionTime when status unchanged.
		if existing.Status == newCond.Status {
			newCond.LastTransitionTime = existing.LastTransitionTime
		}
		(*conditions)[i] = newCond
		return
	}
	*conditions = append(*conditions, newCond)
}

// FindCondition returns the condition of the given type, or nil if absent.
func FindCondition(conditions []metav1.Condition, condType string) *metav1.Condition {
	for i, c := range conditions {
		if c.Type == condType {
			return &conditions[i]
		}
	}
	return nil
}

// IsConditionTrue returns true if the named condition exists and is True.
func IsConditionTrue(conditions []metav1.Condition, condType string) bool {
	c := FindCondition(conditions, condType)
	return c != nil && c.Status == metav1.ConditionTrue
}
