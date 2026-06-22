package types

import (
	"encoding/json"
	"fmt"
	"time"
)

// HealthState represents the health state of a system component
type HealthState string

const (
	HealthStateHealthy   HealthState = "healthy"
	HealthStateDegraded  HealthState = "degraded"
	HealthStateUnhealthy HealthState = "unhealthy"
)

// String returns the string representation of HealthState
func (s HealthState) String() string {
	return string(s)
}

// IsValid checks if the HealthState is a valid value
func (s HealthState) IsValid() bool {
	switch s {
	case HealthStateHealthy, HealthStateDegraded, HealthStateUnhealthy:
		return true
	default:
		return false
	}
}

// MarshalJSON implements json.Marshaler
func (s HealthState) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(s))
}

// UnmarshalJSON implements json.Unmarshaler
func (s *HealthState) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}

	state := HealthState(str)
	if !state.IsValid() {
		return fmt.Errorf("invalid health state: %s", str)
	}

	*s = state
	return nil
}

// HealthStatus represents the health status of a system component with state,
// message, and timestamp information.
type HealthStatus struct {
	State     HealthState `json:"state"`
	Message   string      `json:"message,omitempty"`
	CheckedAt time.Time   `json:"checked_at"`
}

// NewHealthStatus creates a new HealthStatus with the given state and message.
// CheckedAt is automatically set to the current time.
func NewHealthStatus(state HealthState, message string) HealthStatus {
	return HealthStatus{
		State:     state,
		Message:   message,
		CheckedAt: time.Now(),
	}
}

// Healthy creates a new HealthStatus with HealthStateHealthy state.
func Healthy(message string) HealthStatus {
	return NewHealthStatus(HealthStateHealthy, message)
}

// Degraded creates a new HealthStatus with HealthStateDegraded state.
func Degraded(message string) HealthStatus {
	return NewHealthStatus(HealthStateDegraded, message)
}

// Unhealthy creates a new HealthStatus with HealthStateUnhealthy state.
func Unhealthy(message string) HealthStatus {
	return NewHealthStatus(HealthStateUnhealthy, message)
}

// IsHealthy returns true if the health state is healthy.
func (h HealthStatus) IsHealthy() bool {
	return h.State == HealthStateHealthy
}

// IsDegraded returns true if the health state is degraded.
func (h HealthStatus) IsDegraded() bool {
	return h.State == HealthStateDegraded
}

// IsUnhealthy returns true if the health state is unhealthy.
func (h HealthStatus) IsUnhealthy() bool {
	return h.State == HealthStateUnhealthy
}
