package types

import (
	"encoding/json"
	"testing"
	"time"
)

func TestHealthState_String(t *testing.T) {
	tests := []struct {
		name  string
		state HealthState
		want  string
	}{
		{
			name:  "healthy state",
			state: HealthStateHealthy,
			want:  "healthy",
		},
		{
			name:  "degraded state",
			state: HealthStateDegraded,
			want:  "degraded",
		},
		{
			name:  "unhealthy state",
			state: HealthStateUnhealthy,
			want:  "unhealthy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.state.String(); got != tt.want {
				t.Errorf("HealthState.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHealthState_IsValid(t *testing.T) {
	tests := []struct {
		name  string
		state HealthState
		want  bool
	}{
		{
			name:  "valid healthy state",
			state: HealthStateHealthy,
			want:  true,
		},
		{
			name:  "valid degraded state",
			state: HealthStateDegraded,
			want:  true,
		},
		{
			name:  "valid unhealthy state",
			state: HealthStateUnhealthy,
			want:  true,
		},
		{
			name:  "invalid state",
			state: HealthState("invalid"),
			want:  false,
		},
		{
			name:  "empty state",
			state: HealthState(""),
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.state.IsValid(); got != tt.want {
				t.Errorf("HealthState.IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHealthState_MarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		state   HealthState
		want    string
		wantErr bool
	}{
		{
			name:    "marshal healthy",
			state:   HealthStateHealthy,
			want:    `"healthy"`,
			wantErr: false,
		},
		{
			name:    "marshal degraded",
			state:   HealthStateDegraded,
			want:    `"degraded"`,
			wantErr: false,
		},
		{
			name:    "marshal unhealthy",
			state:   HealthStateUnhealthy,
			want:    `"unhealthy"`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.state.MarshalJSON()
			if (err != nil) != tt.wantErr {
				t.Errorf("HealthState.MarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if string(got) != tt.want {
				t.Errorf("HealthState.MarshalJSON() = %v, want %v", string(got), tt.want)
			}
		})
	}
}

func TestHealthState_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		want    HealthState
		wantErr bool
	}{
		{
			name:    "unmarshal healthy",
			json:    `"healthy"`,
			want:    HealthStateHealthy,
			wantErr: false,
		},
		{
			name:    "unmarshal degraded",
			json:    `"degraded"`,
			want:    HealthStateDegraded,
			wantErr: false,
		},
		{
			name:    "unmarshal unhealthy",
			json:    `"unhealthy"`,
			want:    HealthStateUnhealthy,
			wantErr: false,
		},
		{
			name:    "unmarshal invalid",
			json:    `"invalid"`,
			want:    HealthState(""),
			wantErr: true,
		},
		{
			name:    "unmarshal malformed json",
			json:    `{bad}`,
			want:    HealthState(""),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var state HealthState
			err := state.UnmarshalJSON([]byte(tt.json))
			if (err != nil) != tt.wantErr {
				t.Errorf("HealthState.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && state != tt.want {
				t.Errorf("HealthState.UnmarshalJSON() = %v, want %v", state, tt.want)
			}
		})
	}
}

func TestNewHealthStatus(t *testing.T) {
	tests := []struct {
		name    string
		state   HealthState
		message string
	}{
		{
			name:    "create healthy status",
			state:   HealthStateHealthy,
			message: "All systems operational",
		},
		{
			name:    "create degraded status",
			state:   HealthStateDegraded,
			message: "Database connection slow",
		},
		{
			name:    "create unhealthy status",
			state:   HealthStateUnhealthy,
			message: "Service unavailable",
		},
		{
			name:    "empty message",
			state:   HealthStateHealthy,
			message: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := time.Now()
			status := NewHealthStatus(tt.state, tt.message)
			after := time.Now()

			if status.State != tt.state {
				t.Errorf("NewHealthStatus().State = %v, want %v", status.State, tt.state)
			}
			if status.Message != tt.message {
				t.Errorf("NewHealthStatus().Message = %v, want %v", status.Message, tt.message)
			}
			if status.CheckedAt.Before(before) || status.CheckedAt.After(after) {
				t.Errorf("NewHealthStatus().CheckedAt = %v, want between %v and %v",
					status.CheckedAt, before, after)
			}
		})
	}
}

func TestHealthy(t *testing.T) {
	message := "Service running normally"
	status := Healthy(message)

	if status.State != HealthStateHealthy {
		t.Errorf("Healthy().State = %v, want %v", status.State, HealthStateHealthy)
	}
	if status.Message != message {
		t.Errorf("Healthy().Message = %v, want %v", status.Message, message)
	}
	if status.CheckedAt.IsZero() {
		t.Error("Healthy().CheckedAt should not be zero")
	}
}

func TestDegraded(t *testing.T) {
	message := "Partial service degradation"
	status := Degraded(message)

	if status.State != HealthStateDegraded {
		t.Errorf("Degraded().State = %v, want %v", status.State, HealthStateDegraded)
	}
	if status.Message != message {
		t.Errorf("Degraded().Message = %v, want %v", status.Message, message)
	}
	if status.CheckedAt.IsZero() {
		t.Error("Degraded().CheckedAt should not be zero")
	}
}

func TestUnhealthy(t *testing.T) {
	message := "Service down"
	status := Unhealthy(message)

	if status.State != HealthStateUnhealthy {
		t.Errorf("Unhealthy().State = %v, want %v", status.State, HealthStateUnhealthy)
	}
	if status.Message != message {
		t.Errorf("Unhealthy().Message = %v, want %v", status.Message, message)
	}
	if status.CheckedAt.IsZero() {
		t.Error("Unhealthy().CheckedAt should not be zero")
	}
}

func TestHealthStatus_IsHealthy(t *testing.T) {
	tests := []struct {
		name   string
		status HealthStatus
		want   bool
	}{
		{
			name:   "healthy status",
			status: Healthy("ok"),
			want:   true,
		},
		{
			name:   "degraded status",
			status: Degraded("slow"),
			want:   false,
		},
		{
			name:   "unhealthy status",
			status: Unhealthy("down"),
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.status.IsHealthy(); got != tt.want {
				t.Errorf("HealthStatus.IsHealthy() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHealthStatus_IsDegraded(t *testing.T) {
	tests := []struct {
		name   string
		status HealthStatus
		want   bool
	}{
		{
			name:   "healthy status",
			status: Healthy("ok"),
			want:   false,
		},
		{
			name:   "degraded status",
			status: Degraded("slow"),
			want:   true,
		},
		{
			name:   "unhealthy status",
			status: Unhealthy("down"),
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.status.IsDegraded(); got != tt.want {
				t.Errorf("HealthStatus.IsDegraded() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHealthStatus_IsUnhealthy(t *testing.T) {
	tests := []struct {
		name   string
		status HealthStatus
		want   bool
	}{
		{
			name:   "healthy status",
			status: Healthy("ok"),
			want:   false,
		},
		{
			name:   "degraded status",
			status: Degraded("slow"),
			want:   false,
		},
		{
			name:   "unhealthy status",
			status: Unhealthy("down"),
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.status.IsUnhealthy(); got != tt.want {
				t.Errorf("HealthStatus.IsUnhealthy() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHealthStatus_JSON_RoundTrip(t *testing.T) {
	original := HealthStatus{
		State:     HealthStateDegraded,
		Message:   "Database latency high",
		CheckedAt: time.Date(2025, 12, 25, 10, 30, 0, 0, time.UTC),
	}

	// Marshal to JSON
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	// Unmarshal back
	var decoded HealthStatus
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	// Compare
	if decoded.State != original.State {
		t.Errorf("State after round-trip = %v, want %v", decoded.State, original.State)
	}
	if decoded.Message != original.Message {
		t.Errorf("Message after round-trip = %v, want %v", decoded.Message, original.Message)
	}
	// Compare timestamps (allowing for some precision loss in JSON encoding)
	if !decoded.CheckedAt.Equal(original.CheckedAt) {
		t.Errorf("CheckedAt after round-trip = %v, want %v", decoded.CheckedAt, original.CheckedAt)
	}
}

func TestHealthStatus_JSON_Format(t *testing.T) {
	status := HealthStatus{
		State:     HealthStateHealthy,
		Message:   "All systems operational",
		CheckedAt: time.Date(2025, 12, 25, 10, 30, 0, 0, time.UTC),
	}

	data, err := json.Marshal(status)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	// Verify JSON structure
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("json.Unmarshal() into map error = %v", err)
	}

	if result["state"] != "healthy" {
		t.Errorf("JSON state = %v, want healthy", result["state"])
	}
	if result["message"] != "All systems operational" {
		t.Errorf("JSON message = %v, want 'All systems operational'", result["message"])
	}
	if _, ok := result["checked_at"]; !ok {
		t.Error("JSON should contain checked_at field")
	}
}

func TestHealthStatus_JSON_OmitEmptyMessage(t *testing.T) {
	status := HealthStatus{
		State:     HealthStateHealthy,
		Message:   "",
		CheckedAt: time.Now(),
	}

	data, err := json.Marshal(status)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	// Verify message field is omitted when empty
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("json.Unmarshal() into map error = %v", err)
	}

	if _, ok := result["message"]; ok {
		t.Error("JSON should omit empty message field")
	}
}
