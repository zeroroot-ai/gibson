package orchestrator

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestDataPolicy_SetDefaults(t *testing.T) {
	tests := []struct {
		name     string
		input    DataPolicy
		expected DataPolicy
	}{
		{
			name:  "empty policy sets all defaults",
			input: DataPolicy{},
			expected: DataPolicy{
				OutputScope: ScopeMission,
				InputScope:  ScopeMission,
				Reuse:       ReuseNever,
			},
		},
		{
			name: "partial policy sets missing defaults",
			input: DataPolicy{
				OutputScope: ScopeMissionRun,
			},
			expected: DataPolicy{
				OutputScope: ScopeMissionRun,
				InputScope:  ScopeMission,
				Reuse:       ReuseNever,
			},
		},
		{
			name: "full policy preserves all values",
			input: DataPolicy{
				OutputScope: ScopeGlobal,
				InputScope:  ScopeMissionRun,
				Reuse:       ReuseSkip,
			},
			expected: DataPolicy{
				OutputScope: ScopeGlobal,
				InputScope:  ScopeMissionRun,
				Reuse:       ReuseSkip,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := tt.input
			policy.SetDefaults()

			if policy.OutputScope != tt.expected.OutputScope {
				t.Errorf("OutputScope = %v, want %v", policy.OutputScope, tt.expected.OutputScope)
			}
			if policy.InputScope != tt.expected.InputScope {
				t.Errorf("InputScope = %v, want %v", policy.InputScope, tt.expected.InputScope)
			}
			if policy.Reuse != tt.expected.Reuse {
				t.Errorf("Reuse = %v, want %v", policy.Reuse, tt.expected.Reuse)
			}
		})
	}
}

func TestDataPolicy_Validate(t *testing.T) {
	tests := []struct {
		name      string
		policy    DataPolicy
		wantError bool
		errorMsg  string
	}{
		{
			name: "valid policy with all defaults",
			policy: DataPolicy{
				OutputScope: ScopeMission,
				InputScope:  ScopeMission,
				Reuse:       ReuseNever,
			},
			wantError: false,
		},
		{
			name: "valid policy with mission_run scope",
			policy: DataPolicy{
				OutputScope: ScopeMissionRun,
				InputScope:  ScopeMissionRun,
				Reuse:       ReuseSkip,
			},
			wantError: false,
		},
		{
			name: "valid policy with global scope",
			policy: DataPolicy{
				OutputScope: ScopeGlobal,
				InputScope:  ScopeGlobal,
				Reuse:       ReuseAlways,
			},
			wantError: false,
		},
		{
			name: "invalid output_scope",
			policy: DataPolicy{
				OutputScope: "invalid",
				InputScope:  ScopeMission,
				Reuse:       ReuseNever,
			},
			wantError: true,
			errorMsg:  "invalid output_scope value 'invalid': must be mission_run|mission|global",
		},
		{
			name: "invalid input_scope",
			policy: DataPolicy{
				OutputScope: ScopeMission,
				InputScope:  "bad_scope",
				Reuse:       ReuseNever,
			},
			wantError: true,
			errorMsg:  "invalid input_scope value 'bad_scope': must be mission_run|mission|global",
		},
		{
			name: "invalid reuse",
			policy: DataPolicy{
				OutputScope: ScopeMission,
				InputScope:  ScopeMission,
				Reuse:       "maybe",
			},
			wantError: true,
			errorMsg:  "invalid reuse value 'maybe': must be skip|always|never",
		},
		{
			name: "empty fields should fail validation",
			policy: DataPolicy{
				OutputScope: "",
				InputScope:  "",
				Reuse:       "",
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.policy.Validate()

			if tt.wantError {
				if err == nil {
					t.Errorf("Validate() expected error but got nil")
				} else if tt.errorMsg != "" && err.Error() != tt.errorMsg {
					t.Errorf("Validate() error = %v, want %v", err.Error(), tt.errorMsg)
				}
			} else {
				if err != nil {
					t.Errorf("Validate() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestDataPolicy_YAMLParsing(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		expected DataPolicy
	}{
		{
			name: "full policy from YAML",
			yaml: `
output_scope: mission_run
input_scope: global
reuse: skip
`,
			expected: DataPolicy{
				OutputScope: ScopeMissionRun,
				InputScope:  ScopeGlobal,
				Reuse:       ReuseSkip,
			},
		},
		{
			name: "partial policy from YAML",
			yaml: `
output_scope: mission
`,
			expected: DataPolicy{
				OutputScope: ScopeMission,
				InputScope:  "",
				Reuse:       "",
			},
		},
		{
			name: "empty YAML",
			yaml: `{}`,
			expected: DataPolicy{
				OutputScope: "",
				InputScope:  "",
				Reuse:       "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var policy DataPolicy
			err := yaml.Unmarshal([]byte(tt.yaml), &policy)
			if err != nil {
				t.Fatalf("Failed to unmarshal YAML: %v", err)
			}

			if policy.OutputScope != tt.expected.OutputScope {
				t.Errorf("OutputScope = %v, want %v", policy.OutputScope, tt.expected.OutputScope)
			}
			if policy.InputScope != tt.expected.InputScope {
				t.Errorf("InputScope = %v, want %v", policy.InputScope, tt.expected.InputScope)
			}
			if policy.Reuse != tt.expected.Reuse {
				t.Errorf("Reuse = %v, want %v", policy.Reuse, tt.expected.Reuse)
			}
		})
	}
}

func TestDataPolicy_YAMLRoundTrip(t *testing.T) {
	original := DataPolicy{
		OutputScope: ScopeGlobal,
		InputScope:  ScopeMissionRun,
		Reuse:       ReuseAlways,
	}

	// Marshal to YAML
	data, err := yaml.Marshal(&original)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	// Unmarshal back
	var parsed DataPolicy
	err = yaml.Unmarshal(data, &parsed)
	if err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	// Compare
	if parsed.OutputScope != original.OutputScope {
		t.Errorf("OutputScope = %v, want %v", parsed.OutputScope, original.OutputScope)
	}
	if parsed.InputScope != original.InputScope {
		t.Errorf("InputScope = %v, want %v", parsed.InputScope, original.InputScope)
	}
	if parsed.Reuse != original.Reuse {
		t.Errorf("Reuse = %v, want %v", parsed.Reuse, original.Reuse)
	}
}

func TestNewDataPolicy(t *testing.T) {
	policy := NewDataPolicy()

	if policy == nil {
		t.Fatal("NewDataPolicy() returned nil")
	}

	// Check defaults are applied
	if policy.OutputScope != ScopeMission {
		t.Errorf("OutputScope = %v, want %v", policy.OutputScope, ScopeMission)
	}
	if policy.InputScope != ScopeMission {
		t.Errorf("InputScope = %v, want %v", policy.InputScope, ScopeMission)
	}
	if policy.Reuse != ReuseNever {
		t.Errorf("Reuse = %v, want %v", policy.Reuse, ReuseNever)
	}

	// Validate should pass
	if err := policy.Validate(); err != nil {
		t.Errorf("NewDataPolicy() created invalid policy: %v", err)
	}
}

func TestDataPolicy_SetDefaultsAndValidate(t *testing.T) {
	// Common mission: unmarshal from YAML, set defaults, validate
	yamlData := `
output_scope: global
`
	var policy DataPolicy
	err := yaml.Unmarshal([]byte(yamlData), &policy)
	if err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	// Before defaults, should fail validation (missing fields)
	if err := policy.Validate(); err == nil {
		t.Error("Validate() should fail before SetDefaults()")
	}

	// Apply defaults
	policy.SetDefaults()

	// After defaults, should pass validation
	if err := policy.Validate(); err != nil {
		t.Errorf("Validate() after SetDefaults() failed: %v", err)
	}

	// Check that explicit value was preserved
	if policy.OutputScope != ScopeGlobal {
		t.Errorf("SetDefaults() overwrote explicit OutputScope value")
	}

	// Check that defaults were applied
	if policy.InputScope != ScopeMission {
		t.Errorf("SetDefaults() didn't set InputScope default")
	}
	if policy.Reuse != ReuseNever {
		t.Errorf("SetDefaults() didn't set Reuse default")
	}
}
