package types

import (
	"encoding/json"
	"testing"
)

// TestTargetType_String tests the String method
func TestTargetType_String(t *testing.T) {
	tests := []struct {
		name     string
		tt       TargetType
		expected string
	}{
		{"llm_chat", TargetTypeLLMChat, "llm_chat"},
		{"llm_api", TargetTypeLLMAPI, "llm_api"},
		{"rag", TargetTypeRAG, "rag"},
		{"agent", TargetTypeAgent, "agent"},
		{"embedding", TargetTypeEmbedding, "embedding"},
		{"multimodal", TargetTypeMultimodal, "multimodal"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.tt.String(); got != tt.expected {
				t.Errorf("TargetType.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestTargetType_IsValid tests the IsValid method
func TestTargetType_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		tt       TargetType
		expected bool
	}{
		{"valid llm_chat", TargetTypeLLMChat, true},
		{"valid llm_api", TargetTypeLLMAPI, true},
		{"valid rag", TargetTypeRAG, true},
		{"valid agent", TargetTypeAgent, true},
		{"valid embedding", TargetTypeEmbedding, true},
		{"valid multimodal", TargetTypeMultimodal, true},
		{"invalid", TargetType("invalid"), false},
		{"empty", TargetType(""), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.tt.IsValid(); got != tt.expected {
				t.Errorf("TargetType.IsValid() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestTargetType_JSON tests JSON marshaling and unmarshaling
func TestTargetType_JSON(t *testing.T) {
	tests := []struct {
		name         string
		tt           TargetType
		json         string
		wantMarshal  string
		marshalErr   bool
		unmarshalErr bool
	}{
		{"valid llm_chat", TargetTypeLLMChat, `"llm_chat"`, `"llm_chat"`, false, false},
		{"valid rag", TargetTypeRAG, `"rag"`, `"rag"`, false, false},
		// MarshalJSON returns an error for invalid types (added by fix(ci) #266).
		// UnmarshalJSON also returns an error when the string is not a valid type.
		{"invalid type", TargetType(""), `"invalid"`, "", true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name+"_marshal", func(t *testing.T) {
			got, err := json.Marshal(tt.tt)
			if (err != nil) != tt.marshalErr {
				t.Fatalf("json.Marshal() error = %v, wantErr %v", err, tt.marshalErr)
			}
			if !tt.marshalErr && string(got) != tt.wantMarshal {
				t.Errorf("json.Marshal() = %v, want %v", string(got), tt.wantMarshal)
			}
		})

		t.Run(tt.name+"_unmarshal", func(t *testing.T) {
			var got TargetType
			err := json.Unmarshal([]byte(tt.json), &got)
			if (err != nil) != tt.unmarshalErr {
				t.Errorf("json.Unmarshal() error = %v, wantErr %v", err, tt.unmarshalErr)
				return
			}
			if !tt.unmarshalErr && got != tt.tt {
				t.Errorf("json.Unmarshal() = %v, want %v", got, tt.tt)
			}
		})
	}
}

// TestProvider_String tests the String method
func TestProvider_String(t *testing.T) {
	tests := []struct {
		name     string
		p        Provider
		expected string
	}{
		{"openai", ProviderOpenAI, "openai"},
		{"anthropic", ProviderAnthropic, "anthropic"},
		{"google", ProviderGoogle, "google"},
		{"azure", ProviderAzure, "azure"},
		{"ollama", ProviderOllama, "ollama"},
		{"custom", ProviderCustom, "custom"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.String(); got != tt.expected {
				t.Errorf("Provider.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestProvider_IsValid tests the IsValid method
func TestProvider_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		p        Provider
		expected bool
	}{
		{"valid openai", ProviderOpenAI, true},
		{"valid anthropic", ProviderAnthropic, true},
		{"valid google", ProviderGoogle, true},
		{"valid azure", ProviderAzure, true},
		{"valid ollama", ProviderOllama, true},
		{"valid custom", ProviderCustom, true},
		{"invalid", Provider("invalid"), false},
		{"empty", Provider(""), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.IsValid(); got != tt.expected {
				t.Errorf("Provider.IsValid() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestAuthType_String tests the String method
func TestAuthType_String(t *testing.T) {
	tests := []struct {
		name     string
		a        AuthType
		expected string
	}{
		{"none", AuthTypeNone, "none"},
		{"api_key", AuthTypeAPIKey, "api_key"},
		{"bearer", AuthTypeBearer, "bearer"},
		{"basic", AuthTypeBasic, "basic"},
		{"oauth", AuthTypeOAuth, "oauth"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.a.String(); got != tt.expected {
				t.Errorf("AuthType.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestAuthType_IsValid tests the IsValid method
func TestAuthType_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		a        AuthType
		expected bool
	}{
		{"valid none", AuthTypeNone, true},
		{"valid api_key", AuthTypeAPIKey, true},
		{"valid bearer", AuthTypeBearer, true},
		{"valid basic", AuthTypeBasic, true},
		{"valid oauth", AuthTypeOAuth, true},
		{"invalid", AuthType("invalid"), false},
		{"empty", AuthType(""), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.a.IsValid(); got != tt.expected {
				t.Errorf("AuthType.IsValid() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestNewTarget tests the NewTarget constructor
func TestNewTarget(t *testing.T) {
	name := "Test Target"
	url := "https://api.example.com"
	targetType := TargetTypeLLMAPI

	target := NewTarget(name, url, targetType)

	if target == nil {
		t.Fatal("NewTarget() returned nil")
	}

	if target.Name != name {
		t.Errorf("NewTarget().Name = %v, want %v", target.Name, name)
	}

	if target.URL != url {
		t.Errorf("NewTarget().URL = %v, want %v", target.URL, url)
	}

	if target.Type != string(targetType) {
		t.Errorf("NewTarget().Type = %v, want %v", target.Type, targetType)
	}

	if target.Status != TargetStatusActive {
		t.Errorf("NewTarget().Status = %v, want %v", target.Status, TargetStatusActive)
	}

	if target.Timeout != 30 {
		t.Errorf("NewTarget().Timeout = %v, want %v", target.Timeout, 30)
	}

	if target.ID.IsZero() {
		t.Error("NewTarget().ID is zero, expected valid ID")
	}

	if target.Headers == nil {
		t.Error("NewTarget().Headers is nil, expected empty map")
	}

	if target.Config == nil {
		t.Error("NewTarget().Config is nil, expected empty map")
	}

	if target.CreatedAt.IsZero() {
		t.Error("NewTarget().CreatedAt is zero, expected timestamp")
	}

	if target.UpdatedAt.IsZero() {
		t.Error("NewTarget().UpdatedAt is zero, expected timestamp")
	}
}

// TestTarget_Validate tests the Validate method
func TestTarget_Validate(t *testing.T) {
	validTarget := NewTarget("Valid Target", "https://api.example.com", TargetTypeLLMAPI)

	tests := []struct {
		name    string
		target  *Target
		wantErr bool
	}{
		{
			name:    "valid target",
			target:  validTarget,
			wantErr: false,
		},
		{
			name: "invalid ID",
			target: &Target{
				ID:      ID("invalid-id"),
				Name:    "Test",
				URL:     "https://api.example.com",
				Type:    string(TargetTypeLLMAPI),
				Status:  TargetStatusActive,
				Timeout: 30,
			},
			wantErr: true,
		},
		{
			name: "empty name",
			target: &Target{
				ID:      NewID(),
				Name:    "",
				URL:     "https://api.example.com",
				Type:    string(TargetTypeLLMAPI),
				Status:  TargetStatusActive,
				Timeout: 30,
			},
			wantErr: true,
		},
		{
			name: "empty URL",
			target: &Target{
				ID:      NewID(),
				Name:    "Test",
				URL:     "",
				Type:    string(TargetTypeLLMAPI),
				Status:  TargetStatusActive,
				Timeout: 30,
			},
			wantErr: true,
		},
		{
			name: "custom type is valid (schema-based types)",
			target: &Target{
				ID:      NewID(),
				Name:    "Test",
				URL:     "https://api.example.com",
				Type:    "custom_type",
				Status:  TargetStatusActive,
				Timeout: 30,
			},
			wantErr: false, // Type validation is now schema-based, any string is valid
		},
		{
			name: "invalid status",
			target: &Target{
				ID:      NewID(),
				Name:    "Test",
				URL:     "https://api.example.com",
				Type:    string(TargetTypeLLMAPI),
				Status:  TargetStatus("invalid"),
				Timeout: 30,
			},
			wantErr: true,
		},
		{
			name: "invalid provider",
			target: &Target{
				ID:       NewID(),
				Name:     "Test",
				URL:      "https://api.example.com",
				Type:     string(TargetTypeLLMAPI),
				Provider: Provider("invalid"),
				Status:   TargetStatusActive,
				Timeout:  30,
			},
			wantErr: true,
		},
		{
			name: "invalid auth type",
			target: &Target{
				ID:       NewID(),
				Name:     "Test",
				URL:      "https://api.example.com",
				Type:     string(TargetTypeLLMAPI),
				AuthType: AuthType("invalid"),
				Status:   TargetStatusActive,
				Timeout:  30,
			},
			wantErr: true,
		},
		{
			name: "invalid timeout",
			target: &Target{
				ID:      NewID(),
				Name:    "Test",
				URL:     "https://api.example.com",
				Type:    string(TargetTypeLLMAPI),
				Status:  TargetStatusActive,
				Timeout: 0,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.target.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Target.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestTarget_JSON tests JSON marshaling and unmarshaling of Target
func TestTarget_JSON(t *testing.T) {
	target := NewTarget("Test Target", "https://api.example.com", TargetTypeLLMAPI)
	target.Provider = ProviderOpenAI
	target.Model = "gpt-4"
	target.AuthType = AuthTypeAPIKey
	target.Description = "Test description"
	target.Tags = []string{"test", "example"}

	// Marshal
	data, err := json.Marshal(target)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	// Unmarshal
	var unmarshaled Target
	err = json.Unmarshal(data, &unmarshaled)
	if err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	// Compare key fields
	if unmarshaled.ID != target.ID {
		t.Errorf("Unmarshaled ID = %v, want %v", unmarshaled.ID, target.ID)
	}

	if unmarshaled.Name != target.Name {
		t.Errorf("Unmarshaled Name = %v, want %v", unmarshaled.Name, target.Name)
	}

	if unmarshaled.Type != target.Type {
		t.Errorf("Unmarshaled Type = %v, want %v", unmarshaled.Type, target.Type)
	}

	if unmarshaled.Provider != target.Provider {
		t.Errorf("Unmarshaled Provider = %v, want %v", unmarshaled.Provider, target.Provider)
	}

	if unmarshaled.Model != target.Model {
		t.Errorf("Unmarshaled Model = %v, want %v", unmarshaled.Model, target.Model)
	}
}

// TestNewTargetFilter tests the NewTargetFilter constructor
func TestNewTargetFilter(t *testing.T) {
	filter := NewTargetFilter()

	if filter == nil {
		t.Fatal("NewTargetFilter() returned nil")
	}

	if filter.Limit != 100 {
		t.Errorf("NewTargetFilter().Limit = %v, want %v", filter.Limit, 100)
	}

	if filter.Offset != 0 {
		t.Errorf("NewTargetFilter().Offset = %v, want %v", filter.Offset, 0)
	}

	if filter.Provider != nil {
		t.Error("NewTargetFilter().Provider should be nil")
	}

	if filter.Type != nil {
		t.Error("NewTargetFilter().Type should be nil")
	}

	if filter.Status != nil {
		t.Error("NewTargetFilter().Status should be nil")
	}
}

// TestTargetFilter_Fluent tests the fluent API of TargetFilter
func TestTargetFilter_Fluent(t *testing.T) {
	filter := NewTargetFilter().
		WithProvider(ProviderOpenAI).
		WithType(string(TargetTypeLLMAPI)).
		WithStatus(TargetStatusActive).
		WithTags([]string{"test"}).
		WithLimit(50).
		WithOffset(10)

	if filter.Provider == nil || *filter.Provider != ProviderOpenAI {
		t.Errorf("Filter.Provider = %v, want %v", filter.Provider, ProviderOpenAI)
	}

	if filter.Type == nil || *filter.Type != string(TargetTypeLLMAPI) {
		t.Errorf("Filter.Type = %v, want %v", filter.Type, TargetTypeLLMAPI)
	}

	if filter.Status == nil || *filter.Status != TargetStatusActive {
		t.Errorf("Filter.Status = %v, want %v", filter.Status, TargetStatusActive)
	}

	if len(filter.Tags) != 1 || filter.Tags[0] != "test" {
		t.Errorf("Filter.Tags = %v, want [test]", filter.Tags)
	}

	if filter.Limit != 50 {
		t.Errorf("Filter.Limit = %v, want %v", filter.Limit, 50)
	}

	if filter.Offset != 10 {
		t.Errorf("Filter.Offset = %v, want %v", filter.Offset, 10)
	}
}

// BenchmarkNewTarget benchmarks target creation
func BenchmarkNewTarget(b *testing.B) {
	for i := 0; i < b.N; i++ {
		NewTarget("Test Target", "https://api.example.com", TargetTypeLLMAPI)
	}
}

// BenchmarkTarget_Validate benchmarks target validation
func BenchmarkTarget_Validate(b *testing.B) {
	target := NewTarget("Test Target", "https://api.example.com", TargetTypeLLMAPI)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = target.Validate()
	}
}

// BenchmarkTarget_JSON benchmarks JSON marshaling
func BenchmarkTarget_JSON(b *testing.B) {
	target := NewTarget("Test Target", "https://api.example.com", TargetTypeLLMAPI)
	target.Provider = ProviderOpenAI
	target.Model = "gpt-4"
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = json.Marshal(target)
	}
}
