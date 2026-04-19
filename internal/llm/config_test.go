package llm

import (
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/types"
)

func TestLLMConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		config      LLMConfig
		expectError bool
		errorCode   types.ErrorCode
		errorMsg    string
	}{
		{
			name: "valid configuration",
			config: LLMConfig{
				DefaultProvider: "anthropic",
				Providers: map[string]ProviderConfig{
					"anthropic": {
						Type:         ProviderAnthropic,
						APIKey:       "test-key",
						DefaultModel: "claude-3-opus",
						Models: map[string]ModelConfig{
							"claude-3-opus": {
								ContextWindow: 200000,
								MaxOutput:     4096,
								Features:      []ModelFeature{FeatureChat, FeatureTools},
								PricingInput:  15.00,
								PricingOutput: 75.00,
							},
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "empty default provider",
			config: LLMConfig{
				DefaultProvider: "",
				Providers: map[string]ProviderConfig{
					"anthropic": {
						Type:         ProviderAnthropic,
						APIKey:       "test-key",
						DefaultModel: "claude-3-opus",
					},
				},
			},
			expectError: true,
			errorCode:   types.CONFIG_VALIDATION_FAILED,
			errorMsg:    "default_provider cannot be empty",
		},
		{
			name: "empty providers map",
			config: LLMConfig{
				DefaultProvider: "anthropic",
				Providers:       map[string]ProviderConfig{},
			},
			expectError: true,
			errorCode:   types.CONFIG_VALIDATION_FAILED,
			errorMsg:    "providers map cannot be empty",
		},
		{
			name: "nil providers map",
			config: LLMConfig{
				DefaultProvider: "anthropic",
				Providers:       nil,
			},
			expectError: true,
			errorCode:   types.CONFIG_VALIDATION_FAILED,
			errorMsg:    "providers map cannot be empty",
		},
		{
			name: "default provider not in map",
			config: LLMConfig{
				DefaultProvider: "nonexistent",
				Providers: map[string]ProviderConfig{
					"anthropic": {
						Type:         ProviderAnthropic,
						APIKey:       "test-key",
						DefaultModel: "claude-3-opus",
					},
				},
			},
			expectError: true,
			errorCode:   types.CONFIG_VALIDATION_FAILED,
			errorMsg:    "default_provider 'nonexistent' not found in providers map",
		},
		{
			name: "invalid provider configuration",
			config: LLMConfig{
				DefaultProvider: "anthropic",
				Providers: map[string]ProviderConfig{
					"anthropic": {
						Type:         ProviderAnthropic,
						APIKey:       "", // Invalid: empty API key
						DefaultModel: "claude-3-opus",
					},
				},
			},
			expectError: true,
			errorCode:   types.CONFIG_VALIDATION_FAILED,
		},
		{
			name: "multiple providers with valid default",
			config: LLMConfig{
				DefaultProvider: "openai",
				Providers: map[string]ProviderConfig{
					"anthropic": {
						Type:         ProviderAnthropic,
						APIKey:       "anthropic-key",
						DefaultModel: "claude-3-opus",
					},
					"openai": {
						Type:         ProviderOpenAI,
						APIKey:       "openai-key",
						DefaultModel: "gpt-4",
					},
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.expectError {
				require.Error(t, err)
				var gibsonErr *types.GibsonError
				require.ErrorAs(t, err, &gibsonErr)
				assert.Equal(t, tt.errorCode, gibsonErr.Code)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestProviderConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		config      ProviderConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid anthropic configuration",
			config: ProviderConfig{
				Type:         ProviderAnthropic,
				APIKey:       "sk-ant-test-key",
				DefaultModel: "claude-3-opus",
				Models: map[string]ModelConfig{
					"claude-3-opus": {
						ContextWindow: 200000,
						MaxOutput:     4096,
						PricingInput:  15.00,
						PricingOutput: 75.00,
					},
				},
			},
			expectError: false,
		},
		{
			name: "valid openai configuration with base url",
			config: ProviderConfig{
				Type:         ProviderOpenAI,
				APIKey:       "sk-test-key",
				BaseURL:      "https://custom.openai.com",
				DefaultModel: "gpt-4",
				Models: map[string]ModelConfig{
					"gpt-4": {
						ContextWindow: 8192,
						MaxOutput:     4096,
						PricingInput:  30.00,
						PricingOutput: 60.00,
					},
				},
			},
			expectError: false,
		},
		{
			name: "empty provider type",
			config: ProviderConfig{
				Type:         "",
				APIKey:       "test-key",
				DefaultModel: "model",
			},
			expectError: true,
			errorMsg:    "provider type cannot be empty",
		},
		{
			name: "invalid provider type",
			config: ProviderConfig{
				Type:         "invalid",
				APIKey:       "test-key",
				DefaultModel: "model",
			},
			expectError: true,
			errorMsg:    "invalid provider type",
		},
		{
			name: "empty api key",
			config: ProviderConfig{
				Type:         ProviderAnthropic,
				APIKey:       "",
				DefaultModel: "claude-3-opus",
			},
			expectError: true,
			errorMsg:    "api_key cannot be empty",
		},
		{
			name: "empty default model",
			config: ProviderConfig{
				Type:         ProviderAnthropic,
				APIKey:       "test-key",
				DefaultModel: "",
			},
			expectError: true,
			errorMsg:    "default_model cannot be empty",
		},
		{
			name: "default model not in models map",
			config: ProviderConfig{
				Type:         ProviderAnthropic,
				APIKey:       "test-key",
				DefaultModel: "nonexistent",
				Models: map[string]ModelConfig{
					"claude-3-opus": {
						ContextWindow: 200000,
						MaxOutput:     4096,
						PricingInput:  15.00,
						PricingOutput: 75.00,
					},
				},
			},
			expectError: true,
			errorMsg:    "default_model 'nonexistent' not found in models map",
		},
		{
			name: "invalid model configuration",
			config: ProviderConfig{
				Type:         ProviderAnthropic,
				APIKey:       "test-key",
				DefaultModel: "claude-3-opus",
				Models: map[string]ModelConfig{
					"claude-3-opus": {
						ContextWindow: 0, // Invalid
						MaxOutput:     4096,
						PricingInput:  15.00,
						PricingOutput: 75.00,
					},
				},
			},
			expectError: true,
		},
		{
			name: "valid configuration without models map",
			config: ProviderConfig{
				Type:         ProviderGoogle,
				APIKey:       "test-key",
				DefaultModel: "gemini-pro",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.expectError {
				require.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestModelConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		config      ModelConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid configuration",
			config: ModelConfig{
				ContextWindow: 200000,
				MaxOutput:     4096,
				Features:      []ModelFeature{FeatureChat, FeatureTools, FeatureStreaming},
				PricingInput:  15.00,
				PricingOutput: 75.00,
			},
			expectError: false,
		},
		{
			name: "zero context window",
			config: ModelConfig{
				ContextWindow: 0,
				MaxOutput:     4096,
				PricingInput:  15.00,
				PricingOutput: 75.00,
			},
			expectError: true,
			errorMsg:    "context_window must be greater than 0",
		},
		{
			name: "negative context window",
			config: ModelConfig{
				ContextWindow: -1000,
				MaxOutput:     4096,
				PricingInput:  15.00,
				PricingOutput: 75.00,
			},
			expectError: true,
			errorMsg:    "context_window must be greater than 0",
		},
		{
			name: "zero max output",
			config: ModelConfig{
				ContextWindow: 8192,
				MaxOutput:     0,
				PricingInput:  15.00,
				PricingOutput: 75.00,
			},
			expectError: true,
			errorMsg:    "max_output must be greater than 0",
		},
		{
			name: "max output exceeds context window",
			config: ModelConfig{
				ContextWindow: 8192,
				MaxOutput:     10000,
				PricingInput:  15.00,
				PricingOutput: 75.00,
			},
			expectError: true,
			errorMsg:    "max_output (10000) cannot exceed context_window (8192)",
		},
		{
			name: "negative input pricing",
			config: ModelConfig{
				ContextWindow: 8192,
				MaxOutput:     4096,
				PricingInput:  -1.00,
				PricingOutput: 75.00,
			},
			expectError: true,
			errorMsg:    "pricing_input must be non-negative",
		},
		{
			name: "negative output pricing",
			config: ModelConfig{
				ContextWindow: 8192,
				MaxOutput:     4096,
				PricingInput:  15.00,
				PricingOutput: -1.00,
			},
			expectError: true,
			errorMsg:    "pricing_output must be non-negative",
		},
		{
			name: "zero pricing is valid",
			config: ModelConfig{
				ContextWindow: 8192,
				MaxOutput:     4096,
				PricingInput:  0.00,
				PricingOutput: 0.00,
			},
			expectError: false,
		},
		{
			name: "invalid feature",
			config: ModelConfig{
				ContextWindow: 8192,
				MaxOutput:     4096,
				Features:      []ModelFeature{"invalid_feature"},
				PricingInput:  15.00,
				PricingOutput: 75.00,
			},
			expectError: true,
			errorMsg:    "invalid feature",
		},
		{
			name: "all valid features",
			config: ModelConfig{
				ContextWindow: 8192,
				MaxOutput:     4096,
				Features: []ModelFeature{
					FeatureChat,
					FeatureCompletion,
					FeatureVision,
					FeatureTools,
					FeatureStreaming,
					FeatureJSON,
				},
				PricingInput:  15.00,
				PricingOutput: 75.00,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.expectError {
				require.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestModelConfig_HasFeature(t *testing.T) {
	tests := []struct {
		name     string
		config   ModelConfig
		feature  ModelFeature
		expected bool
	}{
		{
			name: "feature exists",
			config: ModelConfig{
				Features: []ModelFeature{FeatureChat, FeatureTools, FeatureStreaming},
			},
			feature:  FeatureChat,
			expected: true,
		},
		{
			name: "feature does not exist",
			config: ModelConfig{
				Features: []ModelFeature{FeatureChat, FeatureTools},
			},
			feature:  FeatureVision,
			expected: false,
		},
		{
			name:     "nil features",
			config:   ModelConfig{},
			feature:  FeatureChat,
			expected: false,
		},
		{
			name: "empty features",
			config: ModelConfig{
				Features: []ModelFeature{},
			},
			feature:  FeatureChat,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.HasFeature(tt.feature)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestProviderConfig_GetBaseURL(t *testing.T) {
	tests := []struct {
		name     string
		config   ProviderConfig
		expected string
	}{
		{
			name: "custom base url",
			config: ProviderConfig{
				Type:    ProviderAnthropic,
				BaseURL: "https://custom.api.com",
			},
			expected: "https://custom.api.com",
		},
		{
			name: "anthropic default",
			config: ProviderConfig{
				Type: ProviderAnthropic,
			},
			expected: "https://api.anthropic.com",
		},
		{
			name: "openai default",
			config: ProviderConfig{
				Type: ProviderOpenAI,
			},
			expected: "https://api.openai.com/v1",
		},
		{
			name: "google default",
			config: ProviderConfig{
				Type: ProviderGoogle,
			},
			expected: "https://generativelanguage.googleapis.com/v1beta",
		},
		{
			name: "custom type no url",
			config: ProviderConfig{
				Type: ProviderCustom,
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.GetBaseURL()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestProviderConfig_GetModel(t *testing.T) {
	config := ProviderConfig{
		Models: map[string]ModelConfig{
			"model-1": {
				ContextWindow: 8192,
				MaxOutput:     4096,
			},
			"model-2": {
				ContextWindow: 16384,
				MaxOutput:     8192,
			},
		},
	}

	t.Run("existing model", func(t *testing.T) {
		model := config.GetModel("model-1")
		require.NotNil(t, model)
		assert.Equal(t, 8192, model.ContextWindow)
		assert.Equal(t, 4096, model.MaxOutput)
	})

	t.Run("non-existing model", func(t *testing.T) {
		model := config.GetModel("nonexistent")
		assert.Nil(t, model)
	})

	t.Run("nil models map", func(t *testing.T) {
		emptyConfig := ProviderConfig{}
		model := emptyConfig.GetModel("any")
		assert.Nil(t, model)
	})
}

func TestNormalizeProviderName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Anthropic", "anthropic"},
		{"OPENAI", "openai"},
		{"  Google  ", "google"},
		{"custom", "custom"},
		{"  MixedCase  ", "mixedcase"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := NormalizeProviderName(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNormalizeModelName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Claude-3-Opus", "claude-3-opus"},
		{"GPT-4-TURBO", "gpt-4-turbo"},
		{"  gemini-pro  ", "gemini-pro"},
		{"MODEL", "model"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := NormalizeModelName(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestProviderType_Constants(t *testing.T) {
	// Verify that provider type constants are defined correctly
	assert.Equal(t, ProviderType("anthropic"), ProviderAnthropic)
	assert.Equal(t, ProviderType("openai"), ProviderOpenAI)
	assert.Equal(t, ProviderType("google"), ProviderGoogle)
	assert.Equal(t, ProviderType("ollama"), ProviderOllama)
	assert.Equal(t, ProviderType("bedrock"), ProviderBedrock)
	assert.Equal(t, ProviderType("cloudflare"), ProviderCloudflare)
	assert.Equal(t, ProviderType("cohere"), ProviderCohere)
	assert.Equal(t, ProviderType("huggingface"), ProviderHuggingFace)
	assert.Equal(t, ProviderType("llamafile"), ProviderLlamafile)
	assert.Equal(t, ProviderType("mistral"), ProviderMistral)
	assert.Equal(t, ProviderType("custom"), ProviderCustom)
}

func TestSupportedProviderTypes(t *testing.T) {
	got := SupportedProviderTypes()
	// Spot-check every constant is present and no duplicates exist.
	seen := make(map[ProviderType]bool, len(got))
	for _, p := range got {
		assert.False(t, seen[p], "duplicate provider type in SupportedProviderTypes: %s", p)
		seen[p] = true
	}
	// Anchor the full enum so adding/removing a provider must update this test.
	expected := []ProviderType{
		ProviderAnthropic, ProviderOpenAI, ProviderGoogle, ProviderOllama,
		ProviderBedrock, ProviderCloudflare, ProviderCohere,
		ProviderHuggingFace, ProviderLlamafile,
		ProviderMistral, ProviderCustom,
	}
	assert.ElementsMatch(t, expected, got, "SupportedProviderTypes drift")
}

// TestSupportedProviderTypes_ParityWithOneofTag asserts that every type in
// SupportedProviderTypes() appears in the ProviderConfig.Type struct-tag
// `oneof=` list, and vice versa. Drift here means either the struct tag or
// the helper was updated without the other.
func TestSupportedProviderTypes_ParityWithOneofTag(t *testing.T) {
	typ := reflect.TypeOf(ProviderConfig{})
	field, ok := typ.FieldByName("Type")
	require.True(t, ok, "ProviderConfig.Type field missing")

	rawTag := field.Tag.Get("validate")
	// rawTag looks like: required,oneof=anthropic openai google ... custom
	var oneofList string
	for _, part := range strings.Split(rawTag, ",") {
		if strings.HasPrefix(part, "oneof=") {
			oneofList = strings.TrimPrefix(part, "oneof=")
			break
		}
	}
	require.NotEmpty(t, oneofList, "oneof= clause missing from ProviderConfig.Type validate tag: %q", rawTag)

	tagSet := make(map[string]bool)
	for _, name := range strings.Fields(oneofList) {
		tagSet[name] = true
	}

	for _, p := range SupportedProviderTypes() {
		assert.True(t, tagSet[string(p)],
			"provider type %q is in SupportedProviderTypes() but missing from `oneof=` struct tag", p)
		delete(tagSet, string(p))
	}
	assert.Empty(t, tagSet,
		"`oneof=` struct tag contains provider types not in SupportedProviderTypes(): %v", tagSet)
}

func TestProviderType_IsSelfHosted(t *testing.T) {
	selfHosted := []ProviderType{ProviderOllama, ProviderLlamafile}
	for _, p := range selfHosted {
		assert.True(t, p.IsSelfHosted(), "%s should be self-hosted", p)
	}
	hosted := []ProviderType{
		ProviderAnthropic, ProviderOpenAI, ProviderGoogle,
		ProviderBedrock, ProviderCloudflare, ProviderCohere,
		ProviderHuggingFace, ProviderMistral,
		ProviderCustom,
	}
	for _, p := range hosted {
		assert.False(t, p.IsSelfHosted(), "%s should not be self-hosted", p)
	}
}

func TestProviderConfig_Validate_NewProviders(t *testing.T) {
	tests := []struct {
		name    string
		cfg     ProviderConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "bedrock accepts extra map with aws creds and no api_key",
			cfg: ProviderConfig{
				Type:         ProviderBedrock,
				APIKey:       "unused-but-accepted",
				DefaultModel: "anthropic.claude-3-5-sonnet-20241022-v2:0",
				Extra: map[string]string{
					"aws_access_key_id":     "AKIA...",
					"aws_secret_access_key": "secret",
					"aws_region":            "us-east-1",
				},
			},
		},
		{
			name: "mistral requires api_key",
			cfg: ProviderConfig{
				Type:         ProviderMistral,
				DefaultModel: "mistral-large-latest",
			},
			wantErr: true,
			errMsg:  "api_key cannot be empty",
		},
		{
			name: "llamafile accepts empty api_key (self-hosted)",
			cfg: ProviderConfig{
				Type:         ProviderLlamafile,
				DefaultModel: "llamafile-local",
				BaseURL:      "http://localhost:8080",
			},
		},
		{
			name: "ollama accepts empty api_key (self-hosted)",
			cfg: ProviderConfig{
				Type:         ProviderOllama,
				DefaultModel: "llama3.1:8b",
				BaseURL:      "http://localhost:11434",
			},
		},
		{
			name: "unknown type rejected",
			cfg: ProviderConfig{
				Type:         ProviderType("vaporware"),
				APIKey:       "k",
				DefaultModel: "m",
			},
			wantErr: true,
			errMsg:  "invalid provider type",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestProviderConfig_ExtraField_Roundtrip(t *testing.T) {
	cfg := ProviderConfig{
		Type:         ProviderBedrock,
		APIKey:       "key",
		DefaultModel: "anthropic.claude-3-haiku-20240307-v1:0",
		Extra: map[string]string{
			"aws_access_key_id":     "AKIA...",
			"aws_secret_access_key": "secret",
			"aws_region":            "us-east-1",
		},
	}
	require.NoError(t, cfg.Validate())
	assert.Equal(t, "us-east-1", cfg.Extra["aws_region"])
}

func TestModelFeature_Constants(t *testing.T) {
	// Verify that feature constants are defined correctly
	assert.Equal(t, ModelFeature("chat"), FeatureChat)
	assert.Equal(t, ModelFeature("completion"), FeatureCompletion)
	assert.Equal(t, ModelFeature("vision"), FeatureVision)
	assert.Equal(t, ModelFeature("tools"), FeatureTools)
	assert.Equal(t, ModelFeature("streaming"), FeatureStreaming)
	assert.Equal(t, ModelFeature("json"), FeatureJSON)
}

// Benchmark tests
func BenchmarkLLMConfig_Validate(b *testing.B) {
	config := LLMConfig{
		DefaultProvider: "anthropic",
		Providers: map[string]ProviderConfig{
			"anthropic": {
				Type:         ProviderAnthropic,
				APIKey:       "test-key",
				DefaultModel: "claude-3-opus",
				Models: map[string]ModelConfig{
					"claude-3-opus": {
						ContextWindow: 200000,
						MaxOutput:     4096,
						Features:      []ModelFeature{FeatureChat, FeatureTools},
						PricingInput:  15.00,
						PricingOutput: 75.00,
					},
				},
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = config.Validate()
	}
}

func BenchmarkModelConfig_HasFeature(b *testing.B) {
	config := ModelConfig{
		Features: []ModelFeature{FeatureChat, FeatureTools, FeatureStreaming, FeatureJSON},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = config.HasFeature(FeatureVision)
	}
}
