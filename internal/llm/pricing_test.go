package llm

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/types"
)

func TestNewPricingConfig(t *testing.T) {
	config := NewPricingConfig()
	require.NotNil(t, config)
	assert.NotNil(t, config.Pricing)
	assert.Equal(t, 0, len(config.Pricing))
}

func TestDefaultPricing(t *testing.T) {
	config := DefaultPricing()
	require.NotNil(t, config)

	// Test Anthropic pricing
	t.Run("anthropic pricing exists", func(t *testing.T) {
		anthropic, exists := config.Pricing["anthropic"]
		require.True(t, exists)
		assert.NotEmpty(t, anthropic)

		// Test Claude 3 Opus
		opus := anthropic["claude-3-opus-20240229"]
		assert.Equal(t, 15.00, opus.InputPer1M)
		assert.Equal(t, 75.00, opus.OutputPer1M)

		// Test Claude 3 Sonnet
		sonnet := anthropic["claude-3-sonnet-20240229"]
		assert.Equal(t, 3.00, sonnet.InputPer1M)
		assert.Equal(t, 15.00, sonnet.OutputPer1M)

		// Test Claude 3 Haiku
		haiku := anthropic["claude-3-haiku-20240307"]
		assert.Equal(t, 0.25, haiku.InputPer1M)
		assert.Equal(t, 1.25, haiku.OutputPer1M)

		// Test Claude 3.5 Sonnet
		sonnet35 := anthropic["claude-3-5-sonnet-20240620"]
		assert.Equal(t, 3.00, sonnet35.InputPer1M)
		assert.Equal(t, 15.00, sonnet35.OutputPer1M)
	})

	// Test OpenAI pricing
	t.Run("openai pricing exists", func(t *testing.T) {
		openai, exists := config.Pricing["openai"]
		require.True(t, exists)
		assert.NotEmpty(t, openai)

		// Test GPT-4 Turbo
		gpt4turbo := openai["gpt-4-turbo"]
		assert.Equal(t, 10.00, gpt4turbo.InputPer1M)
		assert.Equal(t, 30.00, gpt4turbo.OutputPer1M)

		// Test GPT-4
		gpt4 := openai["gpt-4"]
		assert.Equal(t, 30.00, gpt4.InputPer1M)
		assert.Equal(t, 60.00, gpt4.OutputPer1M)

		// Test GPT-3.5 Turbo
		gpt35 := openai["gpt-3.5-turbo"]
		assert.Equal(t, 0.50, gpt35.InputPer1M)
		assert.Equal(t, 1.50, gpt35.OutputPer1M)
	})

	// Test Google pricing
	t.Run("google pricing exists", func(t *testing.T) {
		google, exists := config.Pricing["google"]
		require.True(t, exists)
		assert.NotEmpty(t, google)

		// Test Gemini 1.5 Pro
		geminiPro := google["gemini-1.5-pro"]
		assert.Equal(t, 7.00, geminiPro.InputPer1M)
		assert.Equal(t, 21.00, geminiPro.OutputPer1M)

		// Test Gemini 1.5 Flash
		geminiFlash := google["gemini-1.5-flash"]
		assert.Equal(t, 0.35, geminiFlash.InputPer1M)
		assert.Equal(t, 1.05, geminiFlash.OutputPer1M)
	})

	// Test model aliases
	t.Run("model aliases exist", func(t *testing.T) {
		anthropic := config.Pricing["anthropic"]

		// Test that both versioned and non-versioned names exist
		_, hasVersioned := anthropic["claude-3-opus-20240229"]
		_, hasShort := anthropic["claude-3-opus"]
		assert.True(t, hasVersioned)
		assert.True(t, hasShort)
	})
}

func TestPricingConfig_SetProviderPricing(t *testing.T) {
	config := NewPricingConfig()

	pricing := map[string]ModelPricing{
		"model-1": {InputPer1M: 10.00, OutputPer1M: 20.00},
		"model-2": {InputPer1M: 5.00, OutputPer1M: 10.00},
	}

	config.SetProviderPricing("testprovider", pricing)

	provider, exists := config.Pricing["testprovider"]
	require.True(t, exists)
	assert.Equal(t, 2, len(provider))
	assert.Equal(t, 10.00, provider["model-1"].InputPer1M)
	assert.Equal(t, 20.00, provider["model-1"].OutputPer1M)
}

func TestPricingConfig_SetModelPricing(t *testing.T) {
	config := NewPricingConfig()

	pricing := ModelPricing{
		InputPer1M:  15.00,
		OutputPer1M: 75.00,
	}

	config.SetModelPricing("anthropic", "claude-3-opus", pricing)

	model := config.GetModelPricing("anthropic", "claude-3-opus")
	require.NotNil(t, model)
	assert.Equal(t, 15.00, model.InputPer1M)
	assert.Equal(t, 75.00, model.OutputPer1M)
}

func TestPricingConfig_GetModelPricing(t *testing.T) {
	config := DefaultPricing()

	tests := []struct {
		name     string
		provider string
		model    string
		exists   bool
	}{
		{
			name:     "existing model",
			provider: "anthropic",
			model:    "claude-3-opus-20240229",
			exists:   true,
		},
		{
			name:     "non-existing model",
			provider: "anthropic",
			model:    "nonexistent",
			exists:   false,
		},
		{
			name:     "non-existing provider",
			provider: "nonexistent",
			model:    "model",
			exists:   false,
		},
		{
			name:     "case insensitive provider",
			provider: "ANTHROPIC",
			model:    "claude-3-opus-20240229",
			exists:   true,
		},
		{
			name:     "case insensitive model",
			provider: "anthropic",
			model:    "CLAUDE-3-OPUS-20240229",
			exists:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pricing := config.GetModelPricing(tt.provider, tt.model)
			if tt.exists {
				assert.NotNil(t, pricing)
			} else {
				assert.Nil(t, pricing)
			}
		})
	}
}

func TestModelPricing_CalculateCost(t *testing.T) {
	tests := []struct {
		name         string
		pricing      ModelPricing
		usage        TokenUsage
		expectedCost float64
	}{
		{
			name: "claude 3 opus - 1M input, 1M output",
			pricing: ModelPricing{
				InputPer1M:  15.00,
				OutputPer1M: 75.00,
			},
			usage: TokenUsage{
				InputTokens:  1_000_000,
				OutputTokens: 1_000_000,
			},
			expectedCost: 90.00, // 15 + 75
		},
		{
			name: "gpt-3.5-turbo - 100k input, 50k output",
			pricing: ModelPricing{
				InputPer1M:  0.50,
				OutputPer1M: 1.50,
			},
			usage: TokenUsage{
				InputTokens:  100_000,
				OutputTokens: 50_000,
			},
			expectedCost: 0.125, // (100k/1M)*0.5 + (50k/1M)*1.5 = 0.05 + 0.075
		},
		{
			name: "small usage - 1k input, 500 output",
			pricing: ModelPricing{
				InputPer1M:  3.00,
				OutputPer1M: 15.00,
			},
			usage: TokenUsage{
				InputTokens:  1_000,
				OutputTokens: 500,
			},
			expectedCost: 0.0105, // (1k/1M)*3 + (500/1M)*15 = 0.003 + 0.0075
		},
		{
			name: "zero usage",
			pricing: ModelPricing{
				InputPer1M:  15.00,
				OutputPer1M: 75.00,
			},
			usage: TokenUsage{
				InputTokens:  0,
				OutputTokens: 0,
			},
			expectedCost: 0.00,
		},
		{
			name: "only input tokens",
			pricing: ModelPricing{
				InputPer1M:  10.00,
				OutputPer1M: 30.00,
			},
			usage: TokenUsage{
				InputTokens:  500_000,
				OutputTokens: 0,
			},
			expectedCost: 5.00, // (500k/1M)*10
		},
		{
			name: "only output tokens",
			pricing: ModelPricing{
				InputPer1M:  10.00,
				OutputPer1M: 30.00,
			},
			usage: TokenUsage{
				InputTokens:  0,
				OutputTokens: 500_000,
			},
			expectedCost: 15.00, // (500k/1M)*30
		},
		{
			name: "free model",
			pricing: ModelPricing{
				InputPer1M:  0.00,
				OutputPer1M: 0.00,
			},
			usage: TokenUsage{
				InputTokens:  1_000_000,
				OutputTokens: 1_000_000,
			},
			expectedCost: 0.00,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cost := tt.pricing.CalculateCost(tt.usage)
			assert.InDelta(t, tt.expectedCost, cost, 0.0001, "Cost calculation mismatch")
		})
	}
}

func TestPricingConfig_CalculateCost(t *testing.T) {
	config := DefaultPricing()

	tests := []struct {
		name         string
		provider     string
		model        string
		usage        TokenUsage
		expectError  bool
		expectedCost float64
	}{
		{
			name:     "claude 3 opus calculation",
			provider: "anthropic",
			model:    "claude-3-opus-20240229",
			usage: TokenUsage{
				InputTokens:  10_000,
				OutputTokens: 5_000,
			},
			expectError:  false,
			expectedCost: 0.525, // (10k/1M)*15 + (5k/1M)*75 = 0.15 + 0.375
		},
		{
			name:     "gpt-4 calculation",
			provider: "openai",
			model:    "gpt-4",
			usage: TokenUsage{
				InputTokens:  20_000,
				OutputTokens: 10_000,
			},
			expectError:  false,
			expectedCost: 1.2, // (20k/1M)*30 + (10k/1M)*60 = 0.6 + 0.6
		},
		{
			name:     "non-existing model",
			provider: "anthropic",
			model:    "nonexistent",
			usage: TokenUsage{
				InputTokens:  10_000,
				OutputTokens: 5_000,
			},
			expectError: true,
		},
		{
			name:     "non-existing provider",
			provider: "nonexistent",
			model:    "model",
			usage: TokenUsage{
				InputTokens:  10_000,
				OutputTokens: 5_000,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cost, err := config.CalculateCost(tt.provider, tt.model, tt.usage)

			if tt.expectError {
				require.Error(t, err)
				var gibsonErr *types.GibsonError
				require.ErrorAs(t, err, &gibsonErr)
				assert.Equal(t, types.CONFIG_VALIDATION_FAILED, gibsonErr.Code)
			} else {
				require.NoError(t, err)
				assert.InDelta(t, tt.expectedCost, cost, 0.0001)
			}
		})
	}
}

func TestPricingConfig_EstimateCost(t *testing.T) {
	config := DefaultPricing()

	cost, err := config.EstimateCost("anthropic", "claude-3-haiku-20240307", 10_000, 5_000)
	require.NoError(t, err)
	// (10k/1M)*0.25 + (5k/1M)*1.25 = 0.0025 + 0.00625 = 0.00875
	assert.InDelta(t, 0.00875, cost, 0.0001)
}

func TestPricingConfig_GetAllProviders(t *testing.T) {
	config := DefaultPricing()

	providers := config.GetAllProviders()
	// Every provider with a DefaultPricing() entry must be listed here. Drift
	// in this list means DefaultPricing added/removed a provider without
	// updating the test.
	expected := []string{
		"anthropic", "openai", "google",
		"bedrock", "cloudflare", "cohere", "mistral", "huggingface", "maritaca",
		"ernie", "watsonx",
		"ollama", "llamafile", "local",
	}
	for _, p := range expected {
		assert.Contains(t, providers, p, "missing provider %q in DefaultPricing", p)
	}
	assert.Equal(t, len(expected), len(providers), "unexpected number of pricing providers")
}

func TestPricingConfig_GetProviderModels(t *testing.T) {
	config := DefaultPricing()

	t.Run("existing provider", func(t *testing.T) {
		models := config.GetProviderModels("anthropic")
		assert.NotEmpty(t, models)
		assert.Contains(t, models, "claude-3-opus-20240229")
		assert.Contains(t, models, "claude-3-sonnet-20240229")
		assert.Contains(t, models, "claude-3-haiku-20240307")
	})

	t.Run("non-existing provider", func(t *testing.T) {
		models := config.GetProviderModels("nonexistent")
		assert.Empty(t, models)
	})

	t.Run("case insensitive", func(t *testing.T) {
		models := config.GetProviderModels("ANTHROPIC")
		assert.NotEmpty(t, models)
	})
}

func TestPricingConfig_HasPricing(t *testing.T) {
	config := DefaultPricing()

	tests := []struct {
		name     string
		provider string
		model    string
		expected bool
	}{
		{
			name:     "existing model",
			provider: "anthropic",
			model:    "claude-3-opus-20240229",
			expected: true,
		},
		{
			name:     "non-existing model",
			provider: "anthropic",
			model:    "nonexistent",
			expected: false,
		},
		{
			name:     "non-existing provider",
			provider: "nonexistent",
			model:    "model",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := config.HasPricing(tt.provider, tt.model)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPricingConfig_MergePricing(t *testing.T) {
	config1 := NewPricingConfig()
	config1.SetModelPricing("provider1", "model1", ModelPricing{InputPer1M: 10.00, OutputPer1M: 20.00})
	config1.SetModelPricing("provider2", "model2", ModelPricing{InputPer1M: 5.00, OutputPer1M: 10.00})

	config2 := NewPricingConfig()
	config2.SetModelPricing("provider1", "model3", ModelPricing{InputPer1M: 15.00, OutputPer1M: 30.00})
	config2.SetModelPricing("provider3", "model4", ModelPricing{InputPer1M: 1.00, OutputPer1M: 2.00})

	config1.MergePricing(config2)

	// Check that all models exist
	assert.True(t, config1.HasPricing("provider1", "model1"))
	assert.True(t, config1.HasPricing("provider1", "model3"))
	assert.True(t, config1.HasPricing("provider2", "model2"))
	assert.True(t, config1.HasPricing("provider3", "model4"))

	// Verify pricing values
	pricing := config1.GetModelPricing("provider3", "model4")
	require.NotNil(t, pricing)
	assert.Equal(t, 1.00, pricing.InputPer1M)
	assert.Equal(t, 2.00, pricing.OutputPer1M)
}

func TestPricingConfig_MergePricingOverwrite(t *testing.T) {
	config1 := NewPricingConfig()
	config1.SetModelPricing("provider1", "model1", ModelPricing{InputPer1M: 10.00, OutputPer1M: 20.00})

	config2 := NewPricingConfig()
	config2.SetModelPricing("provider1", "model1", ModelPricing{InputPer1M: 15.00, OutputPer1M: 30.00})

	config1.MergePricing(config2)

	pricing := config1.GetModelPricing("provider1", "model1")
	require.NotNil(t, pricing)
	assert.Equal(t, 15.00, pricing.InputPer1M)
	assert.Equal(t, 30.00, pricing.OutputPer1M)
}

func TestPricingConfig_MergePricingNil(t *testing.T) {
	config := NewPricingConfig()
	config.SetModelPricing("provider1", "model1", ModelPricing{InputPer1M: 10.00, OutputPer1M: 20.00})

	// Should not panic
	config.MergePricing(nil)

	assert.True(t, config.HasPricing("provider1", "model1"))
}

func TestPricingConfig_ThreadSafety(t *testing.T) {
	config := DefaultPricing()
	var wg sync.WaitGroup

	// Test concurrent reads
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = config.GetModelPricing("anthropic", "claude-3-opus-20240229")
			_ = config.HasPricing("openai", "gpt-4")
			_ = config.GetAllProviders()
			_ = config.GetProviderModels("google")
		}()
	}

	// Test concurrent writes
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			config.SetModelPricing("test-provider", "test-model", ModelPricing{
				InputPer1M:  float64(index),
				OutputPer1M: float64(index * 2),
			})
		}(i)
	}

	wg.Wait()
}

func TestTokenUsage(t *testing.T) {
	usage := TokenUsage{
		InputTokens:  10_000,
		OutputTokens: 5_000,
	}

	assert.Equal(t, 10_000, usage.InputTokens)
	assert.Equal(t, 5_000, usage.OutputTokens)
}

// Benchmark tests
func BenchmarkModelPricing_CalculateCost(b *testing.B) {
	pricing := ModelPricing{
		InputPer1M:  15.00,
		OutputPer1M: 75.00,
	}
	usage := TokenUsage{
		InputTokens:  10_000,
		OutputTokens: 5_000,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = pricing.CalculateCost(usage)
	}
}

func BenchmarkPricingConfig_CalculateCost(b *testing.B) {
	config := DefaultPricing()
	usage := TokenUsage{
		InputTokens:  10_000,
		OutputTokens: 5_000,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = config.CalculateCost("anthropic", "claude-3-opus-20240229", usage)
	}
}

func BenchmarkPricingConfig_GetModelPricing(b *testing.B) {
	config := DefaultPricing()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = config.GetModelPricing("anthropic", "claude-3-opus-20240229")
	}
}

func BenchmarkPricingConfig_SetModelPricing(b *testing.B) {
	config := NewPricingConfig()
	pricing := ModelPricing{InputPer1M: 15.00, OutputPer1M: 75.00}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		config.SetModelPricing("anthropic", "claude-3-opus", pricing)
	}
}
