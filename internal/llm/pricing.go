package llm

import (
	"fmt"
	"sync"

	"github.com/zero-day-ai/gibson/internal/types"
)

// TokenUsage represents the number of tokens used in a request.
type TokenUsage struct {
	InputTokens  int
	OutputTokens int
}

// ModelPricing contains pricing information for a specific model.
// Prices are specified per 1 million tokens.
type ModelPricing struct {
	InputPer1M  float64 `mapstructure:"input_per_1m" yaml:"input_per_1m" validate:"min=0"`
	OutputPer1M float64 `mapstructure:"output_per_1m" yaml:"output_per_1m" validate:"min=0"`

	// SelfHosted is true for providers running on operator-controlled
	// infrastructure (ollama, llamafile, local) — cost is always zero by
	// convention. Distinguishes "free" from "unknown".
	SelfHosted bool `mapstructure:"self_hosted" yaml:"self_hosted"`

	// Unknown is true when the provider has a public rate card but Gibson
	// has not been configured with the rates (e.g. IBM WatsonX custom
	// deployments). The token tracker emits a WARN log and records zero
	// cost rather than poisoning metrics with a false zero.
	Unknown bool `mapstructure:"unknown" yaml:"unknown"`
}

// PricingConfig manages pricing information for all providers and models.
// It maintains a hierarchical map structure: provider -> model -> pricing.
type PricingConfig struct {
	mu      sync.RWMutex
	Pricing map[string]map[string]ModelPricing `mapstructure:"pricing" yaml:"pricing"`
}

// NewPricingConfig creates a new PricingConfig with default pricing data.
func NewPricingConfig() *PricingConfig {
	return &PricingConfig{
		Pricing: make(map[string]map[string]ModelPricing),
	}
}

// DefaultPricing returns a PricingConfig populated with known model prices
// for major LLM providers as of January 2025.
func DefaultPricing() *PricingConfig {
	config := NewPricingConfig()

	// Anthropic Claude pricing
	config.Pricing["anthropic"] = map[string]ModelPricing{
		// Claude 3 Opus - Most powerful model
		"claude-3-opus-20240229": {
			InputPer1M:  15.00,
			OutputPer1M: 75.00,
		},
		"claude-3-opus": {
			InputPer1M:  15.00,
			OutputPer1M: 75.00,
		},
		// Claude 3 Sonnet - Balanced performance/cost
		"claude-3-sonnet-20240229": {
			InputPer1M:  3.00,
			OutputPer1M: 15.00,
		},
		"claude-3-sonnet": {
			InputPer1M:  3.00,
			OutputPer1M: 15.00,
		},
		// Claude 3.5 Sonnet - Enhanced Sonnet
		"claude-3-5-sonnet-20240620": {
			InputPer1M:  3.00,
			OutputPer1M: 15.00,
		},
		"claude-3-5-sonnet": {
			InputPer1M:  3.00,
			OutputPer1M: 15.00,
		},
		// Claude 3 Haiku - Fastest and most cost-effective
		"claude-3-haiku-20240307": {
			InputPer1M:  0.25,
			OutputPer1M: 1.25,
		},
		"claude-3-haiku": {
			InputPer1M:  0.25,
			OutputPer1M: 1.25,
		},
	}

	// OpenAI pricing
	config.Pricing["openai"] = map[string]ModelPricing{
		// GPT-4 Turbo - Latest GPT-4 model
		"gpt-4-turbo": {
			InputPer1M:  10.00,
			OutputPer1M: 30.00,
		},
		"gpt-4-turbo-preview": {
			InputPer1M:  10.00,
			OutputPer1M: 30.00,
		},
		"gpt-4-0125-preview": {
			InputPer1M:  10.00,
			OutputPer1M: 30.00,
		},
		"gpt-4-1106-preview": {
			InputPer1M:  10.00,
			OutputPer1M: 30.00,
		},
		// GPT-4 - Original GPT-4 models
		"gpt-4": {
			InputPer1M:  30.00,
			OutputPer1M: 60.00,
		},
		"gpt-4-0613": {
			InputPer1M:  30.00,
			OutputPer1M: 60.00,
		},
		"gpt-4-32k": {
			InputPer1M:  60.00,
			OutputPer1M: 120.00,
		},
		// GPT-3.5 Turbo - Most cost-effective
		"gpt-3.5-turbo": {
			InputPer1M:  0.50,
			OutputPer1M: 1.50,
		},
		"gpt-3.5-turbo-0125": {
			InputPer1M:  0.50,
			OutputPer1M: 1.50,
		},
		"gpt-3.5-turbo-1106": {
			InputPer1M:  1.00,
			OutputPer1M: 2.00,
		},
		"gpt-3.5-turbo-16k": {
			InputPer1M:  3.00,
			OutputPer1M: 4.00,
		},
	}

	// AWS Bedrock pricing (mirrors the upstream model family's published per-1M rates)
	config.Pricing["bedrock"] = map[string]ModelPricing{
		"anthropic.claude-3-opus-20240229-v1:0":    {InputPer1M: 15.00, OutputPer1M: 75.00},
		"anthropic.claude-3-sonnet-20240229-v1:0":  {InputPer1M: 3.00, OutputPer1M: 15.00},
		"anthropic.claude-3-haiku-20240307-v1:0":   {InputPer1M: 0.25, OutputPer1M: 1.25},
		"anthropic.claude-3-5-sonnet-20241022-v2:0": {InputPer1M: 3.00, OutputPer1M: 15.00},
		"anthropic.claude-3-5-haiku-20241022-v1:0":  {InputPer1M: 1.00, OutputPer1M: 5.00},
		"amazon.titan-text-lite-v1":                {InputPer1M: 0.15, OutputPer1M: 0.20},
		"amazon.titan-text-express-v1":             {InputPer1M: 0.20, OutputPer1M: 0.60},
		"us.amazon.nova-micro-v1:0":                {InputPer1M: 0.035, OutputPer1M: 0.14},
		"us.amazon.nova-lite-v1:0":                 {InputPer1M: 0.06, OutputPer1M: 0.24},
		"us.amazon.nova-pro-v1:0":                  {InputPer1M: 0.80, OutputPer1M: 3.20},
		"meta.llama3-8b-instruct-v1:0":             {InputPer1M: 0.30, OutputPer1M: 0.60},
		"meta.llama3-70b-instruct-v1:0":            {InputPer1M: 2.65, OutputPer1M: 3.50},
		"mistral.mistral-large-2407-v1:0":          {InputPer1M: 3.00, OutputPer1M: 9.00},
	}

	// Cloudflare Workers AI — per-neuron pricing converted to rough per-1M
	// estimates for budgeting. Cloudflare's pricing model is neuron-based so
	// exact conversions vary by model; treat these as advisory.
	config.Pricing["cloudflare"] = map[string]ModelPricing{
		"@cf/meta/llama-3.1-8b-instruct":         {InputPer1M: 0.11, OutputPer1M: 0.11},
		"@cf/meta/llama-3-8b-instruct":           {InputPer1M: 0.11, OutputPer1M: 0.11},
		"@cf/mistral/mistral-7b-instruct-v0.1":   {InputPer1M: 0.11, OutputPer1M: 0.11},
		"@cf/google/gemma-7b-it":                 {InputPer1M: 0.11, OutputPer1M: 0.11},
	}

	// Cohere pricing
	config.Pricing["cohere"] = map[string]ModelPricing{
		"command-r-plus":   {InputPer1M: 2.50, OutputPer1M: 10.00},
		"command-r":        {InputPer1M: 0.15, OutputPer1M: 0.60},
		"command":          {InputPer1M: 1.00, OutputPer1M: 2.00},
		"command-light":    {InputPer1M: 0.30, OutputPer1M: 0.60},
	}

	// Mistral La Plateforme pricing
	config.Pricing["mistral"] = map[string]ModelPricing{
		"mistral-large-latest":  {InputPer1M: 2.00, OutputPer1M: 6.00},
		"mistral-medium-latest": {InputPer1M: 2.70, OutputPer1M: 8.10},
		"mistral-small-latest":  {InputPer1M: 0.20, OutputPer1M: 0.60},
		"codestral-latest":      {InputPer1M: 0.20, OutputPer1M: 0.60},
		"open-mistral-7b":       {InputPer1M: 0.25, OutputPer1M: 0.25},
		"open-mixtral-8x7b":     {InputPer1M: 0.70, OutputPer1M: 0.70},
		"open-mixtral-8x22b":    {InputPer1M: 2.00, OutputPer1M: 6.00},
	}

	// HuggingFace Inference API — public serverless is free-tier-gated with
	// enterprise metering variants. Rates here assume the standard plan.
	config.Pricing["huggingface"] = map[string]ModelPricing{
		"meta-llama/Llama-3.1-70B-Instruct":  {InputPer1M: 0.90, OutputPer1M: 0.90},
		"meta-llama/Llama-3.1-8B-Instruct":   {InputPer1M: 0.20, OutputPer1M: 0.20},
		"meta-llama/Llama-3-70B-Instruct":    {InputPer1M: 0.90, OutputPer1M: 0.90},
		"mistralai/Mixtral-8x7B-Instruct-v0.1": {InputPer1M: 0.60, OutputPer1M: 0.60},
	}

	// Maritaca (Brazilian LLM provider) pricing
	config.Pricing["maritaca"] = map[string]ModelPricing{
		"sabia-3":         {InputPer1M: 1.00, OutputPer1M: 3.00},
		"sabia-2-medium":  {InputPer1M: 0.50, OutputPer1M: 1.50},
		"sabia-2-small":   {InputPer1M: 0.10, OutputPer1M: 0.30},
	}

	// Baidu ERNIE — rates not publicly consistent; marked Unknown so the
	// tracker warns rather than reporting false zeros.
	config.Pricing["ernie"] = map[string]ModelPricing{
		"ernie-bot-4":     {Unknown: true},
		"ernie-bot-turbo": {Unknown: true},
		"ernie-bot":       {Unknown: true},
	}

	// IBM WatsonX — custom deployments have per-account pricing. Unknown flag
	// prevents false zeros in billing reports.
	config.Pricing["watsonx"] = map[string]ModelPricing{
		"ibm/granite-13b-chat-v2":            {Unknown: true},
		"ibm/granite-20b-multilingual":       {Unknown: true},
		"meta-llama/llama-3-70b-instruct":    {Unknown: true},
		"meta-llama/llama-3-8b-instruct":     {Unknown: true},
		"mistralai/mixtral-8x7b-instruct-v01": {Unknown: true},
	}

	// Self-hosted providers — zero cost by convention.
	config.Pricing["ollama"] = map[string]ModelPricing{
		"*": {SelfHosted: true},
	}
	config.Pricing["llamafile"] = map[string]ModelPricing{
		"*": {SelfHosted: true},
	}
	config.Pricing["local"] = map[string]ModelPricing{
		"*": {SelfHosted: true},
	}

	// Google Gemini pricing
	config.Pricing["google"] = map[string]ModelPricing{
		// Gemini 1.5 Pro
		"gemini-1.5-pro": {
			InputPer1M:  7.00,
			OutputPer1M: 21.00,
		},
		"gemini-1.5-pro-latest": {
			InputPer1M:  7.00,
			OutputPer1M: 21.00,
		},
		// Gemini 1.5 Flash - Faster and cheaper
		"gemini-1.5-flash": {
			InputPer1M:  0.35,
			OutputPer1M: 1.05,
		},
		"gemini-1.5-flash-latest": {
			InputPer1M:  0.35,
			OutputPer1M: 1.05,
		},
		// Gemini Pro (legacy)
		"gemini-pro": {
			InputPer1M:  0.50,
			OutputPer1M: 1.50,
		},
		// Gemini Pro Vision (legacy)
		"gemini-pro-vision": {
			InputPer1M:  0.50,
			OutputPer1M: 1.50,
		},
	}

	return config
}

// SetProviderPricing sets pricing for all models of a specific provider.
// This replaces any existing pricing data for the provider.
func (p *PricingConfig) SetProviderPricing(provider string, pricing map[string]ModelPricing) {
	p.mu.Lock()
	defer p.mu.Unlock()

	provider = NormalizeProviderName(provider)
	if p.Pricing == nil {
		p.Pricing = make(map[string]map[string]ModelPricing)
	}
	p.Pricing[provider] = pricing
}

// SetModelPricing sets pricing for a specific provider and model.
func (p *PricingConfig) SetModelPricing(provider, model string, pricing ModelPricing) {
	p.mu.Lock()
	defer p.mu.Unlock()

	provider = NormalizeProviderName(provider)
	model = NormalizeModelName(model)

	if p.Pricing == nil {
		p.Pricing = make(map[string]map[string]ModelPricing)
	}
	if p.Pricing[provider] == nil {
		p.Pricing[provider] = make(map[string]ModelPricing)
	}
	p.Pricing[provider][model] = pricing
}

// GetModelPricing retrieves pricing for a specific provider and model.
// Returns nil if pricing is not found.
func (p *PricingConfig) GetModelPricing(provider, model string) *ModelPricing {
	p.mu.RLock()
	defer p.mu.RUnlock()

	provider = NormalizeProviderName(provider)
	model = NormalizeModelName(model)

	if p.Pricing == nil {
		return nil
	}

	providerPricing, exists := p.Pricing[provider]
	if !exists {
		return nil
	}

	modelPricing, exists := providerPricing[model]
	if !exists {
		return nil
	}

	return &modelPricing
}

// CalculateCost calculates the cost for a given token usage with a specific provider and model.
// Returns the total cost in USD and any error encountered.
// Returns an error if pricing information is not available for the specified provider/model.
func (p *PricingConfig) CalculateCost(provider, model string, usage TokenUsage) (float64, error) {
	pricing := p.GetModelPricing(provider, model)
	if pricing == nil {
		return 0, types.NewError(
			types.CONFIG_VALIDATION_FAILED,
			fmt.Sprintf("pricing not found for provider '%s' model '%s'", provider, model),
		)
	}

	return pricing.CalculateCost(usage), nil
}

// CalculateCost calculates the total cost based on token usage.
// Cost = (InputTokens / 1,000,000 * InputPer1M) + (OutputTokens / 1,000,000 * OutputPer1M)
func (m *ModelPricing) CalculateCost(usage TokenUsage) float64 {
	inputCost := (float64(usage.InputTokens) / 1_000_000.0) * m.InputPer1M
	outputCost := (float64(usage.OutputTokens) / 1_000_000.0) * m.OutputPer1M
	return inputCost + outputCost
}

// EstimateCost estimates the cost for a given number of input and output tokens.
// This is a convenience method that creates a TokenUsage and calculates cost.
func (p *PricingConfig) EstimateCost(provider, model string, inputTokens, outputTokens int) (float64, error) {
	usage := TokenUsage{
		InputTokens:  inputTokens,
		OutputTokens: outputTokens,
	}
	return p.CalculateCost(provider, model, usage)
}

// GetAllProviders returns a list of all providers with pricing data.
func (p *PricingConfig) GetAllProviders() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	providers := make([]string, 0, len(p.Pricing))
	for provider := range p.Pricing {
		providers = append(providers, provider)
	}
	return providers
}

// GetProviderModels returns a list of all models for a specific provider.
func (p *PricingConfig) GetProviderModels(provider string) []string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	provider = NormalizeProviderName(provider)
	providerPricing, exists := p.Pricing[provider]
	if !exists {
		return []string{}
	}

	models := make([]string, 0, len(providerPricing))
	for model := range providerPricing {
		models = append(models, model)
	}
	return models
}

// HasPricing checks if pricing data exists for a specific provider and model.
func (p *PricingConfig) HasPricing(provider, model string) bool {
	return p.GetModelPricing(provider, model) != nil
}

// MergePricing merges another PricingConfig into this one.
// Existing entries are overwritten by the new config.
func (p *PricingConfig) MergePricing(other *PricingConfig) {
	if other == nil || other.Pricing == nil {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.Pricing == nil {
		p.Pricing = make(map[string]map[string]ModelPricing)
	}

	for provider, models := range other.Pricing {
		if p.Pricing[provider] == nil {
			p.Pricing[provider] = make(map[string]ModelPricing)
		}
		for model, pricing := range models {
			p.Pricing[provider][model] = pricing
		}
	}
}
