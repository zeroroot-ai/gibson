package llm

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestDefaultPricing_NewProvidersHaveEntries asserts each new provider's
// table has at least one meaningful entry (non-zero rates, SelfHosted=true,
// or Unknown=true). This catches the "forgot to extend DefaultPricing for a
// new provider" regression.
func TestDefaultPricing_NewProvidersHaveEntries(t *testing.T) {
	config := DefaultPricing()

	cases := map[string]struct{ mustHaveFlag string }{
		"bedrock":     {mustHaveFlag: "rates"},
		"cloudflare":  {mustHaveFlag: "rates"},
		"cohere":      {mustHaveFlag: "rates"},
		"mistral":     {mustHaveFlag: "rates"},
		"huggingface": {mustHaveFlag: "rates"},
		"maritaca":    {mustHaveFlag: "rates"},
		"ernie":       {mustHaveFlag: "unknown"},
		"watsonx":     {mustHaveFlag: "unknown"},
		"ollama":      {mustHaveFlag: "selfhosted"},
		"llamafile":   {mustHaveFlag: "selfhosted"},
		"local":       {mustHaveFlag: "selfhosted"},
	}

	for provider, tc := range cases {
		t.Run(provider, func(t *testing.T) {
			entries := config.Pricing[provider]
			if !assert.NotEmpty(t, entries, "no pricing entries for %q", provider) {
				return
			}
			anyRates, anyUnknown, anySelfHosted := false, false, false
			for _, p := range entries {
				if p.InputPer1M > 0 || p.OutputPer1M > 0 {
					anyRates = true
				}
				if p.Unknown {
					anyUnknown = true
				}
				if p.SelfHosted {
					anySelfHosted = true
				}
			}
			switch tc.mustHaveFlag {
			case "rates":
				assert.True(t, anyRates, "%q should have priced rates", provider)
			case "unknown":
				assert.True(t, anyUnknown, "%q should flag Unknown pricing", provider)
			case "selfhosted":
				assert.True(t, anySelfHosted, "%q should flag SelfHosted", provider)
			}
		})
	}
}

// TestModelPricing_CalculateCost_ZeroForSelfHosted verifies SelfHosted
// entries compute zero cost regardless of token count.
func TestModelPricing_CalculateCost_ZeroForSelfHosted(t *testing.T) {
	p := ModelPricing{SelfHosted: true, InputPer1M: 0, OutputPer1M: 0}
	cost := p.CalculateCost(TokenUsage{InputTokens: 1_000_000, OutputTokens: 1_000_000})
	assert.Equal(t, 0.0, cost)
}
