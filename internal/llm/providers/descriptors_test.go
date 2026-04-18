package providers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/llm"
)

func TestSupportedProviderDescriptors_Coverage(t *testing.T) {
	descs := SupportedProviderDescriptors()
	got := make(map[llm.ProviderType]bool, len(descs))
	for _, d := range descs {
		got[d.Type] = true
	}
	for _, typ := range llm.SupportedProviderTypes() {
		if typ == llm.ProviderCustom {
			// Custom is intentionally excluded.
			assert.False(t, got[typ], "ProviderCustom should NOT have a descriptor")
			continue
		}
		assert.True(t, got[typ],
			"provider %q is in SupportedProviderTypes() but has no descriptor — add it to providerDescriptor()", typ)
	}
}

func TestSupportedProviderDescriptors_SelfHostedFlag(t *testing.T) {
	descs := SupportedProviderDescriptors()
	byType := make(map[llm.ProviderType]ProviderDescriptor, len(descs))
	for _, d := range descs {
		byType[d.Type] = d
	}
	selfHosted := []llm.ProviderType{llm.ProviderOllama, llm.ProviderLlamafile, llm.ProviderLocal}
	for _, t_ := range selfHosted {
		assert.True(t, byType[t_].SelfHosted, "%s should have SelfHosted=true", t_)
	}
	hosted := []llm.ProviderType{
		llm.ProviderAnthropic, llm.ProviderBedrock, llm.ProviderCloudflare,
		llm.ProviderCohere, llm.ProviderErnie, llm.ProviderHuggingFace,
		llm.ProviderMaritaca, llm.ProviderMistral, llm.ProviderWatsonX,
	}
	for _, t_ := range hosted {
		assert.False(t, byType[t_].SelfHosted, "%s should have SelfHosted=false", t_)
	}
}

func TestBedrockDescriptor_IncludesAWSFields(t *testing.T) {
	d, ok := providerDescriptor(llm.ProviderBedrock)
	require.True(t, ok)
	keys := make(map[string]bool)
	for _, f := range d.Credentials {
		keys[f.Key] = true
	}
	assert.True(t, keys["aws_access_key_id"])
	assert.True(t, keys["aws_secret_access_key"])
	assert.True(t, keys["aws_region"])
	assert.NotEmpty(t, d.DefaultModels)
}
