package providers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/engine/memory/embedder"
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
	selfHosted := []llm.ProviderType{llm.ProviderOllama, llm.ProviderLlamafile}
	for _, t_ := range selfHosted {
		assert.True(t, byType[t_].SelfHosted, "%s should have SelfHosted=true", t_)
	}
	hosted := []llm.ProviderType{
		llm.ProviderAnthropic, llm.ProviderBedrock, llm.ProviderCloudflare,
		llm.ProviderCohere, llm.ProviderHuggingFace,
		llm.ProviderMistral,
	}
	for _, t_ := range hosted {
		assert.False(t, byType[t_].SelfHosted, "%s should have SelfHosted=false", t_)
	}
}

// TestEmbeddingModelCatalogue_DimensionsKnown is the drift guard for #1012:
// every model advertised in the embedding catalogue MUST resolve to a known,
// non-zero dimension via embedder.DimensionForModel. A model that drifts out
// of the dimension table would surface a 0-dimension to the dashboard and
// silently break RediSearch indexing of the whole document — fail loud here.
func TestEmbeddingModelCatalogue_DimensionsKnown(t *testing.T) {
	for providerType, models := range embeddingModelCatalogue {
		require.NotEmpty(t, models, "embedding catalogue entry for %q must not be empty", providerType)
		for _, m := range models {
			dim, ok := embedder.DimensionForModel(m)
			assert.Truef(t, ok, "embedding model %q (provider %q) is not in embedder.DimensionForModel — add it to the dimension table", m, providerType)
			assert.Positivef(t, dim, "embedding model %q (provider %q) resolved to a non-positive dimension %d", m, providerType, dim)
		}
	}
}

// TestSupportedProviderDescriptors_EmbeddingCapability verifies #1012: the
// provider types with an embedder backend (openai/bedrock/cohere) carry an
// embedding catalogue with resolved dimensions, and every other supported
// provider advertises none.
func TestSupportedProviderDescriptors_EmbeddingCapability(t *testing.T) {
	byType := make(map[llm.ProviderType]ProviderDescriptor)
	for _, d := range SupportedProviderDescriptors() {
		byType[d.Type] = d
	}

	embedders := map[llm.ProviderType]bool{
		llm.ProviderOpenAI:  true,
		llm.ProviderBedrock: true,
		llm.ProviderCohere:  true,
	}
	for typ, d := range byType {
		if embedders[typ] {
			require.NotEmptyf(t, d.EmbeddingModels, "%s should advertise embedding models", typ)
			for _, m := range d.EmbeddingModels {
				assert.Positivef(t, m.Dimensions, "%s embedding model %q must carry a positive dimension", typ, m.Name)
			}
		} else {
			assert.Emptyf(t, d.EmbeddingModels, "%s has no embedder backend and must not advertise embedding models", typ)
		}
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
