// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package embedder

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/modelclient"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/modelcall"
)

// TestNewFromProvider_UnsetKindGates verifies that an empty Kind no longer
// silently yields a bundled embedder (ADR-0059 §4, gibson#810). The live path
// must hit the onboarding gate so vector features prompt the user to configure
// an embedding provider instead of producing mock embeddings.
func TestNewFromProvider_UnsetKindGates(t *testing.T) {
	emb, err := NewFromProvider(Config{})
	require.Error(t, err, "empty Kind must gate, not fall back to the bundled mock")
	assert.Nil(t, emb)
	var gerr *types.GibsonError
	require.True(t, errors.As(err, &gerr))
	assert.Equal(t, ErrCodeNoEmbeddingProvider, gerr.Code)
}

// TestNewMockEmbedder_ForTests confirms the bundled mock is still constructible
// directly — it is retained strictly for tests/fixtures that need a
// deterministic offline embedder.
func TestNewMockEmbedder_ForTests(t *testing.T) {
	emb := NewMockEmbedder()
	assert.Equal(t, 384, emb.Dimensions())
	assert.Equal(t, DefaultEmbeddingModel, emb.Model())
}

// fakeGateway answers each embeddings call with vectors of a fixed size and
// records the call.
type fakeGateway struct {
	dim     int
	callers []modelclient.Caller
	targets []modelclient.Target
	models  []string
	err     error
}

func (f *fakeGateway) Embeddings(
	_ context.Context, c modelclient.Caller, t modelclient.Target, model string, inputs []string,
) (*modelclient.EmbeddingsResult, error) {
	f.callers, f.targets, f.models = append(f.callers, c), append(f.targets, t), append(f.models, model)
	if f.err != nil {
		return nil, f.err
	}
	out := &modelclient.EmbeddingsResult{Vectors: make([][]float64, len(inputs))}
	for i := range inputs {
		out.Vectors[i] = make([]float64, f.dim)
	}
	return out, nil
}

func cfgFor(kind Kind, model string, gw Gateway) Config {
	return Config{Kind: kind, Model: model, Tenant: "acme", Provider: "p", Gateway: gw}
}

// TestNewFromProvider_Selection verifies that each kind that serves embeddings
// builds the one gateway embedder with the model-derived dimension.
func TestNewFromProvider_Selection(t *testing.T) {
	cases := []struct {
		name    string
		kind    Kind
		model   string
		wantDim int
	}{
		{"openai text-embedding-3-small", KindOpenAI, "text-embedding-3-small", 1536},
		{"openai text-embedding-3-large", KindOpenAI, "text-embedding-3-large", 3072},
		{"openai-compatible", KindOpenAICompatible, "text-embedding-3-small", 1536},
		{"tei", KindTEI, "all-MiniLM-L6-v2", 384},
		{"cohere", KindCohere, "embed-english-v3.0", 1024},
		{"bedrock titan", KindBedrock, "amazon.titan-embed-text-v2:0", 1024},
		{"kind is case-insensitive", Kind("OpenAI"), "text-embedding-ada-002", 1536},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			emb, err := NewFromProvider(cfgFor(c.kind, c.model, &fakeGateway{dim: c.wantDim}))
			require.NoError(t, err)
			assert.IsType(t, &gatewayEmbedder{}, emb)
			assert.Equal(t, c.wantDim, emb.Dimensions())
			assert.Equal(t, c.model, emb.Model())
			dim, ok := DimensionForModel(c.model)
			require.True(t, ok)
			assert.Equal(t, c.wantDim, dim)
		})
	}
}

// Voyage is refused with a clear message, and no gateway call is made.
func TestNewFromProvider_VoyageIsRefused(t *testing.T) {
	gw := &fakeGateway{dim: 1024}
	_, err := NewFromProvider(cfgFor(KindVoyage, "voyage-3", gw))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "voyage is not an embedding provider type")
	assert.Empty(t, gw.callers)
}

func TestNewFromProvider_UnknownKindFailsClosed(t *testing.T) {
	_, err := NewFromProvider(cfgFor("made-up-provider", "x", &fakeGateway{}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown embedding provider kind")
}

func TestNewFromProvider_UnknownModelFailsClosed(t *testing.T) {
	// An unknown model has no registered dimension; constructing must fail closed
	// rather than guess (a wrong VECTOR dim silently breaks RediSearch indexing).
	_, err := NewFromProvider(cfgFor(KindOpenAI, "gpt-not-an-embed-model", &fakeGateway{}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown embedding model")
}

func TestNewFromProvider_MissingPartsFailClosed(t *testing.T) {
	_, err := NewFromProvider(cfgFor(KindOpenAI, "", &fakeGateway{}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires a model")

	_, err = NewFromProvider(cfgFor(KindOpenAI, "text-embedding-3-small", nil))
	require.Error(t, err, "no gateway")

	c := cfgFor(KindOpenAI, "text-embedding-3-small", &fakeGateway{})
	c.Provider = ""
	_, err = NewFromProvider(c)
	require.Error(t, err, "no provider name")
}

// A call goes to the route of the tenant and the provider, with the exact model
// and the purpose embedding. A reply with the wrong dimension fails closed.
func TestGatewayEmbedder_CallShapeAndDimensionCheck(t *testing.T) {
	gw := &fakeGateway{dim: 1536}
	emb, err := NewFromProvider(cfgFor(KindOpenAI, "text-embedding-3-small", gw))
	require.NoError(t, err)
	vecs, err := emb.EmbedBatch(context.Background(), []string{"a", "b"})
	require.NoError(t, err)
	require.Len(t, vecs, 2)
	require.Len(t, gw.callers, 1)
	assert.Equal(t, modelcall.PurposeEmbedding, gw.callers[0].Purpose)
	assert.Equal(t, modelclient.Target{Tenant: "acme", Provider: "p", Model: "text-embedding-3-small"}, gw.targets[0])
	assert.Equal(t, "text-embedding-3-small", gw.models[0])

	bad := &fakeGateway{dim: 12}
	emb2, err := NewFromProvider(cfgFor(KindOpenAI, "text-embedding-3-small", bad))
	require.NoError(t, err)
	_, err = emb2.Embed(context.Background(), "x")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dimension mismatch")

	down := &fakeGateway{err: errors.New("boom")}
	emb3, err := NewFromProvider(cfgFor(KindOpenAI, "text-embedding-3-small", down))
	require.NoError(t, err)
	assert.Equal(t, types.HealthStateUnhealthy, emb3.Health(context.Background()).State)
}

func TestRegisterModelDimension_UnlocksOutOfTableModel(t *testing.T) {
	// An operator self-hosting a model not in the built-in table registers its
	// dimension first; then the factory accepts it (air-gap path).
	RegisterModelDimension("custom-airgap-embed-768", 768)
	emb, err := NewFromProvider(cfgFor(KindOpenAICompatible, "custom-airgap-embed-768", &fakeGateway{dim: 768}))
	require.NoError(t, err)
	assert.Equal(t, 768, emb.Dimensions())
}
