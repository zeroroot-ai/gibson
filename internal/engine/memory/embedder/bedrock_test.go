// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package embedder

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubBedrock captures the InvokeModel request and returns a canned Titan body.
type stubBedrock struct {
	gotModelID string
	gotBody    titanRequest
	respDim    int
	respErr    error
}

func (s *stubBedrock) InvokeModel(_ context.Context, in *bedrockruntime.InvokeModelInput, _ ...func(*bedrockruntime.Options)) (*bedrockruntime.InvokeModelOutput, error) {
	if s.respErr != nil {
		return nil, s.respErr
	}
	s.gotModelID = aws.ToString(in.ModelId)
	_ = json.Unmarshal(in.Body, &s.gotBody)
	body, _ := json.Marshal(titanResponse{Embedding: vec(s.respDim, 0.42)})
	return &bedrockruntime.InvokeModelOutput{Body: body}, nil
}

// newBedrockEmbedderWithClient mirrors newBedrockEmbedder's dimension wiring but
// injects a stub invoker, so the test never constructs a real AWS client.
func newBedrockEmbedderWithClient(t *testing.T, model string, inv bedrockInvoker) *bedrockEmbedder {
	t.Helper()
	dim, err := resolveAndRegisterDimension("bedrock", model)
	require.NoError(t, err)
	return &bedrockEmbedder{client: inv, region: "us-east-1", modelID: model, dims: dim}
}

func TestBedrockEmbedder_RequestResponseShaping(t *testing.T) {
	stub := &stubBedrock{respDim: 1024}
	emb := newBedrockEmbedderWithClient(t, "amazon.titan-embed-text-v2:0", stub)

	assert.Equal(t, 1024, emb.Dimensions())
	assert.Equal(t, "amazon.titan-embed-text-v2:0", emb.Model())

	v, err := emb.Embed(context.Background(), "hello world")
	require.NoError(t, err)
	assert.Len(t, v, 1024)
	assert.Equal(t, "amazon.titan-embed-text-v2:0", stub.gotModelID)
	assert.Equal(t, "hello world", stub.gotBody.InputText)
	assert.Equal(t, 1024, stub.gotBody.Dimensions, "dimensions must be pinned to index size")
}

func TestBedrockEmbedder_Batch(t *testing.T) {
	stub := &stubBedrock{respDim: 1536}
	emb := newBedrockEmbedderWithClient(t, "amazon.titan-embed-text-v1", stub)

	out, err := emb.EmbedBatch(context.Background(), []string{"a", "b", "c"})
	require.NoError(t, err)
	assert.Len(t, out, 3)
	for _, v := range out {
		assert.Len(t, v, 1536)
	}
}

func TestBedrockEmbedder_DimensionMismatchFailsClosed(t *testing.T) {
	stub := &stubBedrock{respDim: 256} // index expects 1024
	emb := newBedrockEmbedderWithClient(t, "amazon.titan-embed-text-v2:0", stub)
	_, err := emb.Embed(context.Background(), "x")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dimension mismatch")
}

func TestBedrockEmbedder_UnknownModelFailsClosed(t *testing.T) {
	_, err := newBedrockEmbedder(Config{Kind: KindBedrock, Model: "amazon.titan-not-real", Extra: map[string]string{"use_irsa": "true"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown embedding model")
}

// A tenant Bedrock embedder config needs its own key pair. The daemon's AWS
// environment, a missing pair and use_irsa never supply a credential.
func TestBedrockEmbedder_NeverUsesTheAmbientCredentialChain(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIADAEMON")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "daemon-secret")
	for name, extra := range map[string]map[string]string{
		"use_irsa":    {"use_irsa": "true"},
		"no key pair": {},
		"only the id": {"aws_access_key_id": "AKIAEXAMPLE"},
	} {
		t.Run(name, func(t *testing.T) {
			e, err := newBedrockEmbedder(Config{Kind: KindBedrock, Model: "amazon.titan-embed-text-v2:0", Extra: extra})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "are both required", "the refusal must be about the key pair")
			assert.Nil(t, e)
		})
	}
}

// A config with its own key pair builds an embedder, with no AWS environment.
func TestBedrockEmbedder_BuildsFromTheKeyPairOfTheConfig(t *testing.T) {
	e, err := newBedrockEmbedder(Config{Kind: KindBedrock, Model: "amazon.titan-embed-text-v2:0",
		Extra: map[string]string{"aws_access_key_id": "AKIAEXAMPLE", "aws_secret_access_key": "secret", "aws_session_token": "tok"}})
	require.NoError(t, err)
	assert.NotNil(t, e)
}
