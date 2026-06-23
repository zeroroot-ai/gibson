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
