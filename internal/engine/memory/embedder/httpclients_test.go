package embedder

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// vec returns a slice of n identical float values for stub responses.
func vec(n int, v float64) []float64 {
	out := make([]float64, n)
	for i := range out {
		out[i] = v
	}
	return out
}

// --- OpenAI / OpenAI-compatible ------------------------------------------------

func TestOpenAIEmbedder_RequestResponseShaping(t *testing.T) {
	var gotPath, gotAuth, gotModel string
	var gotInput []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		var req openAIEmbeddingRequest
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &req)
		gotModel = req.Model
		gotInput = req.Input

		resp := openAIEmbeddingResponse{}
		// Return out-of-order indices to prove we re-order by Index.
		resp.Data = append(resp.Data, struct {
			Embedding []float64 `json:"embedding"`
			Index     int       `json:"index"`
		}{Embedding: vec(1536, 0.2), Index: 1})
		resp.Data = append(resp.Data, struct {
			Embedding []float64 `json:"embedding"`
			Index     int       `json:"index"`
		}{Embedding: vec(1536, 0.1), Index: 0})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	emb, err := NewFromProvider(Config{
		Kind:    KindOpenAI,
		Model:   "text-embedding-3-small",
		APIKey:  "sk-secret",
		BaseURL: srv.URL,
	})
	require.NoError(t, err)

	out, err := emb.EmbedBatch(context.Background(), []string{"a", "b"})
	require.NoError(t, err)
	require.Len(t, out, 2)
	assert.Equal(t, 0.1, out[0][0], "result 0 must come from Index 0")
	assert.Equal(t, 0.2, out[1][0], "result 1 must come from Index 1")

	assert.Equal(t, "/v1/embeddings", gotPath)
	assert.Equal(t, "Bearer sk-secret", gotAuth)
	assert.Equal(t, "text-embedding-3-small", gotModel)
	assert.Equal(t, []string{"a", "b"}, gotInput)
}

func TestOpenAIEmbedder_SingleEmbed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := openAIEmbeddingResponse{}
		resp.Data = append(resp.Data, struct {
			Embedding []float64 `json:"embedding"`
			Index     int       `json:"index"`
		}{Embedding: vec(1536, 0.5), Index: 0})
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	emb, err := NewFromProvider(Config{Kind: KindOpenAI, Model: "text-embedding-3-small", APIKey: "k", BaseURL: srv.URL})
	require.NoError(t, err)
	v, err := emb.Embed(context.Background(), "hello")
	require.NoError(t, err)
	assert.Len(t, v, 1536)
}

func TestOpenAICompatible_NoAuthHeaderWhenNoKey(t *testing.T) {
	var sawAuth bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization") != ""
		resp := openAIEmbeddingResponse{}
		resp.Data = append(resp.Data, struct {
			Embedding []float64 `json:"embedding"`
			Index     int       `json:"index"`
		}{Embedding: vec(384, 0.3), Index: 0})
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	// Air-gapped self-hosted endpoint with no API key.
	emb, err := NewFromProvider(Config{
		Kind:                 KindOpenAICompatible,
		Model:                "all-MiniLM-L6-v2",
		BaseURL:              srv.URL,
		AllowPrivateEndpoint: true,
	})
	require.NoError(t, err)
	_, err = emb.Embed(context.Background(), "x")
	require.NoError(t, err)
	assert.False(t, sawAuth, "no Authorization header should be sent when no api_key")
}

func TestOpenAIEmbedder_UpstreamErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"message":"bad key"}}`))
	}))
	defer srv.Close()

	emb, err := NewFromProvider(Config{Kind: KindOpenAI, Model: "text-embedding-3-small", APIKey: "k", BaseURL: srv.URL})
	require.NoError(t, err)
	_, err = emb.Embed(context.Background(), "x")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "status 401")
}

func TestOpenAIEmbedder_DimensionMismatchFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := openAIEmbeddingResponse{}
		resp.Data = append(resp.Data, struct {
			Embedding []float64 `json:"embedding"`
			Index     int       `json:"index"`
		}{Embedding: vec(999, 0.1), Index: 0}) // wrong length
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	emb, err := NewFromProvider(Config{Kind: KindOpenAI, Model: "text-embedding-3-small", APIKey: "k", BaseURL: srv.URL})
	require.NoError(t, err)
	_, err = emb.Embed(context.Background(), "x")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dimension mismatch")
}

// --- TEI native ----------------------------------------------------------------

func TestTEIEmbedder_RequestResponseShaping(t *testing.T) {
	var gotPath string
	var gotReq teiRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotReq)
		// TEI returns a bare [[float,...],...] array.
		_ = json.NewEncoder(w).Encode([][]float64{vec(384, 0.7), vec(384, 0.8)})
	}))
	defer srv.Close()

	emb, err := NewFromProvider(Config{
		Kind:                 KindTEI,
		Model:                "all-MiniLM-L6-v2",
		BaseURL:              srv.URL,
		AllowPrivateEndpoint: true,
	})
	require.NoError(t, err)

	out, err := emb.EmbedBatch(context.Background(), []string{"a", "b"})
	require.NoError(t, err)
	require.Len(t, out, 2)
	assert.Equal(t, 0.7, out[0][0])
	assert.Equal(t, "/embed", gotPath)
	assert.Equal(t, []string{"a", "b"}, gotReq.Inputs)
}

// --- Cohere --------------------------------------------------------------------

func TestCohereEmbedder_RequestResponseShaping(t *testing.T) {
	var gotReq cohereEmbedRequest
	var gotPath, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotReq)
		_ = json.NewEncoder(w).Encode(cohereEmbedResponse{Embeddings: [][]float64{vec(1024, 0.4)}})
	}))
	defer srv.Close()

	emb, err := NewFromProvider(Config{Kind: KindCohere, Model: "embed-english-v3.0", APIKey: "co-key", BaseURL: srv.URL, AllowPrivateEndpoint: true})
	require.NoError(t, err)

	v, err := emb.Embed(context.Background(), "doc")
	require.NoError(t, err)
	assert.Len(t, v, 1024)
	assert.Equal(t, "/v1/embed", gotPath)
	assert.Equal(t, "Bearer co-key", gotAuth)
	assert.Equal(t, "search_document", gotReq.InputType)
	assert.Equal(t, "embed-english-v3.0", gotReq.Model)
	assert.Equal(t, []string{"doc"}, gotReq.Texts)
}

func TestCohereEmbedder_ErrorMessageBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(cohereEmbedResponse{Message: "invalid api token"})
	}))
	defer srv.Close()
	emb, err := NewFromProvider(Config{Kind: KindCohere, Model: "embed-english-v3.0", APIKey: "co-key", BaseURL: srv.URL, AllowPrivateEndpoint: true})
	require.NoError(t, err)
	_, err = emb.Embed(context.Background(), "doc")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid api token")
}

// --- Voyage --------------------------------------------------------------------

func TestVoyageEmbedder_RequestResponseShaping(t *testing.T) {
	var gotReq voyageRequest
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotReq)
		resp := voyageResponse{}
		resp.Data = append(resp.Data, struct {
			Embedding []float64 `json:"embedding"`
			Index     int       `json:"index"`
		}{Embedding: vec(1024, 0.9), Index: 0})
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	emb, err := NewFromProvider(Config{Kind: KindVoyage, Model: "voyage-3", APIKey: "vo-key", BaseURL: srv.URL, AllowPrivateEndpoint: true})
	require.NoError(t, err)

	v, err := emb.Embed(context.Background(), "doc")
	require.NoError(t, err)
	assert.Len(t, v, 1024)
	assert.Equal(t, "/v1/embeddings", gotPath)
	assert.Equal(t, "document", gotReq.InputType)
	assert.Equal(t, "voyage-3", gotReq.Model)
}
