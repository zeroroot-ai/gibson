package embedder

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// teiEmbedder speaks HuggingFace Text-Embeddings-Inference's native POST /embed
// endpoint, which takes {"inputs": <string|[]string>} and returns a bare
// [[float, …], …] array (no envelope). This is the air-gap path for operators
// running a TEI server that does not expose the OpenAI-compatible shim; use
// KindOpenAICompatible against /v1/embeddings if it does.
type teiEmbedder struct {
	client  *http.Client
	baseURL string
	apiKey  string // optional bearer for gated TEI deployments
	model   string
	dims    int
}

// newTEIEmbedder builds the native-TEI backend. BaseURL is required and
// SSRF-checked; the model dimension must be known (register a self-hosted model
// via RegisterModelDimension at startup).
func newTEIEmbedder(cfg Config) (Embedder, error) {
	model, err := cfg.requireModel("tei")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.BaseURL) == "" {
		return nil, types.NewError(ErrCodeInvalidConfig, "tei embedder requires a base_url")
	}
	if err := validateEndpoint(cfg.BaseURL, cfg.AllowPrivateEndpoint); err != nil {
		return nil, err
	}
	dim, err := resolveAndRegisterDimension("tei", model)
	if err != nil {
		return nil, err
	}
	return &teiEmbedder{
		client:  cfg.httpClient(),
		baseURL: strings.TrimRight(cfg.BaseURL, "/"),
		apiKey:  cfg.APIKey,
		model:   model,
		dims:    dim,
	}, nil
}

func (e *teiEmbedder) Model() string   { return e.model }
func (e *teiEmbedder) Dimensions() int { return e.dims }

type teiRequest struct {
	Inputs []string `json:"inputs"`
}

func (e *teiEmbedder) Embed(ctx context.Context, text string) ([]float64, error) {
	out, err := e.EmbedBatch(ctx, []string{text})
	if err != nil {
		return nil, err
	}
	if len(out) != 1 {
		return nil, types.NewError(ErrCodeEmbeddingFailed,
			fmt.Sprintf("tei: expected 1 embedding, got %d", len(out)))
	}
	return out[0], nil
}

func (e *teiEmbedder) EmbedBatch(ctx context.Context, texts []string) ([][]float64, error) {
	if len(texts) == 0 {
		return [][]float64{}, nil
	}
	body, err := json.Marshal(teiRequest{Inputs: texts})
	if err != nil {
		return nil, types.WrapError(ErrCodeEmbeddingBatchFailed, "tei: marshal request", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.baseURL+"/embed", bytes.NewReader(body))
	if err != nil {
		return nil, types.WrapError(ErrCodeEmbeddingBatchFailed, "tei: build request", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if e.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+e.apiKey)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, types.WrapError(ErrCodeEmbeddingBatchFailed, "tei: request failed", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))

	if resp.StatusCode != http.StatusOK {
		return nil, types.NewError(ErrCodeEmbeddingBatchFailed,
			fmt.Sprintf("tei: upstream status %d: %s", resp.StatusCode, snippet(raw)))
	}

	var vectors [][]float64
	if err := json.Unmarshal(raw, &vectors); err != nil {
		return nil, types.WrapError(ErrCodeEmbeddingBatchFailed, "tei: decode response", err)
	}
	if len(vectors) != len(texts) {
		return nil, types.NewError(ErrCodeEmbeddingBatchFailed,
			fmt.Sprintf("tei: expected %d embeddings, got %d", len(texts), len(vectors)))
	}
	for _, v := range vectors {
		if err := assertDimension("tei", e.dims, len(v)); err != nil {
			return nil, err
		}
	}
	return vectors, nil
}

func (e *teiEmbedder) Health(ctx context.Context) types.HealthStatus {
	if _, err := e.Embed(ctx, "healthcheck"); err != nil {
		return types.NewHealthStatus(types.HealthStateUnhealthy, err.Error())
	}
	return types.NewHealthStatus(types.HealthStateHealthy, "")
}
