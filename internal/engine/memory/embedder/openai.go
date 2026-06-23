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

// defaultOpenAIBaseURL is the OpenAI embeddings API root used when no BaseURL
// override is configured.
const defaultOpenAIBaseURL = "https://api.openai.com"

// openAIEmbedder speaks the OpenAI POST /v1/embeddings wire format. It backs
// three Kinds — native OpenAI, a generic OpenAI-compatible endpoint, and a TEI
// server run in OpenAI-compatibility mode — which differ only in BaseURL, auth
// requirement, and SSRF policy. The request/response shaping is identical.
type openAIEmbedder struct {
	provider string // label used in errors / RegisterModelDimension diagnostics
	client   *http.Client
	baseURL  string
	apiKey   string // optional for self-hosted endpoints
	model    string
	dims     int
}

// newOpenAIEmbedder builds the native OpenAI backend. An API key is required and
// the model must be known (dimension is read from the model table; OpenAI does
// not return the dimension in a way we size the index from).
func newOpenAIEmbedder(cfg Config) (Embedder, error) {
	model, err := cfg.requireModel("openai")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.APIKey) == "" {
		return nil, types.NewError(ErrCodeInvalidConfig, "openai embedder requires an api_key")
	}
	baseURL := firstNonEmptyStr(cfg.BaseURL, defaultOpenAIBaseURL)
	dim, err := resolveAndRegisterDimension("openai", model)
	if err != nil {
		return nil, err
	}
	return &openAIEmbedder{
		provider: "openai",
		client:   cfg.httpClient(),
		baseURL:  strings.TrimRight(baseURL, "/"),
		apiKey:   cfg.APIKey,
		model:    model,
		dims:     dim,
	}, nil
}

// newOpenAICompatibleEmbedder builds the generic OpenAI-compatible backend (the
// air-gap path). BaseURL is required and SSRF-checked; the API key is optional
// (self-hosted endpoints often need none). The model dimension must be known —
// register it for an out-of-table self-hosted model via RegisterModelDimension
// at daemon startup before constructing the embedder.
func newOpenAICompatibleEmbedder(cfg Config) (Embedder, error) {
	model, err := cfg.requireModel("openai-compatible")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.BaseURL) == "" {
		return nil, types.NewError(ErrCodeInvalidConfig,
			"openai-compatible embedder requires a base_url")
	}
	if err := validateEndpoint(cfg.BaseURL, cfg.AllowPrivateEndpoint); err != nil {
		return nil, err
	}
	dim, err := resolveAndRegisterDimension("openai-compatible", model)
	if err != nil {
		return nil, err
	}
	return &openAIEmbedder{
		provider: "openai-compatible",
		client:   cfg.httpClient(),
		baseURL:  strings.TrimRight(cfg.BaseURL, "/"),
		apiKey:   cfg.APIKey,
		model:    model,
		dims:     dim,
	}, nil
}

func (e *openAIEmbedder) Model() string   { return e.model }
func (e *openAIEmbedder) Dimensions() int { return e.dims }

// openAIEmbeddingRequest is the POST /v1/embeddings body. Input accepts a string
// or array of strings; we always send an array for uniform batch handling.
type openAIEmbeddingRequest struct {
	Model string   `json:"model"`
	Input []string `json:"input"`
}

type openAIEmbeddingResponse struct {
	Data []struct {
		Embedding []float64 `json:"embedding"`
		Index     int       `json:"index"`
	} `json:"data"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error"`
}

func (e *openAIEmbedder) Embed(ctx context.Context, text string) ([]float64, error) {
	out, err := e.EmbedBatch(ctx, []string{text})
	if err != nil {
		return nil, err
	}
	if len(out) != 1 {
		return nil, types.NewError(ErrCodeEmbeddingFailed,
			fmt.Sprintf("%s: expected 1 embedding, got %d", e.provider, len(out)))
	}
	return out[0], nil
}

func (e *openAIEmbedder) EmbedBatch(ctx context.Context, texts []string) ([][]float64, error) {
	if len(texts) == 0 {
		return [][]float64{}, nil
	}
	body, err := json.Marshal(openAIEmbeddingRequest{Model: e.model, Input: texts})
	if err != nil {
		return nil, types.WrapError(ErrCodeEmbeddingBatchFailed, e.provider+": marshal request", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.baseURL+"/v1/embeddings", bytes.NewReader(body))
	if err != nil {
		return nil, types.WrapError(ErrCodeEmbeddingBatchFailed, e.provider+": build request", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if e.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+e.apiKey)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, types.WrapError(ErrCodeEmbeddingBatchFailed, e.provider+": request failed", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))

	if resp.StatusCode != http.StatusOK {
		return nil, types.NewError(ErrCodeEmbeddingBatchFailed,
			fmt.Sprintf("%s: upstream status %d: %s", e.provider, resp.StatusCode, snippet(raw)))
	}

	var parsed openAIEmbeddingResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, types.WrapError(ErrCodeEmbeddingBatchFailed, e.provider+": decode response", err)
	}
	if parsed.Error != nil {
		return nil, types.NewError(ErrCodeEmbeddingBatchFailed,
			fmt.Sprintf("%s: %s", e.provider, parsed.Error.Message))
	}
	if len(parsed.Data) != len(texts) {
		return nil, types.NewError(ErrCodeEmbeddingBatchFailed,
			fmt.Sprintf("%s: expected %d embeddings, got %d", e.provider, len(texts), len(parsed.Data)))
	}

	// Order by Index defensively — OpenAI returns them in request order, but the
	// field is authoritative.
	out := make([][]float64, len(texts))
	for _, d := range parsed.Data {
		if d.Index < 0 || d.Index >= len(out) {
			return nil, types.NewError(ErrCodeEmbeddingBatchFailed,
				fmt.Sprintf("%s: response index %d out of range", e.provider, d.Index))
		}
		if err := assertDimension(e.provider, e.dims, len(d.Embedding)); err != nil {
			return nil, err
		}
		out[d.Index] = d.Embedding
	}
	return out, nil
}

func (e *openAIEmbedder) Health(ctx context.Context) types.HealthStatus {
	if _, err := e.Embed(ctx, "healthcheck"); err != nil {
		return types.NewHealthStatus(types.HealthStateUnhealthy, err.Error())
	}
	return types.NewHealthStatus(types.HealthStateHealthy, "")
}
