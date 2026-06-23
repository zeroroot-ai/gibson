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

// defaultCohereBaseURL is the Cohere API root.
const defaultCohereBaseURL = "https://api.cohere.com"

// cohereEmbedder speaks Cohere's native POST /v1/embed endpoint. Cohere requires
// an input_type (search_document for stored content, search_query at query time);
// we send search_document because the memory store embeds content to be indexed.
type cohereEmbedder struct {
	client  *http.Client
	baseURL string
	apiKey  string
	model   string
	dims    int
}

// newCohereEmbedder builds the Cohere backend. An API key and a known model are
// required.
func newCohereEmbedder(cfg Config) (Embedder, error) {
	model, err := cfg.requireModel("cohere")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.APIKey) == "" {
		return nil, types.NewError(ErrCodeInvalidConfig, "cohere embedder requires an api_key")
	}
	baseURL := firstNonEmptyStr(cfg.BaseURL, defaultCohereBaseURL)
	if cfg.BaseURL != "" {
		if err := validateEndpoint(cfg.BaseURL, cfg.AllowPrivateEndpoint); err != nil {
			return nil, err
		}
	}
	dim, err := resolveAndRegisterDimension("cohere", model)
	if err != nil {
		return nil, err
	}
	return &cohereEmbedder{
		client:  cfg.httpClient(),
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  cfg.APIKey,
		model:   model,
		dims:    dim,
	}, nil
}

func (e *cohereEmbedder) Model() string   { return e.model }
func (e *cohereEmbedder) Dimensions() int { return e.dims }

type cohereEmbedRequest struct {
	Model     string   `json:"model"`
	Texts     []string `json:"texts"`
	InputType string   `json:"input_type"`
}

type cohereEmbedResponse struct {
	Embeddings [][]float64 `json:"embeddings"`
	Message    string      `json:"message"` // populated on error responses
}

func (e *cohereEmbedder) Embed(ctx context.Context, text string) ([]float64, error) {
	out, err := e.EmbedBatch(ctx, []string{text})
	if err != nil {
		return nil, err
	}
	if len(out) != 1 {
		return nil, types.NewError(ErrCodeEmbeddingFailed,
			fmt.Sprintf("cohere: expected 1 embedding, got %d", len(out)))
	}
	return out[0], nil
}

func (e *cohereEmbedder) EmbedBatch(ctx context.Context, texts []string) ([][]float64, error) {
	if len(texts) == 0 {
		return [][]float64{}, nil
	}
	body, err := json.Marshal(cohereEmbedRequest{
		Model:     e.model,
		Texts:     texts,
		InputType: "search_document",
	})
	if err != nil {
		return nil, types.WrapError(ErrCodeEmbeddingBatchFailed, "cohere: marshal request", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.baseURL+"/v1/embed", bytes.NewReader(body))
	if err != nil {
		return nil, types.WrapError(ErrCodeEmbeddingBatchFailed, "cohere: build request", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+e.apiKey)

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, types.WrapError(ErrCodeEmbeddingBatchFailed, "cohere: request failed", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))

	if resp.StatusCode != http.StatusOK {
		return nil, types.NewError(ErrCodeEmbeddingBatchFailed,
			fmt.Sprintf("cohere: upstream status %d: %s", resp.StatusCode, snippet(raw)))
	}

	var parsed cohereEmbedResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, types.WrapError(ErrCodeEmbeddingBatchFailed, "cohere: decode response", err)
	}
	if parsed.Message != "" {
		return nil, types.NewError(ErrCodeEmbeddingBatchFailed, "cohere: "+parsed.Message)
	}
	if len(parsed.Embeddings) != len(texts) {
		return nil, types.NewError(ErrCodeEmbeddingBatchFailed,
			fmt.Sprintf("cohere: expected %d embeddings, got %d", len(texts), len(parsed.Embeddings)))
	}
	for _, v := range parsed.Embeddings {
		if err := assertDimension("cohere", e.dims, len(v)); err != nil {
			return nil, err
		}
	}
	return parsed.Embeddings, nil
}

func (e *cohereEmbedder) Health(ctx context.Context) types.HealthStatus {
	if _, err := e.Embed(ctx, "healthcheck"); err != nil {
		return types.NewHealthStatus(types.HealthStateUnhealthy, err.Error())
	}
	return types.NewHealthStatus(types.HealthStateHealthy, "")
}
