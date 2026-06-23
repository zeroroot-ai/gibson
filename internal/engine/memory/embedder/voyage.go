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

// defaultVoyageBaseURL is the Voyage AI API root.
const defaultVoyageBaseURL = "https://api.voyageai.com"

// voyageEmbedder speaks Voyage AI's POST /v1/embeddings endpoint. The wire shape
// is OpenAI-like (data[].embedding) but takes an input_type; we send "document"
// because the memory store embeds content to be indexed.
type voyageEmbedder struct {
	client  *http.Client
	baseURL string
	apiKey  string
	model   string
	dims    int
}

// newVoyageEmbedder builds the Voyage backend. An API key and a known model are
// required.
func newVoyageEmbedder(cfg Config) (Embedder, error) {
	model, err := cfg.requireModel("voyage")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.APIKey) == "" {
		return nil, types.NewError(ErrCodeInvalidConfig, "voyage embedder requires an api_key")
	}
	baseURL := firstNonEmptyStr(cfg.BaseURL, defaultVoyageBaseURL)
	if cfg.BaseURL != "" {
		if err := validateEndpoint(cfg.BaseURL, cfg.AllowPrivateEndpoint); err != nil {
			return nil, err
		}
	}
	dim, err := resolveAndRegisterDimension("voyage", model)
	if err != nil {
		return nil, err
	}
	return &voyageEmbedder{
		client:  cfg.httpClient(),
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  cfg.APIKey,
		model:   model,
		dims:    dim,
	}, nil
}

func (e *voyageEmbedder) Model() string   { return e.model }
func (e *voyageEmbedder) Dimensions() int { return e.dims }

type voyageRequest struct {
	Model     string   `json:"model"`
	Input     []string `json:"input"`
	InputType string   `json:"input_type"`
}

type voyageResponse struct {
	Data []struct {
		Embedding []float64 `json:"embedding"`
		Index     int       `json:"index"`
	} `json:"data"`
	Detail string `json:"detail"` // populated on error responses
}

func (e *voyageEmbedder) Embed(ctx context.Context, text string) ([]float64, error) {
	out, err := e.EmbedBatch(ctx, []string{text})
	if err != nil {
		return nil, err
	}
	if len(out) != 1 {
		return nil, types.NewError(ErrCodeEmbeddingFailed,
			fmt.Sprintf("voyage: expected 1 embedding, got %d", len(out)))
	}
	return out[0], nil
}

func (e *voyageEmbedder) EmbedBatch(ctx context.Context, texts []string) ([][]float64, error) {
	if len(texts) == 0 {
		return [][]float64{}, nil
	}
	body, err := json.Marshal(voyageRequest{
		Model:     e.model,
		Input:     texts,
		InputType: "document",
	})
	if err != nil {
		return nil, types.WrapError(ErrCodeEmbeddingBatchFailed, "voyage: marshal request", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.baseURL+"/v1/embeddings", bytes.NewReader(body))
	if err != nil {
		return nil, types.WrapError(ErrCodeEmbeddingBatchFailed, "voyage: build request", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+e.apiKey)

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, types.WrapError(ErrCodeEmbeddingBatchFailed, "voyage: request failed", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))

	if resp.StatusCode != http.StatusOK {
		return nil, types.NewError(ErrCodeEmbeddingBatchFailed,
			fmt.Sprintf("voyage: upstream status %d: %s", resp.StatusCode, snippet(raw)))
	}

	var parsed voyageResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, types.WrapError(ErrCodeEmbeddingBatchFailed, "voyage: decode response", err)
	}
	if parsed.Detail != "" {
		return nil, types.NewError(ErrCodeEmbeddingBatchFailed, "voyage: "+parsed.Detail)
	}
	if len(parsed.Data) != len(texts) {
		return nil, types.NewError(ErrCodeEmbeddingBatchFailed,
			fmt.Sprintf("voyage: expected %d embeddings, got %d", len(texts), len(parsed.Data)))
	}
	out := make([][]float64, len(texts))
	for _, d := range parsed.Data {
		if d.Index < 0 || d.Index >= len(out) {
			return nil, types.NewError(ErrCodeEmbeddingBatchFailed,
				fmt.Sprintf("voyage: response index %d out of range", d.Index))
		}
		if err := assertDimension("voyage", e.dims, len(d.Embedding)); err != nil {
			return nil, err
		}
		out[d.Index] = d.Embedding
	}
	return out, nil
}

func (e *voyageEmbedder) Health(ctx context.Context) types.HealthStatus {
	if _, err := e.Embed(ctx, "healthcheck"); err != nil {
		return types.NewHealthStatus(types.HealthStateUnhealthy, err.Error())
	}
	return types.NewHealthStatus(types.HealthStateHealthy, "")
}
