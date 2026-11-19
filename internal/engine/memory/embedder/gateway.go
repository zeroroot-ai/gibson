// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package embedder

import (
	"context"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/engine/modelclient"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/modelcall"
)

// Gateway sends an OpenAI Embeddings call to the model gateway. The model client
// of the daemon implements it (gibson#1393, ADR-0172).
type Gateway interface {
	Embeddings(ctx context.Context, caller modelclient.Caller, target modelclient.Target,
		model string, inputs []string) (*modelclient.EmbeddingsResult, error)
}

// gatewayEmbedder is the one embedder of the daemon. It calls no provider: the
// gateway holds the credential and the endpoint of the provider of the tenant.
// It sends the OpenAI Embeddings format on the route /v1/embeddings.
type gatewayEmbedder struct {
	gateway  Gateway
	tenant   string
	provider string
	model    string
	dims     int
}

func newGatewayEmbedder(cfg Config) (Embedder, error) {
	model, err := cfg.requireModel(string(cfg.Kind))
	if err != nil {
		return nil, err
	}
	if cfg.Gateway == nil {
		return nil, types.NewError(ErrCodeInvalidConfig, "the embedder needs the model gateway client")
	}
	if strings.TrimSpace(cfg.Tenant) == "" || strings.TrimSpace(cfg.Provider) == "" {
		return nil, types.NewError(ErrCodeInvalidConfig, "the embedder needs the tenant and the provider name")
	}
	dim, err := resolveAndRegisterDimension(string(cfg.Kind), model)
	if err != nil {
		return nil, err
	}
	return &gatewayEmbedder{gateway: cfg.Gateway, tenant: cfg.Tenant, provider: cfg.Provider, model: model, dims: dim}, nil
}

func (e *gatewayEmbedder) Dimensions() int { return e.dims }
func (e *gatewayEmbedder) Model() string   { return e.model }

func (e *gatewayEmbedder) Embed(ctx context.Context, text string) ([]float64, error) {
	out, err := e.EmbedBatch(ctx, []string{text})
	if err != nil {
		return nil, err
	}
	return out[0], nil
}

// EmbedBatch sends the texts in one call. The grant of the call is a daemon call
// grant with the purpose embedding. The gateway trace records the tokens.
func (e *gatewayEmbedder) EmbedBatch(ctx context.Context, texts []string) ([][]float64, error) {
	if len(texts) == 0 {
		return nil, nil
	}
	res, err := e.gateway.Embeddings(ctx,
		modelclient.Caller{Tenant: e.tenant, Purpose: modelcall.PurposeEmbedding},
		modelclient.Target{Tenant: e.tenant, Provider: e.provider, Model: e.model},
		e.model, texts)
	if err != nil {
		return nil, types.WrapError(ErrCodeEmbeddingBatchFailed, "the model gateway embeddings call failed", err)
	}
	for _, v := range res.Vectors {
		if err := assertDimension(e.provider, e.dims, len(v)); err != nil {
			return nil, err
		}
	}
	return res.Vectors, nil
}

func (e *gatewayEmbedder) Health(ctx context.Context) types.HealthStatus {
	if _, err := e.Embed(ctx, "healthcheck"); err != nil {
		return types.NewHealthStatus(types.HealthStateUnhealthy, err.Error())
	}
	return types.NewHealthStatus(types.HealthStateHealthy, "")
}
