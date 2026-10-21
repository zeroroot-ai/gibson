// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package embedder

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// bedrockInvoker is the subset of the bedrockruntime client this embedder needs.
// Narrowing to an interface lets tests stub InvokeModel without an AWS account
// or network; production wiring passes the real *bedrockruntime.Client.
type bedrockInvoker interface {
	InvokeModel(ctx context.Context, in *bedrockruntime.InvokeModelInput, optFns ...func(*bedrockruntime.Options)) (*bedrockruntime.InvokeModelOutput, error)
}

// bedrockEmbedder speaks AWS Bedrock's InvokeModel API against Amazon Titan Text
// Embeddings models. Titan embeds a single document per call, so EmbedBatch
// iterates. Credential resolution mirrors the LLM Bedrock provider: static
// keys from Extra only. The environment and the AWS default chain of the
// daemon are never read.
type bedrockEmbedder struct {
	client  bedrockInvoker
	region  string
	modelID string
	dims    int
}

// newBedrockEmbedder builds the Bedrock/Titan backend. The model must be known
// (its dimension sizes the index); credentials are the key pair of the config.
func newBedrockEmbedder(cfg Config) (Embedder, error) {
	model, err := cfg.requireModel("bedrock")
	if err != nil {
		return nil, err
	}
	dim, err := resolveAndRegisterDimension("bedrock", model)
	if err != nil {
		return nil, err
	}

	region := firstNonEmptyStr(cfg.Region, extra(cfg, "aws_region"), os.Getenv("AWS_REGION"), "us-east-1")

	// The credential is the key pair of the config and nothing else. The AWS
	// default chain of the daemon (an IRSA role, an instance profile, the
	// environment) is never a credential of a tenant.
	ak := extra(cfg, "aws_access_key_id")
	sk := extra(cfg, "aws_secret_access_key")
	st := extra(cfg, "aws_session_token")
	if ak == "" || sk == "" {
		return nil, types.NewError(ErrCodeInvalidConfig,
			"bedrock: aws_access_key_id and aws_secret_access_key are both required; the daemon's own AWS credentials are never used")
	}
	loadOpts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(region),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(ak, sk, st)),
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(), loadOpts...)
	if err != nil {
		return nil, types.WrapError(ErrCodeInvalidConfig, "bedrock: load AWS config", err)
	}

	return &bedrockEmbedder{
		client:  bedrockruntime.NewFromConfig(awsCfg),
		region:  region,
		modelID: model,
		dims:    dim,
	}, nil
}

func (e *bedrockEmbedder) Model() string   { return e.modelID }
func (e *bedrockEmbedder) Dimensions() int { return e.dims }

// titanRequest is the Titan Text Embeddings invoke body. dimensions is honoured
// by v2 models and ignored by v1; sending it keeps the emitted vector length
// pinned to the index size for models that support it.
type titanRequest struct {
	InputText  string `json:"inputText"`
	Dimensions int    `json:"dimensions,omitempty"`
}

type titanResponse struct {
	Embedding []float64 `json:"embedding"`
	Message   string    `json:"message"` // populated on error bodies
}

func (e *bedrockEmbedder) Embed(ctx context.Context, text string) ([]float64, error) {
	reqBody, err := json.Marshal(titanRequest{InputText: text, Dimensions: e.dims})
	if err != nil {
		return nil, types.WrapError(ErrCodeEmbeddingFailed, "bedrock: marshal request", err)
	}

	out, err := e.client.InvokeModel(ctx, &bedrockruntime.InvokeModelInput{
		ModelId:     aws.String(e.modelID),
		ContentType: aws.String("application/json"),
		Accept:      aws.String("application/json"),
		Body:        reqBody,
	})
	if err != nil {
		return nil, translateBedrockEmbedError(err)
	}

	var parsed titanResponse
	if err := json.Unmarshal(out.Body, &parsed); err != nil {
		return nil, types.WrapError(ErrCodeEmbeddingFailed, "bedrock: decode response", err)
	}
	if parsed.Message != "" {
		return nil, types.NewError(ErrCodeEmbeddingFailed, "bedrock: "+parsed.Message)
	}
	if err := assertDimension("bedrock", e.dims, len(parsed.Embedding)); err != nil {
		return nil, err
	}
	return parsed.Embedding, nil
}

func (e *bedrockEmbedder) EmbedBatch(ctx context.Context, texts []string) ([][]float64, error) {
	if len(texts) == 0 {
		return [][]float64{}, nil
	}
	out := make([][]float64, len(texts))
	for i, t := range texts {
		if err := ctx.Err(); err != nil {
			return nil, types.WrapError(ErrCodeEmbeddingBatchFailed, "bedrock: context canceled", err)
		}
		v, err := e.Embed(ctx, t)
		if err != nil {
			return nil, types.WrapError(ErrCodeEmbeddingBatchFailed,
				fmt.Sprintf("bedrock: embed text %d", i), err)
		}
		out[i] = v
	}
	return out, nil
}

func (e *bedrockEmbedder) Health(ctx context.Context) types.HealthStatus {
	if _, err := e.Embed(ctx, "healthcheck"); err != nil {
		return types.NewHealthStatus(types.HealthStateUnhealthy, err.Error())
	}
	return types.NewHealthStatus(types.HealthStateHealthy, "")
}

// extra reads a key from Config.Extra, tolerating a nil map.
func extra(cfg Config, key string) string {
	if cfg.Extra == nil {
		return ""
	}
	return cfg.Extra[key]
}

// translateBedrockEmbedError maps common AWS error substrings to gibson error
// codes so callers can distinguish config/auth problems from runtime failures.
func translateBedrockEmbedError(err error) error {
	if err == nil {
		return nil
	}
	lower := strings.ToLower(err.Error())
	switch {
	case strings.Contains(lower, "accessdenied"),
		strings.Contains(lower, "unrecognizedclient"),
		strings.Contains(lower, "unauthorized"):
		return types.WrapError(ErrCodeInvalidConfig, "bedrock: authentication failed", err)
	case strings.Contains(lower, "validationexception"),
		strings.Contains(lower, "modelnotsupported"):
		return types.WrapError(ErrCodeInvalidConfig, "bedrock: invalid request", err)
	default:
		return types.WrapError(ErrCodeEmbeddingFailed, "bedrock: invoke failed", err)
	}
}
