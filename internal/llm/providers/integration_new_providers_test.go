//go:build integration

package providers

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/llm"
)

// Integration tests for every new provider. Each subtest is gated behind a
// per-provider env var so `go test -tags=integration` skips any provider
// the operator hasn't supplied credentials for. Run with e.g.:
//
//	BEDROCK_INTEGRATION=1 AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_REGION=us-east-1 \
//	  go test -tags=integration -v ./internal/llm/providers/ -run TestIntegration
//
// When no gates are set, every test body skips — the suite is green without
// any credentials wired in.

const integrationTimeout = 15 * time.Second

func integrationCtx(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.Background(), integrationTimeout)
}

func shortPrompt() llm.CompletionRequest {
	return llm.CompletionRequest{
		Messages: []llm.Message{
			llm.NewSystemMessage("Respond with exactly one word."),
			llm.NewUserMessage("Say hello."),
		},
		MaxTokens: 16,
	}
}

func TestIntegrationBedrock(t *testing.T) {
	if os.Getenv("BEDROCK_INTEGRATION") != "1" {
		t.Skip("BEDROCK_INTEGRATION not set")
	}
	p, err := NewBedrockProvider(llm.ProviderConfig{
		Type:         llm.ProviderBedrock,
		DefaultModel: "anthropic.claude-3-haiku-20240307-v1:0",
	})
	require.NoError(t, err)

	ctx, cancel := integrationCtx(t)
	defer cancel()

	models, err := p.Models(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, models)

	req := shortPrompt()
	req.Model = "anthropic.claude-3-haiku-20240307-v1:0"
	resp, err := p.Complete(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.Message.Content)
}

func TestIntegrationCloudflare(t *testing.T) {
	if os.Getenv("CLOUDFLARE_INTEGRATION") != "1" {
		t.Skip("CLOUDFLARE_INTEGRATION not set")
	}
	p, err := NewCloudflareProvider(llm.ProviderConfig{
		Type:         llm.ProviderCloudflare,
		DefaultModel: "@cf/meta/llama-3.1-8b-instruct",
	})
	require.NoError(t, err)

	ctx, cancel := integrationCtx(t)
	defer cancel()

	resp, err := p.Complete(ctx, shortPrompt())
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Message.Content)
}

func TestIntegrationCohere(t *testing.T) {
	if os.Getenv("COHERE_INTEGRATION") != "1" {
		t.Skip("COHERE_INTEGRATION not set")
	}
	p, err := NewCohereProvider(llm.ProviderConfig{
		Type:         llm.ProviderCohere,
		DefaultModel: "command-r",
	})
	require.NoError(t, err)

	ctx, cancel := integrationCtx(t)
	defer cancel()

	resp, err := p.Complete(ctx, shortPrompt())
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Message.Content)
}

func TestIntegrationMistral(t *testing.T) {
	if os.Getenv("MISTRAL_INTEGRATION") != "1" {
		t.Skip("MISTRAL_INTEGRATION not set")
	}
	p, err := NewMistralProvider(llm.ProviderConfig{
		Type:         llm.ProviderMistral,
		DefaultModel: "mistral-small-latest",
	})
	require.NoError(t, err)

	ctx, cancel := integrationCtx(t)
	defer cancel()

	resp, err := p.Complete(ctx, shortPrompt())
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Message.Content)
}

func TestIntegrationHuggingFace(t *testing.T) {
	if os.Getenv("HUGGINGFACE_INTEGRATION") != "1" {
		t.Skip("HUGGINGFACE_INTEGRATION not set")
	}
	p, err := NewHuggingFaceProvider(llm.ProviderConfig{
		Type:         llm.ProviderHuggingFace,
		DefaultModel: "meta-llama/Llama-3.1-8B-Instruct",
	})
	require.NoError(t, err)

	ctx, cancel := integrationCtx(t)
	defer cancel()

	resp, err := p.Complete(ctx, shortPrompt())
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Message.Content)
}

func TestIntegrationErnie(t *testing.T) {
	if os.Getenv("ERNIE_INTEGRATION") != "1" {
		t.Skip("ERNIE_INTEGRATION not set")
	}
	p, err := NewErnieProvider(llm.ProviderConfig{
		Type:         llm.ProviderErnie,
		DefaultModel: "ernie-bot-turbo",
	})
	require.NoError(t, err)

	ctx, cancel := integrationCtx(t)
	defer cancel()

	resp, err := p.Complete(ctx, shortPrompt())
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Message.Content)
}

func TestIntegrationMaritaca(t *testing.T) {
	if os.Getenv("MARITACA_INTEGRATION") != "1" {
		t.Skip("MARITACA_INTEGRATION not set")
	}
	p, err := NewMaritacaProvider(llm.ProviderConfig{
		Type:         llm.ProviderMaritaca,
		DefaultModel: "sabia-2-small",
	})
	require.NoError(t, err)

	ctx, cancel := integrationCtx(t)
	defer cancel()

	resp, err := p.Complete(ctx, shortPrompt())
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Message.Content)
}

func TestIntegrationWatsonX(t *testing.T) {
	if os.Getenv("WATSONX_INTEGRATION") != "1" {
		t.Skip("WATSONX_INTEGRATION not set")
	}
	p, err := NewWatsonXProvider(llm.ProviderConfig{
		Type:         llm.ProviderWatsonX,
		DefaultModel: "ibm/granite-13b-chat-v2",
	})
	require.NoError(t, err)

	ctx, cancel := integrationCtx(t)
	defer cancel()

	resp, err := p.Complete(ctx, shortPrompt())
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Message.Content)
}

func TestIntegrationLlamafile(t *testing.T) {
	if os.Getenv("LLAMAFILE_INTEGRATION") != "1" {
		t.Skip("LLAMAFILE_INTEGRATION not set")
	}
	p, err := NewLlamafileProvider(llm.ProviderConfig{
		Type:         llm.ProviderLlamafile,
		DefaultModel: os.Getenv("LLAMAFILE_MODEL"),
	})
	require.NoError(t, err)

	ctx, cancel := integrationCtx(t)
	defer cancel()

	resp, err := p.Complete(ctx, shortPrompt())
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Message.Content)
}

func TestIntegrationLocal(t *testing.T) {
	if os.Getenv("LOCAL_INTEGRATION") != "1" {
		t.Skip("LOCAL_INTEGRATION not set")
	}
	bin := os.Getenv("LOCAL_LLM_BIN")
	require.NotEmpty(t, bin, "LOCAL_LLM_BIN must be set when LOCAL_INTEGRATION=1")
	p, err := NewLocalProvider(llm.ProviderConfig{
		Type:         llm.ProviderLocal,
		DefaultModel: "local-model",
		Extra:        map[string]string{"bin": bin},
	})
	require.NoError(t, err)

	ctx, cancel := integrationCtx(t)
	defer cancel()

	resp, err := p.Complete(ctx, shortPrompt())
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Message.Content)
}
