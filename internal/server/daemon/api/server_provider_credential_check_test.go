// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

// server_provider_credential_check_test.go — gibson#1193: the connection test
// is the model list call of the provider. It needs no model ID and sends no
// completion. These tests run the real Anthropic provider against an httptest
// fake and count every request that reaches it.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/engine/llm/providers"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// fakeAnthropic answers GET /v1/models and counts every request by kind.
type fakeAnthropic struct {
	*httptest.Server
	listCalls  atomic.Int32
	otherCalls atomic.Int32
	lastKey    atomic.Value
	statusCode int
	body       string
}

func newFakeAnthropic(t *testing.T, status int, body string) *fakeAnthropic {
	t.Helper()
	f := &fakeAnthropic{statusCode: status, body: body}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/models" {
			f.listCalls.Add(1)
			f.lastKey.Store(r.Header.Get("x-api-key"))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(f.statusCode)
			_, _ = w.Write([]byte(f.body))
			return
		}
		f.otherCalls.Add(1)
		w.WriteHeader(http.StatusTeapot)
	}))
	t.Cleanup(f.Close)
	return f
}

// withFakeAnthropic wires the server factory to build the real Anthropic
// provider against the fake.
func withFakeAnthropic(s *DaemonServer, f *fakeAnthropic) *DaemonServer {
	return s.WithProviderFactory(func(cfg llm.ProviderConfig) (llm.LLMProvider, error) {
		return providers.NewAnthropicProvider(llm.ProviderConfig{
			APIKey:               cfg.APIKey,
			DefaultModel:         cfg.DefaultModel,
			BaseURL:              f.URL,
			AllowPrivateEndpoint: true,
		})
	})
}

const anthropicModelsBody = `{"data":[{"id":"claude-live-1","max_input_tokens":200000},{"id":"claude-live-2"}],"has_more":false,"last_id":"claude-live-2"}`

func anthropicTestInput(key string) *tenantv1.ProviderConfigInput {
	return &tenantv1.ProviderConfigInput{
		Name:        "anthropic-prod",
		Type:        "anthropic",
		Credentials: map[string]string{"api_key": key},
		// No default_model: the test must not need one.
	}
}

func TestTestProvider_GoodKeyNeedsNoModel(t *testing.T) {
	fake := newFakeAnthropic(t, http.StatusOK, anthropicModelsBody)
	s := withFakeAnthropic(auditedServer(t), fake)

	resp, err := s.TestProvider(tenantCtx("acme"), &tenantv1.TestProviderRequest{Input: anthropicTestInput("sk-good")})
	require.NoError(t, err)
	require.True(t, resp.Ok, "error: %s", resp.Error)
	assert.Empty(t, resp.Error)
	require.Len(t, resp.Models, 2)
	assert.Equal(t, "claude-live-1", resp.Models[0].Name)
	assert.EqualValues(t, 200000, resp.Models[0].ContextWindow)
	assert.Equal(t, "claude-live-2", resp.Models[1].Name)
	assert.Equal(t, "sk-good", fake.lastKey.Load())
	assert.EqualValues(t, 1, fake.listCalls.Load())
	assert.Zero(t, fake.otherCalls.Load(), "no completion request may reach the provider")
}

func TestTestProvider_BadKeyShowsTheProviderMessage(t *testing.T) {
	fake := newFakeAnthropic(t, http.StatusUnauthorized,
		`{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}`)
	s := withFakeAnthropic(auditedServer(t), fake)

	resp, err := s.TestProvider(tenantCtx("acme"), &tenantv1.TestProviderRequest{Input: anthropicTestInput("sk-bad")})
	require.NoError(t, err, "a bad key is a response, never a gRPC error")
	assert.False(t, resp.Ok)
	assert.Contains(t, resp.Error, "invalid x-api-key")
	assert.NotContains(t, resp.Error, "sk-bad")
	assert.Empty(t, resp.Models)
	assert.Zero(t, fake.otherCalls.Load(), "no completion request may reach the provider")
}

func TestTestProvider_WrongEndpointShowsAnEndpointError(t *testing.T) {
	fake := newFakeAnthropic(t, http.StatusNotFound, `{"error":{"message":"not found"}}`)
	s := withFakeAnthropic(auditedServer(t), fake)

	resp, err := s.TestProvider(tenantCtx("acme"), &tenantv1.TestProviderRequest{Input: anthropicTestInput("sk-x")})
	require.NoError(t, err)
	assert.False(t, resp.Ok)
	assert.Contains(t, resp.Error, "endpoint")
	assert.Contains(t, resp.Error, "404")
}

// blockingLister is a provider whose Models call waits for the context.
type blockingLister struct{ stubMockProvider }

func (*blockingLister) Models(ctx context.Context) ([]llm.ModelInfo, error) {
	<-ctx.Done()
	return nil, fmt.Errorf("models call cancelled: %w", ctx.Err())
}

func TestTestProvider_SlowProviderTimesOut(t *testing.T) {
	s := auditedServer(t).WithProviderFactory(func(llm.ProviderConfig) (llm.LLMProvider, error) {
		return &blockingLister{}, nil
	})
	ctx, cancel := context.WithTimeout(tenantCtx("acme"), 50*time.Millisecond)
	defer cancel()

	resp, err := s.TestProvider(ctx, &tenantv1.TestProviderRequest{Input: anthropicTestInput("sk-x")})
	require.NoError(t, err)
	assert.False(t, resp.Ok)
	assert.Contains(t, resp.Error, "deadline")
}

func TestTestProvider_FactoryErrorIsAResponse(t *testing.T) {
	s := auditedServer(t).WithProviderFactory(func(llm.ProviderConfig) (llm.LLMProvider, error) {
		return nil, assert.AnError
	})
	resp, err := s.TestProvider(tenantCtx("acme"), &tenantv1.TestProviderRequest{Input: anthropicTestInput("sk-x")})
	require.NoError(t, err)
	assert.False(t, resp.Ok)
	assert.Contains(t, resp.Error, "invalid provider configuration")
}

func TestProbeProvider_GoodKeyNeedsNoModel(t *testing.T) {
	fake := newFakeAnthropic(t, http.StatusOK, anthropicModelsBody)
	s := withFakeAnthropic(auditedServer(t), fake)

	resp, err := s.ProbeProvider(tenantCtx("acme"), &tenantv1.ProbeProviderRequest{
		Type:        "anthropic",
		Credentials: map[string]string{"api_key": "sk-good"},
	})
	require.NoError(t, err)
	require.True(t, resp.Ok, "error: %s", resp.ErrorMessage)
	require.Len(t, resp.Models, 2)
	assert.Zero(t, fake.otherCalls.Load(), "no completion request may reach the provider")
}

func TestProbeProvider_BadKeyShowsTheProviderMessage(t *testing.T) {
	fake := newFakeAnthropic(t, http.StatusUnauthorized, `{"error":{"message":"invalid x-api-key"}}`)
	s := withFakeAnthropic(auditedServer(t), fake)

	resp, err := s.ProbeProvider(tenantCtx("acme"), &tenantv1.ProbeProviderRequest{
		Type:        "anthropic",
		Credentials: map[string]string{"api_key": "sk-bad"},
	})
	require.NoError(t, err)
	assert.False(t, resp.Ok)
	assert.Contains(t, resp.ErrorMessage, "invalid x-api-key")
	assert.Equal(t, "auth_failed", resp.ErrorClass)
	assert.Zero(t, fake.otherCalls.Load())
}

func TestProbeProvider_FactoryErrorIsAResponse(t *testing.T) {
	s := auditedServer(t).WithProviderFactory(func(llm.ProviderConfig) (llm.LLMProvider, error) {
		return nil, assert.AnError
	})
	resp, err := s.ProbeProvider(tenantCtx("acme"), &tenantv1.ProbeProviderRequest{
		Type:        "anthropic",
		Credentials: map[string]string{"api_key": "sk-x"},
	})
	require.NoError(t, err)
	assert.False(t, resp.Ok)
	assert.Contains(t, resp.ErrorMessage, "invalid provider configuration")
}
