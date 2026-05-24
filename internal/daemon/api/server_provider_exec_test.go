package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zero-day-ai/gibson/internal/budget"
	"github.com/zero-day-ai/gibson/internal/contextkeys"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/providerconfig"
	"github.com/zero-day-ai/gibson/internal/ratelimit"
	"github.com/zero-day-ai/gibson/internal/types"
	tenantv1 "github.com/zero-day-ai/sdk/api/gen/gibson/tenant/v1"
	"github.com/zero-day-ai/sdk/auth"
)

// ---------------------------------------------------------------------------
// Stubs
// ---------------------------------------------------------------------------

// stubProviderConfigStore implements providerConfigStoreIface for tests.
// Only the Resolve method is exercised by the exec handlers.
type stubProviderConfigStore struct {
	resolveFunc func(ctx context.Context, tenantID, name string) (*providerconfig.DecryptedConfig, error)
}

func (s *stubProviderConfigStore) List(ctx context.Context, tenantID string) ([]*providerconfig.ProviderConfig, error) {
	return nil, nil
}
func (s *stubProviderConfigStore) Get(ctx context.Context, tenantID, name string) (*providerconfig.ProviderConfig, error) {
	return nil, nil
}
func (s *stubProviderConfigStore) Create(ctx context.Context, tenantID string, input *providerconfig.ProviderConfigInput) (*providerconfig.ProviderConfig, error) {
	return nil, nil
}
func (s *stubProviderConfigStore) Update(ctx context.Context, tenantID, name string, input *providerconfig.ProviderConfigInput) (*providerconfig.ProviderConfig, error) {
	return nil, nil
}
func (s *stubProviderConfigStore) Delete(ctx context.Context, tenantID, name string) error {
	return nil
}
func (s *stubProviderConfigStore) GetDefault(ctx context.Context, tenantID string) (*providerconfig.ProviderConfig, error) {
	return nil, nil
}
func (s *stubProviderConfigStore) SetDefault(ctx context.Context, tenantID, name string) error {
	return nil
}
func (s *stubProviderConfigStore) GetFallbackChain(ctx context.Context, tenantID string) ([]string, error) {
	return nil, nil
}
func (s *stubProviderConfigStore) SetFallbackChain(ctx context.Context, tenantID string, names []string) error {
	return nil
}
func (s *stubProviderConfigStore) Resolve(ctx context.Context, tenantID, name string) (*providerconfig.DecryptedConfig, error) {
	if s.resolveFunc != nil {
		return s.resolveFunc(ctx, tenantID, name)
	}
	return nil, providerconfig.ErrNotFound
}

// stubMockProvider is a minimal llm.LLMProvider that returns canned responses.
type stubMockProvider struct {
	completeFunc func(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error)
	streamFunc   func(ctx context.Context, req llm.CompletionRequest) (<-chan llm.StreamChunk, error)
}

func (p *stubMockProvider) Name() string { return "stub" }
func (p *stubMockProvider) Models(ctx context.Context) ([]llm.ModelInfo, error) {
	return nil, nil
}
func (p *stubMockProvider) Complete(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	if p.completeFunc != nil {
		return p.completeFunc(ctx, req)
	}
	return &llm.CompletionResponse{
		Message: llm.Message{Role: llm.RoleAssistant, Content: "stub response"},
	}, nil
}
func (p *stubMockProvider) CompleteWithTools(ctx context.Context, req llm.CompletionRequest, tools []llm.ToolDef) (*llm.CompletionResponse, error) {
	return p.Complete(ctx, req)
}
func (p *stubMockProvider) Stream(ctx context.Context, req llm.CompletionRequest) (<-chan llm.StreamChunk, error) {
	if p.streamFunc != nil {
		return p.streamFunc(ctx, req)
	}
	ch := make(chan llm.StreamChunk, 2)
	ch <- llm.StreamChunk{Delta: llm.StreamDelta{Content: "hello"}}
	ch <- llm.StreamChunk{FinishReason: llm.FinishReasonStop}
	close(ch)
	return ch, nil
}

func (p *stubMockProvider) Health(_ context.Context) types.HealthStatus {
	return types.NewHealthStatus(types.HealthStateHealthy, "")
}

// stubExecLimiter is a controllable execLimiterIface.
type stubExecLimiter struct {
	calls   int
	blockAt int // block on the nth call (1-based). 0 = never block.
}

func (l *stubExecLimiter) Check(_ context.Context, _, _ string) error {
	l.calls++
	if l.blockAt > 0 && l.calls >= l.blockAt {
		return ratelimit.ErrRateLimited
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// tenantCtx builds a context with the given tenant wired in.
func tenantCtx(tenantID string) context.Context {
	return auth.ContextWithTenantString(context.Background(), tenantID)
}

// newExecServer builds a minimal DaemonServer with a stubbed provider store and
// factory. Callers may further customise fields (e.g. WithExecLimiter).
func newExecServer(store providerConfigStoreIface, factory func(llm.ProviderConfig) (llm.LLMProvider, error)) *DaemonServer {
	s := &DaemonServer{
		logger:          slog.Default(),
		providerConfig:  store,
		providerFactory: factory,
	}
	return s
}

// knownDecryptedConfig returns a DecryptedConfig that exercises the
// api_key / base_url / extra credential path.
func knownDecryptedConfig() *providerconfig.DecryptedConfig {
	return &providerconfig.DecryptedConfig{
		ProviderConfig: providerconfig.ProviderConfig{
			Type:         "openai",
			DefaultModel: "gpt-4o",
		},
		Credentials: map[string]string{
			"api_key":  "sk-secret-123456",
			"base_url": "https://api.openai.com/v1",
		},
	}
}

// ---------------------------------------------------------------------------
// ExecuteLLM tests
// ---------------------------------------------------------------------------

// TestExecuteLLM_RoundTrip exercises the happy-path unary handler: messages are
// translated into the llm.CompletionRequest, the provider is called, and the
// response fields are mapped back to proto.
func TestExecuteLLM_RoundTrip(t *testing.T) {
	store := &stubProviderConfigStore{
		resolveFunc: func(_ context.Context, _, _ string) (*providerconfig.DecryptedConfig, error) {
			return knownDecryptedConfig(), nil
		},
	}

	var capturedReq llm.CompletionRequest
	prov := &stubMockProvider{
		completeFunc: func(_ context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
			capturedReq = req
			return &llm.CompletionResponse{
				Message: llm.Message{
					Role:    llm.RoleAssistant,
					Content: "hello from LLM",
				},
				FinishReason: llm.FinishReasonStop,
				Usage: llm.CompletionTokenUsage{
					PromptTokens:     5,
					CompletionTokens: 4,
					TotalTokens:      9,
				},
			}, nil
		},
	}

	s := newExecServer(store, func(_ llm.ProviderConfig) (llm.LLMProvider, error) {
		return prov, nil
	})

	ctx := tenantCtx("tenant-a")
	req := &tenantv1.ExecuteLLMRequest{
		ProviderName: "my-openai",
		Model:        "gpt-4o-mini",
		Messages: []*tenantv1.LLMMessageContent{
			{Role: "user", Content: "hello"},
		},
	}

	resp, err := s.ExecuteLLM(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, "hello from LLM", resp.Content)
	assert.Equal(t, string(llm.FinishReasonStop), resp.FinishReason)
	require.NotNil(t, resp.Usage)
	assert.Equal(t, int32(5), resp.Usage.InputTokens)
	assert.Equal(t, int32(4), resp.Usage.OutputTokens)
	assert.Equal(t, int32(9), resp.Usage.TotalTokens)

	// Model override must reach the CompletionRequest.
	assert.Equal(t, "gpt-4o-mini", capturedReq.Model)

	// Message translation must preserve role and content.
	require.Len(t, capturedReq.Messages, 1)
	assert.Equal(t, llm.Role("user"), capturedReq.Messages[0].Role)
	assert.Equal(t, "hello", capturedReq.Messages[0].Content)
}

// TestExecuteLLM_NoProviderStore ensures FailedPrecondition is returned when
// the server has no provider config store wired.
func TestExecuteLLM_NoProviderStore(t *testing.T) {
	s := &DaemonServer{
		logger:          slog.Default(),
		providerFactory: func(_ llm.ProviderConfig) (llm.LLMProvider, error) { return nil, nil },
	}
	ctx := tenantCtx("tenant-a")
	_, err := s.ExecuteLLM(ctx, &tenantv1.ExecuteLLMRequest{ProviderName: "x"})
	require.Error(t, err)
	st, _ := status_grpc.FromError(err)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

// TestExecuteLLM_ProviderNotFound ensures NotFound is propagated when the store
// returns ErrNotFound.
func TestExecuteLLM_ProviderNotFound(t *testing.T) {
	store := &stubProviderConfigStore{}
	s := newExecServer(store, func(_ llm.ProviderConfig) (llm.LLMProvider, error) { return nil, nil })
	ctx := tenantCtx("tenant-a")
	_, err := s.ExecuteLLM(ctx, &tenantv1.ExecuteLLMRequest{ProviderName: "missing"})
	require.Error(t, err)
	st, _ := status_grpc.FromError(err)
	assert.Equal(t, codes.NotFound, st.Code())
}

// TestExecuteLLM_NoTenantContext verifies that a context with no explicit tenant
// is rejected with Unauthenticated. Under the Envoy/identity interceptor model,
// the tenant is derived from the SPIFFE-mTLS-authenticated identity headers
// injected by ext-authz. A context with no identity (or _system tenant)
// cannot proceed to the provider store.
func TestExecuteLLM_NoTenantContext(t *testing.T) {
	store := &stubProviderConfigStore{} // Resolve always returns ErrNotFound
	s := newExecServer(store, func(_ llm.ProviderConfig) (llm.LLMProvider, error) { return nil, nil })
	// Plain context — no tenant identity; handler rejects with Unauthenticated.
	_, err := s.ExecuteLLM(context.Background(), &tenantv1.ExecuteLLMRequest{ProviderName: "x"})
	require.Error(t, err)
	st, _ := status_grpc.FromError(err)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

// TestExecuteLLM_RateLimitEnforced verifies that the 11th call returns
// ResourceExhausted when a limiter with blockAt=11 is wired.
func TestExecuteLLM_RateLimitEnforced(t *testing.T) {
	store := &stubProviderConfigStore{
		resolveFunc: func(_ context.Context, _, _ string) (*providerconfig.DecryptedConfig, error) {
			return knownDecryptedConfig(), nil
		},
	}
	prov := &stubMockProvider{}
	s := newExecServer(store, func(_ llm.ProviderConfig) (llm.LLMProvider, error) { return prov, nil })

	limiter := &stubExecLimiter{blockAt: 11}
	s.WithExecLimiter(limiter)

	ctx := tenantCtx("tenant-rl")
	req := &tenantv1.ExecuteLLMRequest{ProviderName: "p", Messages: []*tenantv1.LLMMessageContent{{Role: "user", Content: "hi"}}}

	for i := 0; i < 10; i++ {
		_, err := s.ExecuteLLM(ctx, req)
		require.NoError(t, err, "call %d should succeed", i+1)
	}

	_, err := s.ExecuteLLM(ctx, req)
	require.Error(t, err)
	st, _ := status_grpc.FromError(err)
	assert.Equal(t, codes.ResourceExhausted, st.Code())
}

// TestExecuteLLM_CredentialNotLeaked is a security regression test.
// The known credential string must never appear in the serialised proto response.
func TestExecuteLLM_CredentialNotLeaked(t *testing.T) {
	const secretKey = "sk-secret-123456"

	store := &stubProviderConfigStore{
		resolveFunc: func(_ context.Context, _, _ string) (*providerconfig.DecryptedConfig, error) {
			return &providerconfig.DecryptedConfig{
				ProviderConfig: providerconfig.ProviderConfig{
					Type:         "openai",
					DefaultModel: "gpt-4o",
				},
				Credentials: map[string]string{
					"api_key": secretKey,
				},
			}, nil
		},
	}
	prov := &stubMockProvider{}
	s := newExecServer(store, func(_ llm.ProviderConfig) (llm.LLMProvider, error) { return prov, nil })

	ctx := tenantCtx("tenant-sec")
	resp, err := s.ExecuteLLM(ctx, &tenantv1.ExecuteLLMRequest{
		ProviderName: "p",
		Messages:     []*tenantv1.LLMMessageContent{{Role: "user", Content: "hi"}},
	})
	require.NoError(t, err)

	// Serialise the proto response to JSON and assert the credential is absent.
	raw, jsonErr := json.Marshal(resp)
	require.NoError(t, jsonErr)
	assert.NotContains(t, string(raw), secretKey,
		"decrypted credential must not appear in the serialised response")
}

// TestExecuteLLM_ToolCalls verifies that tool calls in the completion response
// are correctly translated into the proto ToolCall slice.
func TestExecuteLLM_ToolCalls(t *testing.T) {
	store := &stubProviderConfigStore{
		resolveFunc: func(_ context.Context, _, _ string) (*providerconfig.DecryptedConfig, error) {
			return knownDecryptedConfig(), nil
		},
	}
	prov := &stubMockProvider{
		completeFunc: func(_ context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
			return &llm.CompletionResponse{
				Message: llm.Message{
					Role: llm.RoleAssistant,
					ToolCalls: []llm.ToolCall{
						{ID: "call-1", Name: "nmap", Arguments: `{"target":"1.2.3.4"}`},
					},
				},
				FinishReason: llm.FinishReasonToolCalls,
			}, nil
		},
	}
	s := newExecServer(store, func(_ llm.ProviderConfig) (llm.LLMProvider, error) { return prov, nil })

	ctx := tenantCtx("tenant-tools")
	resp, err := s.ExecuteLLM(ctx, &tenantv1.ExecuteLLMRequest{
		ProviderName: "p",
		Messages:     []*tenantv1.LLMMessageContent{{Role: "user", Content: "scan this"}},
		Tools:        []*tenantv1.LLMToolDef{{Name: "nmap", Description: "port scanner"}},
	})
	require.NoError(t, err)
	require.Len(t, resp.ToolCalls, 1)
	assert.Equal(t, "call-1", resp.ToolCalls[0].Id)
	assert.Equal(t, "nmap", resp.ToolCalls[0].Name)
	assert.Equal(t, `{"target":"1.2.3.4"}`, resp.ToolCalls[0].Arguments)
}

// TestExecuteLLM_StructuredOutputUnimplemented checks that requesting json_schema
// format against a provider that doesn't implement StructuredOutputProvider
// returns codes.Unimplemented.
func TestExecuteLLM_StructuredOutputUnimplemented(t *testing.T) {
	store := &stubProviderConfigStore{
		resolveFunc: func(_ context.Context, _, _ string) (*providerconfig.DecryptedConfig, error) {
			return knownDecryptedConfig(), nil
		},
	}
	// stubMockProvider does NOT implement llm.StructuredOutputProvider.
	prov := &stubMockProvider{}
	s := newExecServer(store, func(_ llm.ProviderConfig) (llm.LLMProvider, error) { return prov, nil })

	ctx := tenantCtx("tenant-struct")
	resp, err := s.ExecuteLLM(ctx, &tenantv1.ExecuteLLMRequest{
		ProviderName:   "p",
		Messages:       []*tenantv1.LLMMessageContent{{Role: "user", Content: "json please"}},
		ResponseFormat: &tenantv1.ResponseFormat{Type: "json_schema", Name: "MySchema"},
	})
	require.Error(t, err)
	assert.Nil(t, resp)
	st, _ := status_grpc.FromError(err)
	assert.Equal(t, codes.Unimplemented, st.Code())
}

// TestExecuteLLM_TemperatureMaxTokens verifies that optional scalar request
// fields are forwarded to the CompletionRequest when present and zero-valued
// when absent.
func TestExecuteLLM_TemperatureMaxTokens(t *testing.T) {
	store := &stubProviderConfigStore{
		resolveFunc: func(_ context.Context, _, _ string) (*providerconfig.DecryptedConfig, error) {
			return knownDecryptedConfig(), nil
		},
	}
	var capturedReq llm.CompletionRequest
	prov := &stubMockProvider{
		completeFunc: func(_ context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
			capturedReq = req
			return &llm.CompletionResponse{Message: llm.Message{Content: "ok"}}, nil
		},
	}
	s := newExecServer(store, func(_ llm.ProviderConfig) (llm.LLMProvider, error) { return prov, nil })

	temp := float64(0.7)
	maxTok := int32(512)
	ctx := tenantCtx("tenant-params")
	_, err := s.ExecuteLLM(ctx, &tenantv1.ExecuteLLMRequest{
		ProviderName: "p",
		Messages:     []*tenantv1.LLMMessageContent{{Role: "user", Content: "hi"}},
		Temperature:  &temp,
		MaxTokens:    &maxTok,
	})
	require.NoError(t, err)
	assert.InDelta(t, 0.7, capturedReq.Temperature, 0.001)
	assert.Equal(t, 512, capturedReq.MaxTokens)
}

// ---------------------------------------------------------------------------
// decryptedConfigToLLMConfig unit tests
// ---------------------------------------------------------------------------

// TestDecryptedConfigToLLMConfig_APIKeyAndBaseURL verifies the two canonical
// credential fields are promoted into the typed ProviderConfig fields.
func TestDecryptedConfigToLLMConfig_APIKeyAndBaseURL(t *testing.T) {
	dec := &providerconfig.DecryptedConfig{
		ProviderConfig: providerconfig.ProviderConfig{
			Type:         "openai",
			DefaultModel: "gpt-4o",
		},
		Credentials: map[string]string{
			"api_key":  "sk-abc",
			"base_url": "https://custom.endpoint/v1",
			"org":      "org-123",
		},
	}

	cfg := decryptedConfigToLLMConfig(dec, "")
	assert.Equal(t, "sk-abc", cfg.APIKey)
	assert.Equal(t, "https://custom.endpoint/v1", cfg.BaseURL)
	assert.Equal(t, "org-123", cfg.Extra["org"])
	// api_key and base_url must NOT appear in Extra.
	assert.NotContains(t, cfg.Extra, "api_key")
	assert.NotContains(t, cfg.Extra, "base_url")
	// Default model falls through when no override.
	assert.Equal(t, "gpt-4o", cfg.DefaultModel)
}

// TestDecryptedConfigToLLMConfig_ModelOverride verifies that a non-empty
// modelOverride replaces the stored default_model.
func TestDecryptedConfigToLLMConfig_ModelOverride(t *testing.T) {
	dec := &providerconfig.DecryptedConfig{
		ProviderConfig: providerconfig.ProviderConfig{Type: "openai", DefaultModel: "gpt-4o"},
		Credentials:    map[string]string{"api_key": "x"},
	}
	cfg := decryptedConfigToLLMConfig(dec, "gpt-4o-mini")
	assert.Equal(t, "gpt-4o-mini", cfg.DefaultModel)
}

// ---------------------------------------------------------------------------
// protoMessagesToLLM unit tests
// ---------------------------------------------------------------------------

// TestProtoMessagesToLLM_ToolResults verifies that tool-result entries inside a
// proto message are promoted to standalone llm.Message values with RoleTool.
func TestProtoMessagesToLLM_ToolResults(t *testing.T) {
	msgs := protoMessagesToLLM([]*tenantv1.LLMMessageContent{
		{
			Role: "tool",
			ToolResults: []*tenantv1.LLMToolResult{
				{ToolCallId: "call-1", Content: "result-A"},
				{ToolCallId: "call-2", Content: "result-B"},
			},
		},
	})

	require.Len(t, msgs, 2, "each tool result becomes a separate llm.Message")
	assert.Equal(t, llm.RoleTool, msgs[0].Role)
	assert.Equal(t, "call-1", msgs[0].ToolCallID)
	assert.Equal(t, "result-A", msgs[0].Content)
	assert.Equal(t, llm.RoleTool, msgs[1].Role)
	assert.Equal(t, "call-2", msgs[1].ToolCallID)
}

// TestProtoMessagesToLLM_Empty returns nil for an empty slice.
func TestProtoMessagesToLLM_Empty(t *testing.T) {
	assert.Nil(t, protoMessagesToLLM(nil))
	assert.Nil(t, protoMessagesToLLM([]*tenantv1.LLMMessageContent{}))
}

// ---------------------------------------------------------------------------
// protoToolDefsToLLM unit tests
// ---------------------------------------------------------------------------

// TestProtoToolDefsToLLM_ParsesParametersJson verifies that a valid
// parameters_json string is unmarshalled into the schema.JSON Parameters field.
func TestProtoToolDefsToLLM_ParsesParametersJson(t *testing.T) {
	params := `{"type":"object","properties":{"target":{"type":"string"}}}`
	defs := protoToolDefsToLLM([]*tenantv1.LLMToolDef{
		{Name: "nmap", Description: "port scanner", ParametersJson: params},
	})
	require.Len(t, defs, 1)
	assert.Equal(t, "nmap", defs[0].Name)
	assert.Equal(t, "object", defs[0].Parameters.Type)
	assert.Contains(t, defs[0].Parameters.Properties, "target")
}

// TestProtoToolDefsToLLM_InvalidJsonFallsBackToObjectSchema verifies that an
// invalid parameters_json value does not cause the request to fail — the tool
// is included with an empty object schema.
func TestProtoToolDefsToLLM_InvalidJsonFallsBackToObjectSchema(t *testing.T) {
	defs := protoToolDefsToLLM([]*tenantv1.LLMToolDef{
		{Name: "bad-tool", Description: "has bad params", ParametersJson: "not-json{"},
	})
	require.Len(t, defs, 1)
	assert.Equal(t, "object", defs[0].Parameters.Type)
}

// ---------------------------------------------------------------------------
// completionRespToProto unit tests
// ---------------------------------------------------------------------------

// TestCompletionRespToProto_NilResponse returns a non-nil empty proto.
func TestCompletionRespToProto_NilResponse(t *testing.T) {
	out := completionRespToProto(nil)
	require.NotNil(t, out)
}

// TestCompletionRespToProto_Usage verifies usage token counts are mapped correctly.
func TestCompletionRespToProto_Usage(t *testing.T) {
	resp := &llm.CompletionResponse{
		Message:      llm.Message{Content: "hi"},
		FinishReason: llm.FinishReasonStop,
		Usage: llm.CompletionTokenUsage{
			PromptTokens:     100,
			CompletionTokens: 50,
			TotalTokens:      150,
		},
	}
	out := completionRespToProto(resp)
	require.NotNil(t, out.Usage)
	assert.Equal(t, int32(100), out.Usage.InputTokens)
	assert.Equal(t, int32(50), out.Usage.OutputTokens)
	assert.Equal(t, int32(150), out.Usage.TotalTokens)
}

// ---------------------------------------------------------------------------
// WithProviderFactory / WithExecLimiter wiring tests
// ---------------------------------------------------------------------------

// TestWithProviderFactory_ReplacesDefault verifies the factory seam can be
// replaced so tests never call the real providers.NewProvider.
func TestWithProviderFactory_ReplacesDefault(t *testing.T) {
	s := &DaemonServer{
		logger:          slog.Default(),
		providerFactory: providerFactoryFunc, // default
	}
	called := false
	s.WithProviderFactory(func(_ llm.ProviderConfig) (llm.LLMProvider, error) {
		called = true
		return &stubMockProvider{}, nil
	})

	store := &stubProviderConfigStore{
		resolveFunc: func(_ context.Context, _, _ string) (*providerconfig.DecryptedConfig, error) {
			return knownDecryptedConfig(), nil
		},
	}
	s.providerConfig = store

	_, err := s.ExecuteLLM(tenantCtx("t"), &tenantv1.ExecuteLLMRequest{
		ProviderName: "p",
		Messages:     []*tenantv1.LLMMessageContent{{Role: "user", Content: "hi"}},
	})
	require.NoError(t, err)
	assert.True(t, called, "injected factory must be invoked")
}

// TestWithExecLimiter_NilLimiterSkipsCheck verifies that a nil execLimiter
// field does not panic and allows all requests through.
func TestWithExecLimiter_NilLimiterSkipsCheck(t *testing.T) {
	store := &stubProviderConfigStore{
		resolveFunc: func(_ context.Context, _, _ string) (*providerconfig.DecryptedConfig, error) {
			return knownDecryptedConfig(), nil
		},
	}
	s := newExecServer(store, func(_ llm.ProviderConfig) (llm.LLMProvider, error) {
		return &stubMockProvider{}, nil
	})
	// execLimiter is nil by default.

	_, err := s.ExecuteLLM(tenantCtx("t"), &tenantv1.ExecuteLLMRequest{
		ProviderName: "p",
		Messages:     []*tenantv1.LLMMessageContent{{Role: "user", Content: "hi"}},
	})
	require.NoError(t, err)
}

// TestErrRateLimited_IsSentinel ensures ratelimit.ErrRateLimited is detectable
// with errors.Is from the handler's perspective.
func TestErrRateLimited_IsSentinel(t *testing.T) {
	wrapped := errors.Join(errors.New("outer"), ratelimit.ErrRateLimited)
	assert.True(t, errors.Is(wrapped, ratelimit.ErrRateLimited))
}

// ---------------------------------------------------------------------------
// stubBudgetEnforcer
// ---------------------------------------------------------------------------

// stubBudgetEnforcer implements budgetEnforcerIface for unit tests.
// checkErr controls whether Check returns an error (simulating exhausted budget).
// recordCalls records how many times Record was called and the total tokens seen.
type stubBudgetEnforcer struct {
	checkErr      error
	recordCalls   int
	recordedTotal int64
}

func (e *stubBudgetEnforcer) Check(_ context.Context, _ int64) (*budget.Status, error) {
	return nil, e.checkErr
}

func (e *stubBudgetEnforcer) Record(_ context.Context, tokens int64, _ int64) error {
	e.recordCalls++
	e.recordedTotal += tokens
	return nil
}

// ---------------------------------------------------------------------------
// ExecuteLLM budget tests
// ---------------------------------------------------------------------------

// TestExecuteLLM_BudgetExhaustedBlocked verifies that ExecuteLLM returns
// ResourceExhausted before dispatching to the provider when the budget enforcer
// denies the call. No tokens must be consumed.
func TestExecuteLLM_BudgetExhaustedBlocked(t *testing.T) {
	store := &stubProviderConfigStore{
		resolveFunc: func(_ context.Context, _, _ string) (*providerconfig.DecryptedConfig, error) {
			return knownDecryptedConfig(), nil
		},
	}
	providerCalled := false
	prov := &stubMockProvider{
		completeFunc: func(_ context.Context, _ llm.CompletionRequest) (*llm.CompletionResponse, error) {
			providerCalled = true
			return &llm.CompletionResponse{Message: llm.Message{Content: "should not reach here"}}, nil
		},
	}
	s := newExecServer(store, func(_ llm.ProviderConfig) (llm.LLMProvider, error) { return prov, nil })

	budgetErr := status_grpc.Errorf(codes.ResourceExhausted, "monthly token limit exceeded")
	enforcer := &stubBudgetEnforcer{checkErr: budgetErr}
	s.WithBudgetEnforcer(enforcer)

	ctx := tenantCtx("tenant-budget")
	_, err := s.ExecuteLLM(ctx, &tenantv1.ExecuteLLMRequest{
		ProviderName: "p",
		Messages:     []*tenantv1.LLMMessageContent{{Role: "user", Content: "hi"}},
	})

	require.Error(t, err)
	st, _ := status_grpc.FromError(err)
	assert.Equal(t, codes.ResourceExhausted, st.Code(), "exhausted budget must yield ResourceExhausted")
	assert.False(t, providerCalled, "provider must not be called when budget is exhausted")
	assert.Equal(t, 0, enforcer.recordCalls, "Record must not be called when budget check fails")
}

// TestExecuteLLM_BudgetRecordedAfterDispatch verifies that successful
// ExecuteLLM calls record authoritative token usage via the budget enforcer.
func TestExecuteLLM_BudgetRecordedAfterDispatch(t *testing.T) {
	store := &stubProviderConfigStore{
		resolveFunc: func(_ context.Context, _, _ string) (*providerconfig.DecryptedConfig, error) {
			return knownDecryptedConfig(), nil
		},
	}
	prov := &stubMockProvider{
		completeFunc: func(_ context.Context, _ llm.CompletionRequest) (*llm.CompletionResponse, error) {
			return &llm.CompletionResponse{
				Message: llm.Message{Content: "ok"},
				Usage: llm.CompletionTokenUsage{
					PromptTokens:     10,
					CompletionTokens: 20,
					TotalTokens:      30,
				},
			}, nil
		},
	}
	s := newExecServer(store, func(_ llm.ProviderConfig) (llm.LLMProvider, error) { return prov, nil })

	enforcer := &stubBudgetEnforcer{}
	s.WithBudgetEnforcer(enforcer)

	ctx := tenantCtx("tenant-record")
	_, err := s.ExecuteLLM(ctx, &tenantv1.ExecuteLLMRequest{
		ProviderName: "p",
		Messages:     []*tenantv1.LLMMessageContent{{Role: "user", Content: "hello world"}},
	})

	require.NoError(t, err)
	assert.Equal(t, 1, enforcer.recordCalls, "Record must be called once after dispatch")
	assert.Equal(t, int64(30), enforcer.recordedTotal, "recorded tokens must equal provider's total usage")
}

// ---------------------------------------------------------------------------
// Per-call token cap tests (M4 — gibson#133)
// ---------------------------------------------------------------------------

// TestExecuteLLM_PerCallCap_clampsMaxTokens verifies that when a per-call cap is
// placed in context via contextkeys.WithPerCallTokenCap, the ExecuteLLM handler
// clamps req.MaxTokens to the cap before dispatching to the provider.
// Scenario: caller requests 4096 tokens; context cap = 100; provider must see 100.
func TestExecuteLLM_PerCallCap_clampsMaxTokens(t *testing.T) {
	store := &stubProviderConfigStore{
		resolveFunc: func(_ context.Context, _, _ string) (*providerconfig.DecryptedConfig, error) {
			return knownDecryptedConfig(), nil
		},
	}

	var capturedReq llm.CompletionRequest
	prov := &stubMockProvider{
		completeFunc: func(_ context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
			capturedReq = req
			return &llm.CompletionResponse{
				Message: llm.Message{Role: llm.RoleAssistant, Content: "ok"},
			}, nil
		},
	}
	s := newExecServer(store, func(_ llm.ProviderConfig) (llm.LLMProvider, error) {
		return prov, nil
	})

	maxReq := int32(4096)
	ctx := contextkeys.WithPerCallTokenCap(tenantCtx("tenant-cap"), 100)
	req := &tenantv1.ExecuteLLMRequest{
		ProviderName: "my-openai",
		Messages:     []*tenantv1.LLMMessageContent{{Role: "user", Content: "hello"}},
		MaxTokens:    &maxReq,
	}

	_, err := s.ExecuteLLM(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, 100, capturedReq.MaxTokens,
		"per-call cap (100) must override caller's max_tokens (4096)")
}

// TestExecuteLLM_PerCallCap_lowerCallerWins verifies that when the caller already
// set MaxTokens below the context cap, the lower caller value is preserved.
func TestExecuteLLM_PerCallCap_lowerCallerWins(t *testing.T) {
	store := &stubProviderConfigStore{
		resolveFunc: func(_ context.Context, _, _ string) (*providerconfig.DecryptedConfig, error) {
			return knownDecryptedConfig(), nil
		},
	}

	var capturedReq llm.CompletionRequest
	prov := &stubMockProvider{
		completeFunc: func(_ context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
			capturedReq = req
			return &llm.CompletionResponse{Message: llm.Message{Content: "ok"}}, nil
		},
	}
	s := newExecServer(store, func(_ llm.ProviderConfig) (llm.LLMProvider, error) {
		return prov, nil
	})

	callerMax := int32(50) // below the 500 cap
	ctx := contextkeys.WithPerCallTokenCap(tenantCtx("tenant-cap2"), 500)
	req := &tenantv1.ExecuteLLMRequest{
		ProviderName: "my-openai",
		Messages:     []*tenantv1.LLMMessageContent{{Role: "user", Content: "hello"}},
		MaxTokens:    &callerMax,
	}

	_, err := s.ExecuteLLM(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, 50, capturedReq.MaxTokens,
		"caller's lower MaxTokens (50) must be preserved; cap (500) is a ceiling")
}

// TestExecuteLLM_PerCallCap_noCapNoChange verifies that without a cap in context,
// MaxTokens is passed through exactly as the caller set it.
func TestExecuteLLM_PerCallCap_noCapNoChange(t *testing.T) {
	store := &stubProviderConfigStore{
		resolveFunc: func(_ context.Context, _, _ string) (*providerconfig.DecryptedConfig, error) {
			return knownDecryptedConfig(), nil
		},
	}

	var capturedReq llm.CompletionRequest
	prov := &stubMockProvider{
		completeFunc: func(_ context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
			capturedReq = req
			return &llm.CompletionResponse{Message: llm.Message{Content: "ok"}}, nil
		},
	}
	s := newExecServer(store, func(_ llm.ProviderConfig) (llm.LLMProvider, error) {
		return prov, nil
	})

	callerMax := int32(8192)
	ctx := tenantCtx("tenant-nocap") // no cap in context
	req := &tenantv1.ExecuteLLMRequest{
		ProviderName: "my-openai",
		Messages:     []*tenantv1.LLMMessageContent{{Role: "user", Content: "hello"}},
		MaxTokens:    &callerMax,
	}

	_, err := s.ExecuteLLM(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, 8192, capturedReq.MaxTokens,
		"no cap in context: MaxTokens must pass through unchanged")
}

