// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/modelclient"
	"github.com/zeroroot-ai/gibson/internal/platform/budget"
	"github.com/zeroroot-ai/gibson/internal/platform/modelgate"
	"github.com/zeroroot-ai/gibson/internal/platform/providerconfig"
	"github.com/zeroroot-ai/gibson/internal/platform/ratelimit"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/modelcall"
	"github.com/zeroroot-ai/sdk/auth"
)

// stubProviderConfigStore implements providerConfigStoreIface for tests.
// Only the Resolve method is exercised by the exec handlers.
type stubProviderConfigStore struct {
	resolveFunc func(ctx context.Context, tenantID, name string) (*providerconfig.DecryptedConfig, error)
	getFunc     func(ctx context.Context, tenantID, name string) (*providerconfig.ProviderConfig, error)
}

func (s *stubProviderConfigStore) List(ctx context.Context, tenantID string) ([]*providerconfig.ProviderConfig, error) {
	return nil, nil
}
func (s *stubProviderConfigStore) Get(ctx context.Context, tenantID, name string) (*providerconfig.ProviderConfig, error) {
	if s.getFunc != nil {
		return s.getFunc(ctx, tenantID, name)
	}
	return nil, providerconfig.ErrNotFound
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
func (s *stubProviderConfigStore) Resolve(ctx context.Context, tenantID, name string) (*providerconfig.DecryptedConfig, error) {
	if s.resolveFunc != nil {
		return s.resolveFunc(ctx, tenantID, name)
	}
	return nil, providerconfig.ErrNotFound
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

// tenantCtx builds a context with the given tenant wired in.
// tenantCtx is a request context of a signed-in user of tenantID. The user is
// the actor of each audit record the handlers write.
func tenantCtx(tenantID string) context.Context {
	ctx := auth.ContextWithTenantString(context.Background(), tenantID)
	return auth.WithIdentity(ctx, auth.Identity{Tenant: auth.MustNewTenantID(tenantID), Subject: "user-test"})
}

// gateStub is a modelgate.Filter with a fixed answer.
type gateStub struct {
	permit bool
	err    error
}

func (g gateStub) Permitted(_ context.Context, c []modelgate.Candidate) ([]modelgate.Candidate, error) {
	if g.err != nil {
		return nil, g.err
	}
	if g.permit {
		return c, nil
	}
	return nil, nil
}
func (gateStub) InvalidateCache() {}

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

// newExecServer builds a minimal DaemonServer with a stubbed provider store and
// factory. Callers may further customise fields (e.g. WithExecLimiter).
func newExecServer(store providerConfigStoreIface) *DaemonServer {
	s := &DaemonServer{
		logger:         slog.Default(),
		providerConfig: store,
		// The budget enforcer is required: the daemon wires it at start.
		budgetEnforcer: &stubBudgetEnforcer{},
	}
	return s
}

// fakeChatModels is the test gateway of ExecuteLLM. It records each call.
type fakeChatModels struct {
	callers []modelclient.Caller
	targets []modelclient.Target
	reqs    []modelclient.Request
	resp    *modelclient.Response
	err     error
}

func (f *fakeChatModels) Respond(
	_ context.Context, c modelclient.Caller, t modelclient.Target, r modelclient.Request,
) (*modelclient.Response, error) {
	f.callers, f.targets, f.reqs = append(f.callers, c), append(f.targets, t), append(f.reqs, r)
	if f.err != nil {
		return nil, f.err
	}
	return f.resp, nil
}

func textResponse(text string) *modelclient.Response {
	r := &modelclient.Response{Output: []modelclient.Item{{
		Type: modelclient.ItemMessage, Role: modelclient.RoleAssistant,
		Content: []modelclient.ContentPart{{Type: modelclient.PartOutputText, Text: text}},
	}}}
	r.Usage.InputTokens, r.Usage.OutputTokens, r.Usage.TotalTokens = 5, 4, 9
	return r
}

func chatStore() *stubProviderConfigStore {
	return &stubProviderConfigStore{getFunc: func(_ context.Context, _, name string) (*providerconfig.ProviderConfig, error) {
		return &providerconfig.ProviderConfig{Name: name, Type: providerconfig.ProviderOpenAI, DefaultModel: "gpt-default", Enabled: true}, nil
	}}
}

func chatServer(store providerConfigStoreIface, gw chatModels) *DaemonServer {
	s := &DaemonServer{logger: slog.Default(), providerConfig: store, budgetEnforcer: &stubBudgetEnforcer{}}
	return s.WithModelClient(gw)
}

func userChatCtx(tenant string) context.Context { return tenantCtx(tenant) }

func TestExecuteLLM_SendsOneGatewayCallAsTheUser(t *testing.T) {
	gw := &fakeChatModels{resp: textResponse("hello from LLM")}
	s := chatServer(chatStore(), gw)
	resp, err := s.ExecuteLLM(userChatCtx("tenant-a"), &tenantv1.ExecuteLLMRequest{
		ProviderName: "my-openai", Model: "gpt-4o-mini",
		Messages: []*tenantv1.LLMMessageContent{{Role: "system", Content: "be brief"}, {Role: "user", Content: "hello"}},
	})
	require.NoError(t, err)
	assert.Equal(t, "hello from LLM", resp.Content)
	assert.Equal(t, "stop", resp.FinishReason)
	assert.Equal(t, int32(9), resp.Usage.TotalTokens)

	require.Len(t, gw.targets, 1)
	assert.Equal(t, modelclient.Target{Tenant: "tenant-a", Provider: "my-openai", Model: "gpt-4o-mini"}, gw.targets[0])
	c := gw.callers[0]
	assert.Equal(t, modelcall.PurposeChat, c.Purpose)
	assert.Equal(t, "user:user-test", c.Initiator, "the user is the initiator")
	assert.Empty(t, c.Mission, "a call outside a mission has no mission")
	assert.Equal(t, defaultMaxOutputTokens, gw.reqs[0].MaxOutputTokens)
	require.Len(t, gw.reqs[0].Input, 2)
	assert.Equal(t, modelclient.RoleSystem, gw.reqs[0].Input[0].Role)
}

func TestExecuteLLM_TheProviderDefaultModelIsUsedWhenNoneIsNamed(t *testing.T) {
	gw := &fakeChatModels{resp: textResponse("ok")}
	_, err := chatServer(chatStore(), gw).ExecuteLLM(userChatCtx("t"), &tenantv1.ExecuteLLMRequest{
		ProviderName: "p", Messages: []*tenantv1.LLMMessageContent{{Role: "user", Content: "hi"}},
	})
	require.NoError(t, err)
	assert.Equal(t, "gpt-default", gw.targets[0].Model)
}

func TestExecuteLLM_AMissionCallCarriesTheMissionGrantScope(t *testing.T) {
	gw := &fakeChatModels{resp: textResponse("ok")}
	missionID := "m-1"
	_, err := chatServer(chatStore(), gw).ExecuteLLM(userChatCtx("t"), &tenantv1.ExecuteLLMRequest{
		ProviderName: "p", MissionId: &missionID, Messages: []*tenantv1.LLMMessageContent{{Role: "user", Content: "hi"}},
	})
	require.NoError(t, err)
	c := gw.callers[0]
	assert.Equal(t, "m-1", c.Mission)
	assert.NotEmpty(t, c.Task)
	assert.Equal(t, "dashboard-chat", c.Purpose)
}

func TestExecuteLLM_ToolsAndToolCalls(t *testing.T) {
	resp := &modelclient.Response{Output: []modelclient.Item{
		{Type: modelclient.ItemFunctionCall, CallID: "c1", Name: "nmap", Arguments: `{"host":"a"}`},
	}}
	gw := &fakeChatModels{resp: resp}
	out, err := chatServer(chatStore(), gw).ExecuteLLM(userChatCtx("t"), &tenantv1.ExecuteLLMRequest{
		ProviderName: "p",
		Messages: []*tenantv1.LLMMessageContent{
			{Role: "user", Content: "scan"},
			{Role: "assistant", ToolCalls: []*tenantv1.LLMToolCall{{Id: "c0", Name: "ping", Arguments: "{}"}}},
			{Role: "tool", ToolResults: []*tenantv1.LLMToolResult{{ToolCallId: "c0", Content: "pong"}}},
		},
		Tools: []*tenantv1.LLMToolDef{{Name: "nmap", Description: "scan", ParametersJson: `{"type":"object"}`}},
	})
	require.NoError(t, err)
	require.Len(t, out.ToolCalls, 1)
	assert.Equal(t, "nmap", out.ToolCalls[0].Name)
	assert.Equal(t, "c1", out.ToolCalls[0].Id)
	assert.Equal(t, "tool_calls", out.FinishReason)
	req := gw.reqs[0]
	require.Len(t, req.Tools, 1)
	var kinds []string
	for _, it := range req.Input {
		kinds = append(kinds, it.Type)
	}
	assert.Equal(t, []string{"message", "function_call", "function_call_output"}, kinds)
}

func TestExecuteLLM_StructuredOutput(t *testing.T) {
	gw := &fakeChatModels{resp: textResponse(`{"ok":true}`)}
	_, err := chatServer(chatStore(), gw).ExecuteLLM(userChatCtx("t"), &tenantv1.ExecuteLLMRequest{
		ProviderName: "p", Messages: []*tenantv1.LLMMessageContent{{Role: "user", Content: "hi"}},
		ResponseFormat: &tenantv1.ResponseFormat{Type: "json_schema", Name: "a", SchemaJson: `{"type":"object"}`, Strict: true},
	})
	require.NoError(t, err)
	require.NotNil(t, gw.reqs[0].Text)
	assert.Equal(t, "json_schema", gw.reqs[0].Text.Format.Type)
	assert.True(t, gw.reqs[0].Text.Format.Strict)

	_, err = chatServer(chatStore(), gw).ExecuteLLM(userChatCtx("t"), &tenantv1.ExecuteLLMRequest{
		ProviderName: "p", Messages: []*tenantv1.LLMMessageContent{{Role: "user", Content: "hi"}},
		ResponseFormat: &tenantv1.ResponseFormat{Type: "json_schema", SchemaJson: "{not json"},
	})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
}

func TestExecuteLLM_GatewayErrorsMapToStatuses(t *testing.T) {
	cases := map[int]codes.Code{
		http.StatusForbidden:       codes.PermissionDenied,
		http.StatusUnauthorized:    codes.PermissionDenied,
		http.StatusNotFound:        codes.Unavailable,
		http.StatusTooManyRequests: codes.ResourceExhausted,
		http.StatusBadGateway:      codes.Internal,
	}
	for status, want := range cases {
		gw := &fakeChatModels{err: &modelclient.APIError{Status: status, Body: "x-secret-header-leak"}}
		_, err := chatServer(chatStore(), gw).ExecuteLLM(userChatCtx("t"), &tenantv1.ExecuteLLMRequest{
			ProviderName: "p", Messages: []*tenantv1.LLMMessageContent{{Role: "user", Content: "hi"}},
		})
		assert.Equal(t, want, grpcCode(err), "status %d", status)
		assert.NotContains(t, err.Error(), "x-secret-header-leak", "the gateway body is not forwarded")
	}
}

func TestExecuteLLM_Refusals(t *testing.T) {
	gw := &fakeChatModels{resp: textResponse("ok")}
	// No provider store.
	s := chatServer(nil, gw)
	s.providerConfig = nil
	_, err := s.ExecuteLLM(userChatCtx("t"), &tenantv1.ExecuteLLMRequest{ProviderName: "p"})
	assert.Equal(t, codes.FailedPrecondition, grpcCode(err))
	// No model client.
	s2 := &DaemonServer{logger: slog.Default(), providerConfig: chatStore(), budgetEnforcer: &stubBudgetEnforcer{}}
	_, err = s2.ExecuteLLM(userChatCtx("t"), &tenantv1.ExecuteLLMRequest{ProviderName: "p"})
	assert.Equal(t, codes.FailedPrecondition, grpcCode(err))
	// Unknown provider.
	_, err = chatServer(&stubProviderConfigStore{}, gw).ExecuteLLM(userChatCtx("t"), &tenantv1.ExecuteLLMRequest{ProviderName: "x"})
	assert.Equal(t, codes.NotFound, grpcCode(err))
	// No tenant.
	_, err = chatServer(chatStore(), gw).ExecuteLLM(context.Background(), &tenantv1.ExecuteLLMRequest{ProviderName: "p"})
	assert.Equal(t, codes.Unauthenticated, grpcCode(err))
	// No model anywhere.
	noModel := &stubProviderConfigStore{getFunc: func(context.Context, string, string) (*providerconfig.ProviderConfig, error) {
		return &providerconfig.ProviderConfig{Name: "p"}, nil
	}}
	_, err = chatServer(noModel, gw).ExecuteLLM(userChatCtx("t"), &tenantv1.ExecuteLLMRequest{ProviderName: "p"})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
	assert.Empty(t, gw.targets, "no refused call reached the gateway")
}

func TestExecuteLLM_RateLimitEnforced(t *testing.T) {
	gw := &fakeChatModels{resp: textResponse("ok")}
	s := chatServer(chatStore(), gw).WithExecLimiter(&stubExecLimiter{blockAt: 1})
	_, err := s.ExecuteLLM(userChatCtx("t"), &tenantv1.ExecuteLLMRequest{ProviderName: "p"})
	assert.Equal(t, codes.ResourceExhausted, grpcCode(err))
	assert.Empty(t, gw.targets)
}

func TestExecuteLLM_BudgetExhaustedBlocked(t *testing.T) {
	gw := &fakeChatModels{resp: textResponse("ok")}
	s := chatServer(chatStore(), gw)
	s.budgetEnforcer = &stubBudgetEnforcer{checkErr: errors.New("budget exceeded")}
	_, err := s.ExecuteLLM(userChatCtx("t"), &tenantv1.ExecuteLLMRequest{ProviderName: "p"})
	require.Error(t, err)
	assert.Equal(t, codes.ResourceExhausted, grpcCode(err))
	assert.Empty(t, gw.targets)
}

// The handler records no token count of its own: the gateway trace is the one
// source (gibson#1390).
func TestExecuteLLM_RecordsNoTokensOfItsOwn(t *testing.T) {
	be := &stubBudgetEnforcer{}
	gw := &fakeChatModels{resp: textResponse("ok")}
	s := chatServer(chatStore(), gw)
	s.budgetEnforcer = be
	_, err := s.ExecuteLLM(userChatCtx("t"), &tenantv1.ExecuteLLMRequest{
		ProviderName: "p", Messages: []*tenantv1.LLMMessageContent{{Role: "user", Content: "hi"}}})
	require.NoError(t, err)
	assert.Zero(t, be.recordCalls)
}

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

	require.Len(t, msgs, 2, "each tool result becomes a separate message")
	assert.Equal(t, roleTool, msgs[0].Role)
	assert.Equal(t, "call-1", msgs[0].ToolCallID)
	assert.Equal(t, "result-A", msgs[0].Content)
	assert.Equal(t, roleTool, msgs[1].Role)
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

func TestErrRateLimited_IsSentinel(t *testing.T) {
	wrapped := errors.Join(errors.New("outer"), ratelimit.ErrRateLimited)
	assert.True(t, errors.Is(wrapped, ratelimit.ErrRateLimited))
}

// A call with no identity, or with an empty subject, has no initiator. The
// call fails and never runs as an empty or privileged person.
func TestCallerInitiator_FailsClosed(t *testing.T) {
	for name, ctx := range map[string]context.Context{
		"no identity":   context.Background(),
		"empty subject": auth.WithIdentity(context.Background(), auth.Identity{}),
	} {
		t.Run(name, func(t *testing.T) {
			got, err := callerInitiator(ctx)
			require.Error(t, err)
			assert.Empty(t, got)
			assert.Equal(t, codes.Unauthenticated, status.Code(err))
		})
	}
	got, err := callerInitiator(auth.WithIdentity(context.Background(), auth.Identity{Subject: "user:alice"}))
	require.NoError(t, err)
	assert.Equal(t, "user:alice", got)
}
