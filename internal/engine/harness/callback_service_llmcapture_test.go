package harness

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"github.com/zeroroot-ai/sdk/auth"
	"google.golang.org/grpc"
)

// completingMockHarness returns a canned successful completion so the LLM
// callback handlers can be exercised end-to-end through getHarness. It embeds
// tenantAwareMockHarness for the tenant-isolation check + all the other
// AgentHarness stubs.
type completingMockHarness struct {
	tenantAwareMockHarness
	resp *llm.CompletionResponse
}

func (m *completingMockHarness) Complete(_ context.Context, _ string, _ []llm.Message, _ ...CompletionOption) (*llm.CompletionResponse, error) {
	return m.resp, nil
}

func (m *completingMockHarness) CompleteWithTools(_ context.Context, _ string, _ []llm.Message, _ []llm.ToolDef, _ ...CompletionOption) (*llm.CompletionResponse, error) {
	return m.resp, nil
}

// Stream emulates a provider stream: two content deltas followed by a terminal
// chunk carrying aggregated usage + model (gibson#1085), mirroring streamToChannel.
func (m *completingMockHarness) Stream(_ context.Context, _ string, _ []llm.Message, _ ...CompletionOption) (<-chan llm.StreamChunk, error) {
	ch := make(chan llm.StreamChunk, 4)
	go func() {
		defer close(ch)
		ch <- llm.StreamChunk{Delta: llm.StreamDelta{Content: "hello "}}
		ch <- llm.StreamChunk{Delta: llm.StreamDelta{Content: "back"}}
		ch <- llm.StreamChunk{
			FinishReason: llm.FinishReasonStop,
			Model:        m.resp.Model,
			Usage: &llm.CompletionTokenUsage{
				PromptTokens:     m.resp.Usage.PromptTokens,
				CompletionTokens: m.resp.Usage.CompletionTokens,
				TotalTokens:      m.resp.Usage.TotalTokens,
			},
		}
	}()
	return ch, nil
}

// CompleteStructuredAnyWithUsage emulates the Decider's structured path: a parsed
// result plus surfaced token usage (gibson#1085).
func (m *completingMockHarness) CompleteStructuredAnyWithUsage(_ context.Context, _ string, _ []llm.Message, _ any, _ ...CompletionOption) (*StructuredCompletionResult, error) {
	return &StructuredCompletionResult{
		Result:           map[string]any{"decision": "advance"},
		Model:            m.resp.Model,
		RawJSON:          `{"decision":"advance"}`,
		PromptTokens:     13,
		CompletionTokens: 5,
		TotalTokens:      18,
	}, nil
}

// erroringStreamHarness fails mid-stream so the success-only capture rule can be
// asserted: a failed/aborted stream must not be folded into the mission frame.
type erroringStreamHarness struct {
	completingMockHarness
}

func (m *erroringStreamHarness) Stream(_ context.Context, _ string, _ []llm.Message, _ ...CompletionOption) (<-chan llm.StreamChunk, error) {
	ch := make(chan llm.StreamChunk, 2)
	go func() {
		defer close(ch)
		ch <- llm.StreamChunk{Delta: llm.StreamDelta{Content: "partial"}}
		ch <- llm.StreamChunk{Error: errors.New("boom")}
	}()
	return ch, nil
}

// fakeLLMStreamServer is a minimal HarnessCallbackService_LLMStreamServer that
// records the chunks the handler sends.
type fakeLLMStreamServer struct {
	grpc.ServerStream
	ctx  context.Context
	sent []*harnesspb.LLMStreamResponse
}

func (f *fakeLLMStreamServer) Context() context.Context { return f.ctx }
func (f *fakeLLMStreamServer) Send(r *harnesspb.LLMStreamResponse) error {
	f.sent = append(f.sent, r)
	return nil
}

func newCompletingHarness(tenant string) *completingMockHarness {
	h := &completingMockHarness{
		resp: &llm.CompletionResponse{
			Model:        "claude-haiku-4-5",
			Message:      llm.Message{Role: llm.RoleAssistant, Content: "hello back"},
			FinishReason: llm.FinishReasonStop,
			Usage:        llm.CompletionTokenUsage{PromptTokens: 11, CompletionTokens: 7, TotalTokens: 18},
		},
	}
	h.tenantID = tenant
	return h
}

// capturedCall records what the wired sink received.
type capturedCall struct {
	tenant string
	call   LLMCallRecord
}

func newCaptureService(t *testing.T, tenant string, captured *[]capturedCall) *HarnessCallbackService {
	t.Helper()
	registry := NewCallbackHarnessRegistry()
	registry.Register("mission-A", "recon-agent", newCompletingHarness(tenant))
	return NewHarnessCallbackServiceWithRegistry(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		registry,
		WithLLMCallSink(func(_ context.Context, tn string, call LLMCallRecord) {
			*captured = append(*captured, capturedCall{tenant: tn, call: call})
		}),
	)
}

// TestLLMComplete_FeedsLLMCallSink_WithMissionContext is the gibson#1083 unit:
// a mission/agent LLM call via the callback path surfaces as an LlmCallObserved
// record stamped with mission_id + run_id + model + token counts, routed to the
// mission's tenant.
func TestLLMComplete_FeedsLLMCallSink_WithMissionContext(t *testing.T) {
	var captured []capturedCall
	svc := newCaptureService(t, "acme", &captured)

	ctx := auth.ContextWithTenantString(context.Background(), "acme")
	resp, err := svc.LLMComplete(ctx, &harnesspb.LLMCompleteRequest{
		Context: &harnesspb.ContextInfo{
			MissionId:    "mission-A",
			MissionRunId: "run-1",
			AgentName:    "recon-agent",
		},
		Slot:     "default",
		Messages: []*harnesspb.LLMMessage{{Role: "user", Content: "hello"}},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Nil(t, resp.Error)

	require.Len(t, captured, 1, "exactly one LlmCall should be captured (no double-capture)")
	got := captured[0]
	assert.Equal(t, "acme", got.tenant)
	assert.Equal(t, "mission-A", got.call.MissionID, "mission context must be stamped")
	assert.Equal(t, "run-1", got.call.RunID)
	assert.Equal(t, "claude-haiku-4-5", got.call.Model)
	assert.Equal(t, 11, got.call.PromptTokens)
	assert.Equal(t, 7, got.call.CompletionTokens)
	assert.NotEmpty(t, got.call.CallID, "each call gets a stable World identity")
	assert.Equal(t, "hello back", got.call.Completion)
	require.Len(t, got.call.Messages, 1)
	assert.Equal(t, "user", got.call.Messages[0].Role)
}

// TestLLMCompleteWithTools_FeedsLLMCallSink ensures the tool-calling completion
// path is captured too, with the same mission stamping.
func TestLLMCompleteWithTools_FeedsLLMCallSink(t *testing.T) {
	var captured []capturedCall
	svc := newCaptureService(t, "acme", &captured)

	ctx := auth.ContextWithTenantString(context.Background(), "acme")
	resp, err := svc.LLMCompleteWithTools(ctx, &harnesspb.LLMCompleteWithToolsRequest{
		Context: &harnesspb.ContextInfo{
			MissionId:  "mission-A",
			AgentRunId: "agent-run-9",
			AgentName:  "recon-agent",
		},
		Slot:     "default",
		Messages: []*harnesspb.LLMMessage{{Role: "user", Content: "scan"}},
	})
	require.NoError(t, err)
	require.Nil(t, resp.Error)

	require.Len(t, captured, 1)
	assert.Equal(t, "mission-A", captured[0].call.MissionID)
	// RunID falls back to agent_run_id when mission_run_id is unset.
	assert.Equal(t, "agent-run-9", captured[0].call.RunID)
	assert.Equal(t, 11, captured[0].call.PromptTokens)
}

// TestLLMStream_FeedsLLMCallSink_WithAggregatedUsage is the gibson#1085 unit for
// the streaming path: a mission/agent streaming completion surfaces as a single
// LlmCallObserved record, with the text deltas aggregated into the transcript and
// the token usage read off the terminal chunk. Success-only, no double-capture.
func TestLLMStream_FeedsLLMCallSink_WithAggregatedUsage(t *testing.T) {
	var captured []capturedCall
	svc := newCaptureService(t, "acme", &captured)

	ctx := auth.ContextWithTenantString(context.Background(), "acme")
	srv := &fakeLLMStreamServer{ctx: ctx}
	err := svc.LLMStream(&harnesspb.LLMStreamRequest{
		Context: &harnesspb.ContextInfo{
			MissionId:    "mission-A",
			MissionRunId: "run-7",
			AgentName:    "recon-agent",
		},
		Slot:     "default",
		Messages: []*harnesspb.LLMMessage{{Role: "user", Content: "hello"}},
	}, srv)
	require.NoError(t, err)

	require.Len(t, captured, 1, "exactly one LlmCall should be captured (no double-capture)")
	got := captured[0]
	assert.Equal(t, "acme", got.tenant)
	assert.Equal(t, "mission-A", got.call.MissionID, "mission context must be stamped")
	assert.Equal(t, "run-7", got.call.RunID)
	assert.Equal(t, "claude-haiku-4-5", got.call.Model, "model read off terminal chunk")
	assert.Equal(t, 11, got.call.PromptTokens, "usage aggregated at stream end")
	assert.Equal(t, 7, got.call.CompletionTokens)
	assert.NotEmpty(t, got.call.CallID)
	assert.Equal(t, "hello back", got.call.Completion, "text deltas aggregated into transcript")
	require.Len(t, got.call.Messages, 1)
	assert.Equal(t, "user", got.call.Messages[0].Role)

	// The terminal usage also rides on the wire chunk for the agent.
	var sawWireUsage bool
	for _, c := range srv.sent {
		if c.Usage != nil {
			sawWireUsage = true
			assert.Equal(t, int32(11), c.Usage.InputTokens)
			assert.Equal(t, int32(7), c.Usage.OutputTokens)
		}
	}
	assert.True(t, sawWireUsage, "terminal usage should be forwarded on the stream")
}

// TestLLMStream_ErrorMidStream_NoCapture proves the success-only rule: an aborted
// stream is not folded into the mission frame.
func TestLLMStream_ErrorMidStream_NoCapture(t *testing.T) {
	var captured []capturedCall
	registry := NewCallbackHarnessRegistry()
	h := &erroringStreamHarness{}
	h.resp = &llm.CompletionResponse{Model: "claude-haiku-4-5"}
	h.tenantID = "acme"
	registry.Register("mission-A", "recon-agent", h)
	svc := NewHarnessCallbackServiceWithRegistry(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		registry,
		WithLLMCallSink(func(_ context.Context, tn string, call LLMCallRecord) {
			captured = append(captured, capturedCall{tenant: tn, call: call})
		}),
	)

	ctx := auth.ContextWithTenantString(context.Background(), "acme")
	srv := &fakeLLMStreamServer{ctx: ctx}
	err := svc.LLMStream(&harnesspb.LLMStreamRequest{
		Context:  &harnesspb.ContextInfo{MissionId: "mission-A", AgentName: "recon-agent"},
		Slot:     "default",
		Messages: []*harnesspb.LLMMessage{{Role: "user", Content: "hello"}},
	}, srv)
	require.NoError(t, err)
	assert.Empty(t, captured, "a failed/aborted stream must not be captured")
}

// TestLLMCompleteStructured_FeedsLLMCallSink_Decider is the gibson#1085 unit for
// the structured path — the path the brain Decider uses. The structured
// completion (with surfaced usage) folds into the mission frame as an
// LlmCallObserved, and the usage is also returned on the wire.
func TestLLMCompleteStructured_FeedsLLMCallSink_Decider(t *testing.T) {
	var captured []capturedCall
	svc := newCaptureService(t, "acme", &captured)

	ctx := auth.ContextWithTenantString(context.Background(), "acme")
	resp, err := svc.LLMCompleteStructured(ctx, &harnesspb.LLMCompleteStructuredRequest{
		Context: &harnesspb.ContextInfo{
			MissionId:    "mission-A",
			MissionRunId: "run-decider",
			AgentName:    "recon-agent",
		},
		Slot:       "default",
		Messages:   []*harnesspb.LLMMessage{{Role: "user", Content: "decide"}},
		SchemaJson: `{"type":"object"}`,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Nil(t, resp.Error)

	require.Len(t, captured, 1, "exactly one LlmCall should be captured (no double-capture)")
	got := captured[0]
	assert.Equal(t, "acme", got.tenant)
	assert.Equal(t, "mission-A", got.call.MissionID)
	assert.Equal(t, "run-decider", got.call.RunID)
	assert.Equal(t, "claude-haiku-4-5", got.call.Model)
	assert.Equal(t, 13, got.call.PromptTokens, "structured usage surfaced + captured")
	assert.Equal(t, 5, got.call.CompletionTokens)
	assert.Equal(t, `{"decision":"advance"}`, got.call.Completion)

	// Usage is also surfaced back to the caller on the wire.
	require.NotNil(t, resp.Usage)
	assert.Equal(t, int32(13), resp.Usage.InputTokens)
	assert.Equal(t, int32(5), resp.Usage.OutputTokens)
	assert.Equal(t, int32(18), resp.Usage.TotalTokens)
}

// TestLLMComplete_NoSink_NoPanic ensures capture is a clean no-op when the sink
// is unwired (chat-only / capture-disabled deployments).
func TestLLMComplete_NoSink_NoPanic(t *testing.T) {
	registry := NewCallbackHarnessRegistry()
	registry.Register("mission-A", "recon-agent", newCompletingHarness("acme"))
	svc := NewHarnessCallbackServiceWithRegistry(slog.New(slog.NewTextHandler(io.Discard, nil)), registry)

	ctx := auth.ContextWithTenantString(context.Background(), "acme")
	resp, err := svc.LLMComplete(ctx, &harnesspb.LLMCompleteRequest{
		Context:  &harnesspb.ContextInfo{MissionId: "mission-A", AgentName: "recon-agent"},
		Slot:     "default",
		Messages: []*harnesspb.LLMMessage{{Role: "user", Content: "hi"}},
	})
	require.NoError(t, err)
	require.Nil(t, resp.Error)
}
