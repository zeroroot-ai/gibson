package harness

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"github.com/zeroroot-ai/sdk/auth"
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
