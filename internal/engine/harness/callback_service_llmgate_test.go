// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/engine/llm/modelgate"
	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// failingLLMHarness fails every LLM call with err. With midStream set, Stream
// starts and then fails in a chunk.
type failingLLMHarness struct {
	completingMockHarness
	err       error
	midStream bool
}

func (m *failingLLMHarness) Complete(context.Context, string, []llm.Message, ...CompletionOption) (*llm.CompletionResponse, error) {
	return nil, m.err
}

func (m *failingLLMHarness) CompleteWithTools(
	context.Context, string, []llm.Message, []llm.ToolDef, ...CompletionOption,
) (*llm.CompletionResponse, error) {
	return nil, m.err
}

func (m *failingLLMHarness) Stream(context.Context, string, []llm.Message, ...CompletionOption) (<-chan llm.StreamChunk, error) {
	if !m.midStream {
		return nil, m.err
	}
	ch := make(chan llm.StreamChunk, 1)
	ch <- llm.StreamChunk{Error: m.err}
	close(ch)
	return ch, nil
}

func (m *failingLLMHarness) CompleteStructuredAnyWithUsage(
	context.Context, string, []llm.Message, any, ...CompletionOption,
) (*StructuredCompletionResult, error) {
	return nil, m.err
}

// A model gate denial reaches a sandboxed agent as permission denied. A gate
// that could not decide reaches it as unavailable. Other errors stay internal
// (gibson#1221). Each of the five LLM RPCs answers the same way.
func TestLLMRPCs_ModelGateCodes(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode commonpb.ErrorCode
		wantGRPC codes.Code
	}{
		{"denied", fmt.Errorf("model_access_denied: %w", modelgate.ErrDenied),
			commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED, codes.PermissionDenied},
		{"undecided", fmt.Errorf("model_access_denied: %w", modelgate.ErrUnavailable),
			commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE, codes.Unavailable},
		{"other", errors.New("the provider broke"),
			commonpb.ErrorCode_ERROR_CODE_INTERNAL, codes.Internal},
	}
	msgs := []*harnesspb.LLMMessage{{Role: "user", Content: "hello"}}
	info := &harnesspb.ContextInfo{MissionId: "mission-A", AgentName: "recon-agent"}

	for _, tc := range cases {
		for _, midStream := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/midStream=%v", tc.name, midStream), func(t *testing.T) {
				h := &failingLLMHarness{err: tc.err, midStream: midStream}
				h.tenantID = "acme"
				registry := NewCallbackHarnessRegistry()
				mustRegister(t, registry, "mission-A", "recon-agent", h)
				svc := NewHarnessCallbackServiceWithRegistry(
					slog.New(slog.NewTextHandler(io.Discard, nil)), registry, testEventBus())
				ctx := auth.ContextWithTenantString(context.Background(), "acme")

				c, err := svc.LLMComplete(ctx, &harnesspb.LLMCompleteRequest{Context: info, Slot: "default", Messages: msgs})
				require.NoError(t, err)
				assert.Equal(t, tc.wantCode, c.GetError().GetCode(), "LLMComplete")

				w, err := svc.LLMCompleteWithTools(ctx, &harnesspb.LLMCompleteWithToolsRequest{
					Context: info, Slot: "default", Messages: msgs})
				require.NoError(t, err)
				assert.Equal(t, tc.wantCode, w.GetError().GetCode(), "LLMCompleteWithTools")

				st, err := svc.LLMCompleteStructured(ctx, &harnesspb.LLMCompleteStructuredRequest{
					Context: info, Slot: "default", Messages: msgs, SchemaJson: `{"type":"object"}`})
				require.NoError(t, err)
				assert.Equal(t, tc.wantCode, st.GetError().GetCode(), "LLMCompleteStructured")

				srv := &fakeLLMStreamServer{ctx: ctx}
				err = svc.LLMStream(&harnesspb.LLMStreamRequest{Context: info, Slot: "default", Messages: msgs}, srv)
				if midStream {
					require.NoError(t, err)
					require.Len(t, srv.sent, 1)
					assert.Equal(t, tc.wantCode, srv.sent[0].GetError().GetCode(), "LLMStream chunk")
				} else {
					assert.Equal(t, tc.wantGRPC, status.Code(err), "LLMStream")
				}
			})
		}
	}
}
