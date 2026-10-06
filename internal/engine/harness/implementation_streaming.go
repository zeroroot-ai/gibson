// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package harness — DefaultAgentHarness streaming-tool dispatch.
//
// CallToolProtoStream is the streaming counterpart to CallToolProto. It
// resolves the tool the same way as CallToolProto, then opens the tool's
// gRPC StreamExecute bidi stream and translates each ToolStreamResponse
// payload variant into the matching SDK ToolStreamCallback invocation.
//
// Spec: headline-feature-completion R1.
package harness

import (
	"context"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"google.golang.org/protobuf/proto"

	sdkagent "github.com/zeroroot-ai/sdk/agent"
)

// CallToolProtoStream invokes a tool and reports its result through the
// stream callback.
//
// A tool has two dispatch paths, the sandbox and the work queue (ADR-0110),
// and neither streams partial results. So a streamed call takes the same
// dispatch as CallToolProto and then delivers the complete output as one
// final partial. No path opens a connection to an address that a tool
// reports.
func (h *DefaultAgentHarness) CallToolProtoStream(
	ctx context.Context,
	name string,
	request proto.Message,
	response proto.Message,
	callback sdkagent.ToolStreamCallback,
) error {
	ctx, span := h.tracer.Start(ctx, "harness.CallToolProtoStream")
	defer span.End()

	if request == nil || response == nil {
		return types.WrapError(
			ErrHarnessToolExecutionFailed,
			fmt.Sprintf("CallToolProtoStream: nil request or response for tool %s", name),
			nil,
		)
	}

	// CallToolProto makes the execute gate decision and the dispatch gate
	// decision. A streamed call is another road to the same tool.
	if err := h.CallToolProto(ctx, name, request, response); err != nil {
		if callback != nil {
			callback.OnError(err, true)
		}
		return err
	}
	if callback != nil {
		callback.OnPartial(response, false)
	}
	return nil
}
