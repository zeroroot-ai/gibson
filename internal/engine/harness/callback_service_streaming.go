// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"fmt"
	"time"

	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
)

// CallToolProtoStream implements the streaming tool execution RPC.
//
// A tool has two dispatch paths, the sandbox and the work queue (ADR-0110),
// and neither streams partial results. So this handler hands the call to the
// unary handler and sends its outcome as the one terminal event of the
// stream. The unary handler owns the whole call: the mission deny list, the
// execute gate, the dispatch, the discovery ingest and the flight recorder
// record. No path opens a connection to an address that a tool reports.
func (s *HarnessCallbackService) CallToolProtoStream(req *harnesspb.CallToolProtoStreamRequest, stream harnesspb.HarnessCallbackService_CallToolProtoStreamServer) error {
	ctx := stream.Context()

	resp, err := s.CallToolProto(ctx, &harnesspb.CallToolProtoRequest{
		Context:    req.GetContext(),
		Name:       req.GetName(),
		InputType:  req.GetInputType(),
		InputJson:  req.GetInputJson(),
		OutputType: req.GetOutputType(),
	})
	if err != nil {
		return err
	}

	// The unary handler above recorded the call, or refused it before any
	// dispatch. This handler only changes the shape of that outcome.
	var event *harnesspb.CallToolProtoStreamResponse
	if herr := resp.GetError(); herr != nil {
		event = &harnesspb.CallToolProtoStreamResponse{
			Payload: &harnesspb.CallToolProtoStreamResponse_Error{
				Error: &harnesspb.ToolErrorEvent{
					Error: &harnesspb.HarnessError{Code: herr.GetCode(), Message: herr.GetMessage()},
					Fatal: true,
				},
			},
		}
	} else {
		event = &harnesspb.CallToolProtoStreamResponse{
			Payload: &harnesspb.CallToolProtoStreamResponse_Complete{
				Complete: &harnesspb.ToolCompleteEvent{OutputJson: resp.GetOutputJson()},
			},
		}
	}
	event.TraceId = req.GetContext().GetTraceId()
	event.SpanId = req.GetContext().GetSpanId()
	event.Sequence = 1
	event.TimestampMs = time.Now().UnixMilli()
	if sendErr := stream.Send(event); sendErr != nil {
		s.logger.Error("failed to send the terminal tool event", "error", sendErr, "tool", req.GetName())
		return fmt.Errorf("send the terminal tool event: %w", sendErr)
	}
	return nil
}
