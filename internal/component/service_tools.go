package component

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zero-day-ai/sdk/auth"
	componentpb "github.com/zero-day-ai/sdk/api/gen/gibson/component/v1"
)

// ToolExecutor dispatches tool execution for streaming and queued operations.
// May be nil; tool streaming and queue RPCs return Unimplemented when nil.
type ToolExecutor interface {
	// ExecuteTool runs a tool and returns the result JSON.
	ExecuteTool(ctx context.Context, tenant, toolName, inputJSON string) (outputJSON string, err error)
}

// CallToolStream proxies a tool execution with server-side streaming of events.
func (s *ComponentServiceServer) CallToolStream(
	req *componentpb.CallToolStreamRequest,
	stream componentpb.ComponentService_CallToolStreamServer,
) error {
	ctx := stream.Context()
	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" {
		return status.Error(codes.Unauthenticated, "tenant not found in context")
	}
	if s.toolExecutor == nil {
		return status.Error(codes.Unimplemented, "tool streaming not configured")
	}

	// Send a progress event indicating execution started.
	if err := stream.Send(&componentpb.CallToolStreamResponse{
		EventType:   "progress",
		PayloadJson: `{"status":"executing"}`,
	}); err != nil {
		return err
	}

	// Execute the tool synchronously and send the result as the final event.
	outputJSON, err := s.toolExecutor.ExecuteTool(ctx, tenant, req.GetToolName(), req.GetInputJson())
	if err != nil {
		return stream.Send(&componentpb.CallToolStreamResponse{
			EventType: "error",
			Done:      true,
			Error: &componentpb.ComponentError{
				Code:    "TOOL_EXECUTION_FAILED",
				Message: err.Error(),
			},
		})
	}

	return stream.Send(&componentpb.CallToolStreamResponse{
		EventType:   "result",
		PayloadJson: outputJSON,
		Done:        true,
	})
}

// QueueToolWork submits a batch of tool invocations for parallel execution.
func (s *ComponentServiceServer) QueueToolWork(
	ctx context.Context,
	req *componentpb.QueueToolWorkRequest,
) (*componentpb.QueueToolWorkResponse, error) {
	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "tenant not found in context")
	}
	if s.toolExecutor == nil {
		return nil, status.Error(codes.Unimplemented, "tool queue not configured")
	}

	jobID := uuid.New().String()

	// Store the job for later retrieval by ToolResults.
	job := &toolJob{
		id:       jobID,
		tenant:   tenant,
		toolName: req.GetToolName(),
		inputs:   req.GetInputsJson(),
		results:  make(chan toolJobResult, len(req.GetInputsJson())),
	}

	s.toolJobsMu.Lock()
	if s.toolJobs == nil {
		s.toolJobs = make(map[string]*toolJob)
	}
	s.toolJobs[jobID] = job
	s.toolJobsMu.Unlock()

	// Launch parallel tool executions.
	go func() {
		var wg sync.WaitGroup
		for i, inputJSON := range job.inputs {
			wg.Add(1)
			go func(idx int, input string) {
				defer wg.Done()
				output, err := s.toolExecutor.ExecuteTool(context.Background(), tenant, job.toolName, input)
				var compErr *componentpb.ComponentError
				if err != nil {
					compErr = &componentpb.ComponentError{
						Code:    "TOOL_EXECUTION_FAILED",
						Message: err.Error(),
					}
				}
				job.results <- toolJobResult{index: int32(idx), outputJSON: output, err: compErr}
			}(i, inputJSON)
		}
		wg.Wait()
		close(job.results)
	}()

	return &componentpb.QueueToolWorkResponse{JobId: jobID}, nil
}

// ToolResults streams results for a previously queued tool batch.
func (s *ComponentServiceServer) ToolResults(
	req *componentpb.ToolResultsRequest,
	stream componentpb.ComponentService_ToolResultsServer,
) error {
	ctx := stream.Context()
	_ = auth.TenantStringFromContext(ctx)

	s.toolJobsMu.Lock()
	job, ok := s.toolJobs[req.GetJobId()]
	s.toolJobsMu.Unlock()

	if !ok {
		return status.Errorf(codes.NotFound, "job %s not found", req.GetJobId())
	}

	total := len(job.inputs)
	sent := 0

	for result := range job.results {
		sent++
		if err := stream.Send(&componentpb.ToolResultsResponse{
			Index:      result.index,
			OutputJson: result.outputJSON,
			Error:      result.err,
			Done:       sent >= total,
		}); err != nil {
			return err
		}
	}

	// Clean up the job.
	s.toolJobsMu.Lock()
	delete(s.toolJobs, req.GetJobId())
	s.toolJobsMu.Unlock()

	return nil
}

// toolJob tracks a queued batch of tool executions.
type toolJob struct {
	id       string
	tenant   string
	toolName string
	inputs   []string
	results  chan toolJobResult
}

// toolJobResult is a single result from a queued tool execution.
type toolJobResult struct {
	index      int32
	outputJSON string
	err        *componentpb.ComponentError
}

// formatToolError creates a ComponentError from a Go error.
func formatToolError(err error) *componentpb.ComponentError {
	if err == nil {
		return nil
	}
	return &componentpb.ComponentError{
		Code:    "TOOL_EXECUTION_FAILED",
		Message: fmt.Sprintf("%v", err),
	}
}

// marshalToolResult marshals a tool result for streaming.
func marshalToolResult(result any) string {
	data, err := json.Marshal(result)
	if err != nil {
		return "{}"
	}
	return string(data)
}
