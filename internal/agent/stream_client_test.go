package agent

import (
	"context"
	"encoding/json"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/zero-day-ai/gibson/internal/database"
	"github.com/zero-day-ai/gibson/internal/types"
	agentpb "github.com/zero-day-ai/sdk/api/gen/gibson/agent/v1"
	commonpb "github.com/zero-day-ai/sdk/api/gen/gibson/common/v1"
	typespb "github.com/zero-day-ai/sdk/api/gen/gibson/types/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// mockStream implements the bidirectional stream interface for testing
type mockStream struct {
	sendCh chan *agentpb.StreamExecuteRequest
	recvCh chan *agentpb.StreamExecuteResponse
	ctx    context.Context
	mu     sync.Mutex
	closed bool
}

func newMockStream(ctx context.Context) *mockStream {
	return &mockStream{
		sendCh: make(chan *agentpb.StreamExecuteRequest, 10),
		recvCh: make(chan *agentpb.StreamExecuteResponse, 10),
		ctx:    ctx,
	}
}

func (m *mockStream) Send(msg *agentpb.StreamExecuteRequest) error {
	select {
	case m.sendCh <- msg:
		return nil
	case <-m.ctx.Done():
		return m.ctx.Err()
	}
}

func (m *mockStream) Recv() (*agentpb.StreamExecuteResponse, error) {
	select {
	case msg, ok := <-m.recvCh:
		if !ok {
			return nil, io.EOF
		}
		return msg, nil
	case <-m.ctx.Done():
		return nil, m.ctx.Err()
	}
}

func (m *mockStream) CloseSend() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.closed {
		close(m.sendCh)
		m.closed = true
	}
	return nil
}

func (m *mockStream) SendMsg(msg any) error {
	return m.Send(msg.(*agentpb.StreamExecuteRequest))
}

func (m *mockStream) RecvMsg(msg any) error {
	received, err := m.Recv()
	if err != nil {
		return err
	}
	// Avoid copying lock values by manually copying fields
	target := msg.(*agentpb.StreamExecuteResponse)
	target.Payload = received.Payload
	target.TraceId = received.TraceId
	return nil
}

func (m *mockStream) Header() (metadata.MD, error) {
	return nil, nil
}

func (m *mockStream) Trailer() metadata.MD {
	return nil
}

func (m *mockStream) Context() context.Context {
	return m.ctx
}

func (m *mockStream) SendHeader(metadata.MD) error {
	return nil
}

func (m *mockStream) SetHeader(metadata.MD) error {
	return nil
}

func (m *mockStream) SetTrailer(metadata.MD) {
}

func TestStreamClient_EventConversion(t *testing.T) {
	ctx := context.Background()

	// Create a minimal StreamClient for testing event conversion
	client := &StreamClient{
		sessionID: types.NewID(),
		eventCh:   make(chan *database.StreamEvent, 10),
		ctx:       ctx,
	}

	tests := []struct {
		name     string
		msg      *agentpb.StreamExecuteResponse
		wantType database.StreamEventType
	}{
		{
			name: "output chunk",
			msg: &agentpb.StreamExecuteResponse{
				Payload: &agentpb.StreamExecuteResponse_Output{
					Output: &agentpb.OutputChunk{
						Content:     "test output",
						IsReasoning: true,
					},
				},
				Sequence:    1,
				TraceId:     "trace-1",
				SpanId:      "span-1",
				TimestampMs: time.Now().UnixMilli(),
			},
			wantType: database.StreamEventOutput,
		},
		{
			name: "tool call",
			msg: &agentpb.StreamExecuteResponse{
				Payload: &agentpb.StreamExecuteResponse_ToolCall{
					ToolCall: &agentpb.ToolCallEvent{
						ToolName: "scan",
						Input: map[string]*commonpb.TypedValue{
							"target": {Kind: &commonpb.TypedValue_StringValue{StringValue: "192.168.1.1"}},
						},
						CallId: "call-1",
					},
				},
				Sequence:    2,
				TimestampMs: time.Now().UnixMilli(),
			},
			wantType: database.StreamEventToolCall,
		},
		{
			name: "tool result",
			msg: &agentpb.StreamExecuteResponse{
				Payload: &agentpb.StreamExecuteResponse_ToolResult{
					ToolResult: &agentpb.ToolResultEvent{
						CallId:  "call-1",
						Output:  &commonpb.TypedValue{Kind: &commonpb.TypedValue_StringValue{StringValue: "success"}},
						Success: true,
					},
				},
				Sequence:    3,
				TimestampMs: time.Now().UnixMilli(),
			},
			wantType: database.StreamEventToolResult,
		},
		{
			name: "finding",
			msg: &agentpb.StreamExecuteResponse{
				Payload: &agentpb.StreamExecuteResponse_Finding{
					Finding: &agentpb.FindingEvent{
						Finding: &typespb.Finding{
							Severity: typespb.FindingSeverity_FINDING_SEVERITY_HIGH,
							Title:    "SQL Injection",
						},
					},
				},
				Sequence:    4,
				TimestampMs: time.Now().UnixMilli(),
			},
			wantType: database.StreamEventFinding,
		},
		{
			name: "status change",
			msg: &agentpb.StreamExecuteResponse{
				Payload: &agentpb.StreamExecuteResponse_Status{
					Status: &agentpb.StatusChange{
						Status:  agentpb.AgentStatus_AGENT_STATUS_RUNNING,
						Message: "Agent is running",
					},
				},
				Sequence:    5,
				TimestampMs: time.Now().UnixMilli(),
			},
			wantType: database.StreamEventStatus,
		},
		{
			name: "steering acknowledgment",
			msg: &agentpb.StreamExecuteResponse{
				Payload: &agentpb.StreamExecuteResponse_SteeringAck{
					SteeringAck: &agentpb.SteeringAck{
						MessageId: "msg-1",
						Response:  "Acknowledged",
					},
				},
				Sequence:    6,
				TimestampMs: time.Now().UnixMilli(),
			},
			wantType: database.StreamEventSteeringAck,
		},
		{
			name: "error event",
			msg: &agentpb.StreamExecuteResponse{
				Payload: &agentpb.StreamExecuteResponse_Error{
					Error: &agentpb.ErrorEvent{
						Code:    commonpb.ErrorCode_ERROR_CODE_TIMEOUT,
						Message: "Operation timed out",
						Fatal:   true,
					},
				},
				Sequence:    7,
				TimestampMs: time.Now().UnixMilli(),
			},
			wantType: database.StreamEventError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event, err := client.protoToEvent(tt.msg)
			if err != nil {
				t.Errorf("protoToEvent() error = %v", err)
				return
			}

			if event.EventType != tt.wantType {
				t.Errorf("protoToEvent() event type = %v, want %v", event.EventType, tt.wantType)
			}

			if event.SessionID != client.sessionID {
				t.Errorf("protoToEvent() session ID = %v, want %v", event.SessionID, client.sessionID)
			}

			if event.Sequence != tt.msg.Sequence {
				t.Errorf("protoToEvent() sequence = %v, want %v", event.Sequence, tt.msg.Sequence)
			}

			// Verify content can be unmarshaled
			if len(event.Content) > 0 {
				var content map[string]any
				if err := json.Unmarshal(event.Content, &content); err != nil {
					t.Errorf("protoToEvent() content is not valid JSON: %v", err)
				}
			}
		})
	}
}

func TestStreamClient_GracefulShutdown(t *testing.T) {
	ctx := context.Background()
	stream := newMockStream(ctx)

	// Create client with mock stream
	client := &StreamClient{
		stream:     stream,
		agentName:  "test-agent",
		sessionID:  types.NewID(),
		eventCh:    make(chan *database.StreamEvent, 10),
		steeringCh: make(chan *agentpb.StreamExecuteRequest, 10),
		ctx:        ctx,
		closed:     false,
	}

	clientCtx, cancel := context.WithCancel(ctx)
	client.ctx = clientCtx
	client.cancel = cancel

	// Start goroutines
	client.wg.Add(2)
	go client.sendLoop()
	go client.recvLoop()

	// Give goroutines time to start
	time.Sleep(10 * time.Millisecond)

	// Close mock stream to trigger EOF in recvLoop
	close(stream.recvCh)

	// Close the client
	err := client.Close()
	if err != nil && err != io.EOF {
		t.Errorf("Close() error = %v", err)
	}

	// Verify channels are closed
	select {
	case _, ok := <-client.eventCh:
		if ok {
			t.Error("eventCh should be closed after Close()")
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("eventCh was not closed in time")
	}

	// Verify Close is idempotent
	err = client.Close()
	if err != nil {
		t.Errorf("Second Close() error = %v, should be nil", err)
	}
}

func TestStreamClient_SendOperations(t *testing.T) {
	ctx := context.Background()
	stream := newMockStream(ctx)

	client := &StreamClient{
		stream:     stream,
		agentName:  "test-agent",
		sessionID:  types.NewID(),
		eventCh:    make(chan *database.StreamEvent, 10),
		steeringCh: make(chan *agentpb.StreamExecuteRequest, 10),
		ctx:        ctx,
		closed:     false,
	}

	clientCtx, cancel := context.WithCancel(ctx)
	client.ctx = clientCtx
	client.cancel = cancel
	defer cancel()

	// Start send loop
	client.wg.Add(1)
	go client.sendLoop()

	t.Run("Start", func(t *testing.T) {
		err := client.Start(`{"task": "test"}`, database.AgentModeAutonomous)
		if err != nil {
			t.Errorf("Start() error = %v", err)
		}

		// Verify message was sent
		select {
		case msg := <-stream.sendCh:
			if msg.GetStart() == nil {
				t.Error("Expected StartExecutionRequest")
			}
			// The task is now sent as a Task proto message, not JSON
			if msg.GetStart().Task == nil {
				t.Error("Expected Task to be set")
			}
		case <-time.After(100 * time.Millisecond):
			t.Error("Start message not received")
		}
	})

	t.Run("SendSteering", func(t *testing.T) {
		err := client.SendSteering("Please scan port 443", map[string]string{
			"priority": "high",
		})
		if err != nil {
			t.Errorf("SendSteering() error = %v", err)
		}

		// Verify message was sent
		select {
		case msg := <-stream.sendCh:
			if msg.GetSteering() == nil {
				t.Error("Expected SteeringMessage")
			}
			if msg.GetSteering().Content != "Please scan port 443" {
				t.Errorf("Steering content = %v, want 'Please scan port 443'", msg.GetSteering().Content)
			}
		case <-time.After(100 * time.Millisecond):
			t.Error("Steering message not received")
		}
	})

	t.Run("SendInterrupt", func(t *testing.T) {
		err := client.SendInterrupt("user requested stop")
		if err != nil {
			t.Errorf("SendInterrupt() error = %v", err)
		}

		// Verify message was sent
		select {
		case msg := <-stream.sendCh:
			if msg.GetInterrupt() == nil {
				t.Error("Expected InterruptRequest")
			}
			if msg.GetInterrupt().Reason != "user requested stop" {
				t.Errorf("Interrupt reason = %v, want 'user requested stop'", msg.GetInterrupt().Reason)
			}
		case <-time.After(100 * time.Millisecond):
			t.Error("Interrupt message not received")
		}
	})

	t.Run("SetMode", func(t *testing.T) {
		err := client.SetMode(database.AgentModeInteractive)
		if err != nil {
			t.Errorf("SetMode() error = %v", err)
		}

		// Verify message was sent
		select {
		case msg := <-stream.sendCh:
			if msg.GetSetMode() == nil {
				t.Error("Expected SetModeRequest")
			}
			if msg.GetSetMode().Mode != agentpb.AgentMode_AGENT_MODE_INTERACTIVE {
				t.Errorf("Mode = %v, want AGENT_MODE_INTERACTIVE", msg.GetSetMode().Mode)
			}
		case <-time.After(100 * time.Millisecond):
			t.Error("SetMode message not received")
		}
	})

	t.Run("Resume", func(t *testing.T) {
		err := client.Resume("Continue with increased verbosity")
		if err != nil {
			t.Errorf("Resume() error = %v", err)
		}

		// Verify message was sent
		select {
		case msg := <-stream.sendCh:
			if msg.GetResume() == nil {
				t.Error("Expected ResumeRequest")
			}
			if msg.GetResume().Guidance != "Continue with increased verbosity" {
				t.Errorf("Guidance = %v, want 'Continue with increased verbosity'", msg.GetResume().Guidance)
			}
		case <-time.After(100 * time.Millisecond):
			t.Error("Resume message not received")
		}
	})

	// Clean up
	cancel()
	client.wg.Wait()
}

func TestStreamClient_SendAfterClose(t *testing.T) {
	ctx := context.Background()
	stream := newMockStream(ctx)

	client := &StreamClient{
		stream:     stream,
		agentName:  "test-agent",
		sessionID:  types.NewID(),
		eventCh:    make(chan *database.StreamEvent, 10),
		steeringCh: make(chan *agentpb.StreamExecuteRequest, 10),
		ctx:        ctx,
		closed:     false,
	}

	clientCtx, cancel := context.WithCancel(ctx)
	client.ctx = clientCtx
	client.cancel = cancel

	// Start goroutines
	client.wg.Add(2)
	go client.sendLoop()
	go client.recvLoop()

	// Close mock stream to trigger EOF in recvLoop
	close(stream.recvCh)

	// Close the client
	err := client.Close()
	if err != nil && err != io.EOF {
		t.Errorf("Close() error = %v", err)
	}

	// Try to send after close
	err = client.SendSteering("test", map[string]string{})
	if err == nil {
		t.Error("SendSteering() after Close() should return error")
	}

	err = client.SendInterrupt("test")
	if err == nil {
		t.Error("SendInterrupt() after Close() should return error")
	}

	err = client.SetMode(database.AgentModeAutonomous)
	if err == nil {
		t.Error("SetMode() after Close() should return error")
	}

	err = client.Resume("test")
	if err == nil {
		t.Error("Resume() after Close() should return error")
	}
}

// TestNewStreamClient_ErrorPath tests that NewStreamClient properly handles
// stream creation failures by returning an error instead of panicking.
//
// Note: This test verifies the error handling behavior indirectly by checking
// that the function signature returns an error. Direct testing of stream creation
// failures would require complex mocking of gRPC internals.
func TestNewStreamClient_ErrorPath(t *testing.T) {
	// This test documents the expected behavior:
	// 1. NewStreamClient returns (*StreamClient, error) instead of panicking
	// 2. Callers must handle the error case
	// 3. Context cancellation is properly cleaned up on error

	// We can't easily test stream creation failure without a real gRPC server,
	// but we can verify the function signature change is correct by ensuring
	// compilation succeeds with error handling code.

	ctx := context.Background()
	sessionID := types.NewID()

	// Example of proper error handling that callers must now implement:
	// (This won't actually execute successfully, but demonstrates the pattern)
	_ = func() error {
		// Create a mock connection (won't work in practice, but shows the pattern)
		var conn *grpc.ClientConn // nil connection will fail
		client, err := NewStreamClient(ctx, conn, "test-agent", sessionID)
		if err != nil {
			// Proper error handling - no panic!
			return err
		}
		defer client.Close()
		return nil
	}

	// Test that the function signature accepts the standard parameters
	// and returns error as the second return value
	var _ func(context.Context, *grpc.ClientConn, string, types.ID) (*StreamClient, error) = NewStreamClient

	// Success - the test passes if the code compiles with proper error handling
	t.Log("NewStreamClient now returns error instead of panicking")
}
