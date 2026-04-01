package harness

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"
	"time"
	"unsafe"

	"github.com/google/uuid"
	"github.com/zero-day-ai/gibson/internal/tool"
	"github.com/zero-day-ai/gibson/internal/types"
	commonpb "github.com/zero-day-ai/sdk/api/gen/gibson/common/v1"
	"github.com/zero-day-ai/sdk/queue"
	"go.opentelemetry.io/otel"
	"google.golang.org/protobuf/encoding/protojson"
)

// MockRedisClient implements the queue.Client interface for testing
type MockRedisClient struct {
	// Control behavior
	PushError      error
	SubscribeError error
	SubscribeChan  chan queue.Result
	SubscribeDelay time.Duration

	// Captured calls
	PushedItems    []queue.WorkItem
	PushedQueues   []string
	SubscribedChan string

	// Worker count for health checks
	WorkerCount    int
	WorkerCountErr error

	// Tools list for factory tests
	Tools   []queue.ToolMeta
	ListErr error
}

func NewMockRedisClient() *MockRedisClient {
	return &MockRedisClient{
		PushedItems:   make([]queue.WorkItem, 0),
		PushedQueues:  make([]string, 0),
		SubscribeChan: make(chan queue.Result, 1),
		WorkerCount:   1,
	}
}

func (m *MockRedisClient) Push(ctx context.Context, queueName string, item queue.WorkItem) error {
	if m.PushError != nil {
		return m.PushError
	}
	m.PushedItems = append(m.PushedItems, item)
	m.PushedQueues = append(m.PushedQueues, queueName)
	return nil
}

func (m *MockRedisClient) Pop(ctx context.Context, queueName string) (*queue.WorkItem, error) {
	return nil, errors.New("not implemented")
}

func (m *MockRedisClient) Publish(ctx context.Context, channel string, result queue.Result) error {
	return errors.New("not implemented")
}

func (m *MockRedisClient) Subscribe(ctx context.Context, channel string) (<-chan queue.Result, error) {
	if m.SubscribeError != nil {
		return nil, m.SubscribeError
	}
	m.SubscribedChan = channel

	// Optionally delay the subscription to simulate network latency
	if m.SubscribeDelay > 0 {
		time.Sleep(m.SubscribeDelay)
	}

	return m.SubscribeChan, nil
}

func (m *MockRedisClient) RegisterTool(ctx context.Context, meta queue.ToolMeta) error {
	return errors.New("not implemented")
}

func (m *MockRedisClient) ListTools(ctx context.Context) ([]queue.ToolMeta, error) {
	if m.ListErr != nil {
		return nil, m.ListErr
	}
	return m.Tools, nil
}

func (m *MockRedisClient) Heartbeat(ctx context.Context, toolName string) error {
	return errors.New("not implemented")
}

func (m *MockRedisClient) GetWorkerCount(ctx context.Context, toolName string) (int, error) {
	if m.WorkerCountErr != nil {
		return 0, m.WorkerCountErr
	}
	return m.WorkerCount, nil
}

func (m *MockRedisClient) IncrementWorkerCount(ctx context.Context, toolName string) error {
	return errors.New("not implemented")
}

func (m *MockRedisClient) DecrementWorkerCount(ctx context.Context, toolName string) error {
	return errors.New("not implemented")
}

func (m *MockRedisClient) Close() error {
	close(m.SubscribeChan)
	return nil
}

// Helper to send a result after a delay
func (m *MockRedisClient) SendResult(result queue.Result, delay time.Duration) {
	go func() {
		time.Sleep(delay)
		m.SubscribeChan <- result
	}()
}

// Helper to close the channel after a delay
func (m *MockRedisClient) CloseChannel(delay time.Duration) {
	go func() {
		time.Sleep(delay)
		close(m.SubscribeChan)
	}()
}

// Test helper to create a test ToolMeta
func createTestToolMeta() queue.ToolMeta {
	return queue.ToolMeta{
		Name:              "test-tool",
		Version:           "1.0.0",
		Description:       "Test tool for unit tests",
		InputMessageType:  "gibson.common.HealthStatus",
		OutputMessageType: "gibson.common.HealthStatus",
		Schema:            "{}",
		Tags:              []string{"test"},
		WorkerCount:       1,
	}
}

// Test helper to create a test logger
func createTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(nil, &slog.HandlerOptions{Level: slog.LevelError}))
}

// ────────────────────────────────────────────────────────────────────────────
// RedisToolProxy Tests
// ────────────────────────────────────────────────────────────────────────────

// createTestProxy creates a RedisToolProxy for testing with mock client
// Since RedisToolProxy.client is *queue.RedisClient (concrete type), we use unsafe pointer
// conversion for testing. This is acceptable in test code.
func createTestProxy(mockClient *MockRedisClient, meta queue.ToolMeta) *RedisToolProxy {
	proxy := &RedisToolProxy{
		meta:    meta,
		logger:  createTestLogger(),
		timeout: 5 * time.Minute,
	}
	// Use unsafe pointer conversion to assign mock client (test-only)
	// Convert *MockRedisClient to *queue.RedisClient via unsafe.Pointer
	proxy.client = (*queue.RedisClient)(unsafe.Pointer(mockClient))
	return proxy
}

func TestRedisToolProxy_Name(t *testing.T) {
	meta := createTestToolMeta()
	meta.Name = "custom-name"
	client := NewMockRedisClient()
	proxy := createTestProxy(client, meta)

	if got := proxy.Name(); got != "custom-name" {
		t.Errorf("Name() = %v, want %v", got, "custom-name")
	}
}

func TestRedisToolProxy_Version(t *testing.T) {
	meta := createTestToolMeta()
	meta.Version = "2.3.4"
	client := NewMockRedisClient()
	proxy := createTestProxy(client, meta)

	if got := proxy.Version(); got != "2.3.4" {
		t.Errorf("Version() = %v, want %v", got, "2.3.4")
	}
}

func TestRedisToolProxy_Description(t *testing.T) {
	meta := createTestToolMeta()
	meta.Description = "Custom description"
	client := NewMockRedisClient()
	proxy := createTestProxy(client, meta)

	if got := proxy.Description(); got != "Custom description" {
		t.Errorf("Description() = %v, want %v", got, "Custom description")
	}
}

func TestRedisToolProxy_Tags(t *testing.T) {
	meta := createTestToolMeta()
	meta.Tags = []string{"tag1", "tag2", "tag3"}
	client := NewMockRedisClient()
	proxy := createTestProxy(client, meta)

	got := proxy.Tags()
	if len(got) != 3 {
		t.Fatalf("Tags() length = %v, want %v", len(got), 3)
	}
	for i, tag := range []string{"tag1", "tag2", "tag3"} {
		if got[i] != tag {
			t.Errorf("Tags()[%d] = %v, want %v", i, got[i], tag)
		}
	}
}

func TestRedisToolProxy_InputMessageType(t *testing.T) {
	meta := createTestToolMeta()
	meta.InputMessageType = "test.Input"
	client := NewMockRedisClient()
	proxy := createTestProxy(client, meta)

	if got := proxy.InputMessageType(); got != "test.Input" {
		t.Errorf("InputMessageType() = %v, want %v", got, "test.Input")
	}
}

func TestRedisToolProxy_OutputMessageType(t *testing.T) {
	meta := createTestToolMeta()
	meta.OutputMessageType = "test.Output"
	client := NewMockRedisClient()
	proxy := createTestProxy(client, meta)

	if got := proxy.OutputMessageType(); got != "test.Output" {
		t.Errorf("OutputMessageType() = %v, want %v", got, "test.Output")
	}
}

func TestRedisToolProxy_ExecuteProto_Success(t *testing.T) {
	ctx := context.Background()
	meta := createTestToolMeta()
	client := NewMockRedisClient()
	proxy := createTestProxy(client, meta)

	// Create input message
	input := &commonpb.HealthStatus{
		Status:    "healthy",
		Message:   "test input",
		CheckedAt: time.Now().UnixMilli(),
	}

	// Create expected output
	outputMsg := &commonpb.HealthStatus{
		Status:    "healthy",
		Message:   "test output",
		CheckedAt: time.Now().UnixMilli(),
	}
	outputJSON, _ := protojson.Marshal(outputMsg)

	// Set up mock to send result after short delay
	go func() {
		time.Sleep(10 * time.Millisecond)
		// Wait for subscription to happen
		for client.SubscribedChan == "" {
			time.Sleep(1 * time.Millisecond)
		}
		// Extract jobID from subscribed channel (format: "results:<jobID>")
		jobID := client.SubscribedChan[8:] // Remove "results:" prefix
		result := queue.Result{
			JobID:       jobID,
			Index:       0,
			OutputJSON:  string(outputJSON),
			OutputType:  meta.OutputMessageType,
			WorkerID:    "test-worker",
			StartedAt:   time.Now().UnixMilli(),
			CompletedAt: time.Now().UnixMilli() + 100,
		}
		client.SubscribeChan <- result
	}()

	// Execute tool
	output, err := proxy.ExecuteProto(ctx, input)
	if err != nil {
		t.Fatalf("ExecuteProto() error = %v, want nil", err)
	}

	// Verify output type
	healthOutput, ok := output.(*commonpb.HealthStatus)
	if !ok {
		t.Fatalf("ExecuteProto() output type = %T, want *commonpb.HealthStatus", output)
	}

	if healthOutput.Message != "test output" {
		t.Errorf("ExecuteProto() output.Message = %v, want %v", healthOutput.Message, "test output")
	}

	// Verify work item was pushed
	if len(client.PushedItems) != 1 {
		t.Fatalf("Expected 1 pushed work item, got %d", len(client.PushedItems))
	}

	workItem := client.PushedItems[0]
	if workItem.Tool != "test-tool" {
		t.Errorf("WorkItem.Tool = %v, want %v", workItem.Tool, "test-tool")
	}
	if workItem.Index != 0 {
		t.Errorf("WorkItem.Index = %v, want %v", workItem.Index, 0)
	}
	if workItem.Total != 1 {
		t.Errorf("WorkItem.Total = %v, want %v", workItem.Total, 1)
	}

	// Verify queue name
	if len(client.PushedQueues) != 1 {
		t.Fatalf("Expected 1 queue name, got %d", len(client.PushedQueues))
	}
	expectedQueue := "tool:test-tool:queue"
	if client.PushedQueues[0] != expectedQueue {
		t.Errorf("Queue name = %v, want %v", client.PushedQueues[0], expectedQueue)
	}
}

func TestRedisToolProxy_ExecuteProto_Timeout(t *testing.T) {
	ctx := context.Background()
	meta := createTestToolMeta()
	client := NewMockRedisClient()
	proxy := createTestProxy(client, meta)

	// Set very short timeout
	proxy.SetTimeout(50 * time.Millisecond)

	// Create input message
	input := &commonpb.HealthStatus{
		Status:  "healthy",
		Message: "test input",
	}

	// Don't send any result (simulate timeout)

	// Execute tool
	output, err := proxy.ExecuteProto(ctx, input)
	if err == nil {
		t.Fatal("ExecuteProto() error = nil, want timeout error")
	}

	if output != nil {
		t.Errorf("ExecuteProto() output = %v, want nil", output)
	}

	// Verify error is timeout error
	var gibsonErr *types.GibsonError
	if !errors.As(err, &gibsonErr) {
		t.Fatalf("error type = %T, want *types.GibsonError", err)
	}

	if gibsonErr.Code != ErrRedisProxyTimeout {
		t.Errorf("error code = %v, want %v", gibsonErr.Code, ErrRedisProxyTimeout)
	}
}

func TestRedisToolProxy_ExecuteProto_Error(t *testing.T) {
	ctx := context.Background()
	meta := createTestToolMeta()
	client := NewMockRedisClient()
	proxy := createTestProxy(client, meta)

	// Create input message
	input := &commonpb.HealthStatus{
		Status:  "healthy",
		Message: "test input",
	}

	// Set up mock to send error result
	go func() {
		time.Sleep(10 * time.Millisecond)
		for client.SubscribedChan == "" {
			time.Sleep(1 * time.Millisecond)
		}
		jobID := client.SubscribedChan[8:]
		result := queue.Result{
			JobID:       jobID,
			Index:       0,
			OutputType:  meta.OutputMessageType,
			Error:       "tool execution failed: command not found",
			WorkerID:    "test-worker",
			StartedAt:   time.Now().UnixMilli(),
			CompletedAt: time.Now().UnixMilli() + 100,
		}
		client.SubscribeChan <- result
	}()

	// Execute tool
	output, err := proxy.ExecuteProto(ctx, input)
	if err == nil {
		t.Fatal("ExecuteProto() error = nil, want error")
	}

	if output != nil {
		t.Errorf("ExecuteProto() output = %v, want nil", output)
	}

	// Verify error contains worker error message
	var gibsonErr *types.GibsonError
	if !errors.As(err, &gibsonErr) {
		t.Fatalf("error type = %T, want *types.GibsonError", err)
	}

	if gibsonErr.Code != ErrRedisProxyExecutionFailed {
		t.Errorf("error code = %v, want %v", gibsonErr.Code, ErrRedisProxyExecutionFailed)
	}

	if gibsonErr.Message != "tool execution failed: command not found" {
		t.Errorf("error message = %v, want %v", gibsonErr.Message, "tool execution failed: command not found")
	}
}

func TestRedisToolProxy_ExecuteProto_InvalidInput(t *testing.T) {
	ctx := context.Background()
	meta := createTestToolMeta()
	client := NewMockRedisClient()
	proxy := createTestProxy(client, meta)

	// Pass nil input (will fail during marshaling)
	output, err := proxy.ExecuteProto(ctx, nil)
	if err == nil {
		t.Fatal("ExecuteProto() error = nil, want error for nil input")
	}

	if output != nil {
		t.Errorf("ExecuteProto() output = %v, want nil", output)
	}
}

func TestRedisToolProxy_ExecuteProto_PushError(t *testing.T) {
	ctx := context.Background()
	meta := createTestToolMeta()
	client := NewMockRedisClient()
	client.PushError = errors.New("redis connection failed")
	proxy := createTestProxy(client, meta)

	input := &commonpb.HealthStatus{
		Status:  "healthy",
		Message: "test input",
	}

	output, err := proxy.ExecuteProto(ctx, input)
	if err == nil {
		t.Fatal("ExecuteProto() error = nil, want push error")
	}

	if output != nil {
		t.Errorf("ExecuteProto() output = %v, want nil", output)
	}

	var gibsonErr *types.GibsonError
	if !errors.As(err, &gibsonErr) {
		t.Fatalf("error type = %T, want *types.GibsonError", err)
	}

	if gibsonErr.Code != ErrRedisProxyQueuePush {
		t.Errorf("error code = %v, want %v", gibsonErr.Code, ErrRedisProxyQueuePush)
	}
}

func TestRedisToolProxy_ExecuteProto_SubscribeError(t *testing.T) {
	ctx := context.Background()
	meta := createTestToolMeta()
	client := NewMockRedisClient()
	client.SubscribeError = errors.New("subscribe failed")
	proxy := createTestProxy(client, meta)

	input := &commonpb.HealthStatus{
		Status:  "healthy",
		Message: "test input",
	}

	output, err := proxy.ExecuteProto(ctx, input)
	if err == nil {
		t.Fatal("ExecuteProto() error = nil, want subscribe error")
	}

	if output != nil {
		t.Errorf("ExecuteProto() output = %v, want nil", output)
	}

	var gibsonErr *types.GibsonError
	if !errors.As(err, &gibsonErr) {
		t.Fatalf("error type = %T, want *types.GibsonError", err)
	}

	if gibsonErr.Code != ErrRedisProxySubscribe {
		t.Errorf("error code = %v, want %v", gibsonErr.Code, ErrRedisProxySubscribe)
	}
}

func TestRedisToolProxy_ExecuteProto_ChannelClosed(t *testing.T) {
	ctx := context.Background()
	meta := createTestToolMeta()
	client := NewMockRedisClient()
	proxy := createTestProxy(client, meta)

	input := &commonpb.HealthStatus{
		Status:  "healthy",
		Message: "test input",
	}

	// Close channel immediately
	go func() {
		time.Sleep(10 * time.Millisecond)
		close(client.SubscribeChan)
	}()

	output, err := proxy.ExecuteProto(ctx, input)
	if err == nil {
		t.Fatal("ExecuteProto() error = nil, want error for closed channel")
	}

	if output != nil {
		t.Errorf("ExecuteProto() output = %v, want nil", output)
	}

	var gibsonErr *types.GibsonError
	if !errors.As(err, &gibsonErr) {
		t.Fatalf("error type = %T, want *types.GibsonError", err)
	}

	if gibsonErr.Code != ErrRedisProxyExecutionFailed {
		t.Errorf("error code = %v, want %v", gibsonErr.Code, ErrRedisProxyExecutionFailed)
	}
}

func TestRedisToolProxy_ExecuteProto_WrongJobID(t *testing.T) {
	ctx := context.Background()
	meta := createTestToolMeta()
	client := NewMockRedisClient()
	proxy := createTestProxy(client, meta)

	input := &commonpb.HealthStatus{
		Status:  "healthy",
		Message: "test input",
	}

	// Send result with wrong job ID
	go func() {
		time.Sleep(10 * time.Millisecond)
		result := queue.Result{
			JobID:       "wrong-job-id",
			Index:       0,
			OutputJSON:  "{}",
			OutputType:  meta.OutputMessageType,
			WorkerID:    "test-worker",
			StartedAt:   time.Now().UnixMilli(),
			CompletedAt: time.Now().UnixMilli() + 100,
		}
		client.SubscribeChan <- result
	}()

	output, err := proxy.ExecuteProto(ctx, input)
	if err == nil {
		t.Fatal("ExecuteProto() error = nil, want error for wrong job ID")
	}

	if output != nil {
		t.Errorf("ExecuteProto() output = %v, want nil", output)
	}

	var gibsonErr *types.GibsonError
	if !errors.As(err, &gibsonErr) {
		t.Fatalf("error type = %T, want *types.GibsonError", err)
	}

	if gibsonErr.Code != ErrRedisProxyExecutionFailed {
		t.Errorf("error code = %v, want %v", gibsonErr.Code, ErrRedisProxyExecutionFailed)
	}
}

func TestRedisToolProxy_ExecuteProto_MalformedOutput(t *testing.T) {
	ctx := context.Background()
	meta := createTestToolMeta()
	client := NewMockRedisClient()
	proxy := createTestProxy(client, meta)

	input := &commonpb.HealthStatus{
		Status:  "healthy",
		Message: "test input",
	}

	// Send result with malformed JSON
	go func() {
		time.Sleep(10 * time.Millisecond)
		for client.SubscribedChan == "" {
			time.Sleep(1 * time.Millisecond)
		}
		jobID := client.SubscribedChan[8:]
		result := queue.Result{
			JobID:       jobID,
			Index:       0,
			OutputJSON:  "{malformed json",
			OutputType:  meta.OutputMessageType,
			WorkerID:    "test-worker",
			StartedAt:   time.Now().UnixMilli(),
			CompletedAt: time.Now().UnixMilli() + 100,
		}
		client.SubscribeChan <- result
	}()

	output, err := proxy.ExecuteProto(ctx, input)
	if err == nil {
		t.Fatal("ExecuteProto() error = nil, want deserialization error")
	}

	if output != nil {
		t.Errorf("ExecuteProto() output = %v, want nil", output)
	}

	var gibsonErr *types.GibsonError
	if !errors.As(err, &gibsonErr) {
		t.Fatalf("error type = %T, want *types.GibsonError", err)
	}

	if gibsonErr.Code != ErrRedisProxyOutputDeserialization {
		t.Errorf("error code = %v, want %v", gibsonErr.Code, ErrRedisProxyOutputDeserialization)
	}
}

func TestRedisToolProxy_ExecuteProto_EmptyOutput(t *testing.T) {
	ctx := context.Background()
	meta := createTestToolMeta()
	client := NewMockRedisClient()
	proxy := createTestProxy(client, meta)

	input := &commonpb.HealthStatus{
		Status:  "healthy",
		Message: "test input",
	}

	// Send result with empty output JSON (should fail validation)
	go func() {
		time.Sleep(10 * time.Millisecond)
		for client.SubscribedChan == "" {
			time.Sleep(1 * time.Millisecond)
		}
		jobID := client.SubscribedChan[8:]
		result := queue.Result{
			JobID:       jobID,
			Index:       0,
			OutputJSON:  "", // Empty output
			OutputType:  meta.OutputMessageType,
			WorkerID:    "test-worker",
			StartedAt:   time.Now().UnixMilli(),
			CompletedAt: time.Now().UnixMilli() + 100,
		}
		client.SubscribeChan <- result
	}()

	output, err := proxy.ExecuteProto(ctx, input)
	if err == nil {
		t.Fatal("ExecuteProto() error = nil, want validation error")
	}

	if output != nil {
		t.Errorf("ExecuteProto() output = %v, want nil", output)
	}

	var gibsonErr *types.GibsonError
	if !errors.As(err, &gibsonErr) {
		t.Fatalf("error type = %T, want *types.GibsonError", err)
	}

	if gibsonErr.Code != ErrRedisProxyExecutionFailed {
		t.Errorf("error code = %v, want %v", gibsonErr.Code, ErrRedisProxyExecutionFailed)
	}
}

func TestRedisToolProxy_WorkItemSerialization(t *testing.T) {
	ctx := context.Background()
	meta := createTestToolMeta()
	client := NewMockRedisClient()
	proxy := createTestProxy(client, meta)

	// Create input with specific values
	input := &commonpb.HealthStatus{
		Status:    "healthy",
		Message:   "specific test message",
		CheckedAt: 1234567890,
	}

	// Set up timeout to abort quickly
	proxy.SetTimeout(50 * time.Millisecond)

	// Execute (will timeout but that's OK, we just want to check the work item)
	_, _ = proxy.ExecuteProto(ctx, input)

	// Verify work item was pushed
	if len(client.PushedItems) != 1 {
		t.Fatalf("Expected 1 pushed work item, got %d", len(client.PushedItems))
	}

	workItem := client.PushedItems[0]

	// Verify JobID is valid UUID
	if _, err := uuid.Parse(workItem.JobID); err != nil {
		t.Errorf("WorkItem.JobID is not a valid UUID: %v", err)
	}

	// Verify batch fields
	if workItem.Index != 0 {
		t.Errorf("WorkItem.Index = %v, want 0", workItem.Index)
	}
	if workItem.Total != 1 {
		t.Errorf("WorkItem.Total = %v, want 1", workItem.Total)
	}

	// Verify tool name
	if workItem.Tool != "test-tool" {
		t.Errorf("WorkItem.Tool = %v, want test-tool", workItem.Tool)
	}

	// Verify input JSON can be deserialized
	var decodedInput commonpb.HealthStatus
	if err := json.Unmarshal([]byte(workItem.InputJSON), &decodedInput); err != nil {
		t.Fatalf("Failed to unmarshal InputJSON: %v", err)
	}
	if decodedInput.Message != "specific test message" {
		t.Errorf("Deserialized input message = %v, want specific test message", decodedInput.Message)
	}

	// Verify type fields
	if workItem.InputType != "gibson.common.HealthStatus" {
		t.Errorf("WorkItem.InputType = %v, want gibson.common.HealthStatus", workItem.InputType)
	}
	if workItem.OutputType != "gibson.common.HealthStatus" {
		t.Errorf("WorkItem.OutputType = %v, want gibson.common.HealthStatus", workItem.OutputType)
	}

	// Verify timestamp is reasonable (within last second)
	now := time.Now().UnixMilli()
	if workItem.SubmittedAt < now-1000 || workItem.SubmittedAt > now {
		t.Errorf("WorkItem.SubmittedAt = %v, want between %v and %v", workItem.SubmittedAt, now-1000, now)
	}

	// Verify validation passes
	if err := workItem.IsValid(); err != nil {
		t.Errorf("WorkItem.IsValid() = %v, want nil", err)
	}
}

func TestRedisToolProxy_WorkItemSerialization_WithTracing(t *testing.T) {
	// Create a context with an OpenTelemetry span
	tracer := otel.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "test-span")
	defer span.End()

	meta := createTestToolMeta()
	client := NewMockRedisClient()
	proxy := createTestProxy(client, meta)

	input := &commonpb.HealthStatus{
		Status:  "healthy",
		Message: "test",
	}

	// Set up timeout to abort quickly
	proxy.SetTimeout(50 * time.Millisecond)

	// Execute
	_, _ = proxy.ExecuteProto(ctx, input)

	// Verify trace context was captured
	if len(client.PushedItems) != 1 {
		t.Fatalf("Expected 1 pushed work item, got %d", len(client.PushedItems))
	}

	workItem := client.PushedItems[0]

	// If span context is valid, trace ID and span ID should be set
	if span.SpanContext().IsValid() {
		if workItem.TraceID == "" {
			t.Error("WorkItem.TraceID should be set when span context is valid")
		}
		if workItem.SpanID == "" {
			t.Error("WorkItem.SpanID should be set when span context is valid")
		}

		// Verify they match the span context
		expectedTraceID := span.SpanContext().TraceID().String()
		expectedSpanID := span.SpanContext().SpanID().String()

		if workItem.TraceID != expectedTraceID {
			t.Errorf("WorkItem.TraceID = %v, want %v", workItem.TraceID, expectedTraceID)
		}
		if workItem.SpanID != expectedSpanID {
			t.Errorf("WorkItem.SpanID = %v, want %v", workItem.SpanID, expectedSpanID)
		}
	}
}

func TestRedisToolProxy_Health_Healthy(t *testing.T) {
	ctx := context.Background()
	meta := createTestToolMeta()
	client := NewMockRedisClient()
	client.WorkerCount = 3
	proxy := createTestProxy(client, meta)

	status := proxy.Health(ctx)

	if !status.IsHealthy() {
		t.Errorf("Health() status = %v, want healthy", status.State)
	}

	if status.Message != "3 workers available" {
		t.Errorf("Health() message = %v, want '3 workers available'", status.Message)
	}
}

func TestRedisToolProxy_Health_NoWorkers(t *testing.T) {
	ctx := context.Background()
	meta := createTestToolMeta()
	client := NewMockRedisClient()
	client.WorkerCount = 0
	proxy := createTestProxy(client, meta)

	status := proxy.Health(ctx)

	if !status.IsUnhealthy() {
		t.Errorf("Health() status = %v, want unhealthy", status.State)
	}

	if status.Message != "no workers available" {
		t.Errorf("Health() message = %v, want 'no workers available'", status.Message)
	}
}

func TestRedisToolProxy_Health_Error(t *testing.T) {
	ctx := context.Background()
	meta := createTestToolMeta()
	client := NewMockRedisClient()
	client.WorkerCountErr = errors.New("redis connection failed")
	proxy := createTestProxy(client, meta)

	status := proxy.Health(ctx)

	if !status.IsUnhealthy() {
		t.Errorf("Health() status = %v, want unhealthy", status.State)
	}

	expectedMsg := "failed to get worker count: redis connection failed"
	if status.Message != expectedMsg {
		t.Errorf("Health() message = %v, want %v", status.Message, expectedMsg)
	}
}

func TestRedisToolProxy_SetTimeout(t *testing.T) {
	meta := createTestToolMeta()
	client := NewMockRedisClient()
	proxy := createTestProxy(client, meta)

	// Default timeout should be 5 minutes
	if proxy.timeout != 5*time.Minute {
		t.Errorf("default timeout = %v, want %v", proxy.timeout, 5*time.Minute)
	}

	// Set custom timeout
	proxy.SetTimeout(30 * time.Second)

	if proxy.timeout != 30*time.Second {
		t.Errorf("timeout after SetTimeout = %v, want %v", proxy.timeout, 30*time.Second)
	}
}

func TestRedisToolProxy_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	meta := createTestToolMeta()
	client := NewMockRedisClient()
	proxy := createTestProxy(client, meta)

	input := &commonpb.HealthStatus{
		Status:  "healthy",
		Message: "test input",
	}

	// Cancel context immediately after starting
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	output, err := proxy.ExecuteProto(ctx, input)
	if err == nil {
		t.Fatal("ExecuteProto() error = nil, want context cancellation error")
	}

	if output != nil {
		t.Errorf("ExecuteProto() output = %v, want nil", output)
	}

	var gibsonErr *types.GibsonError
	if !errors.As(err, &gibsonErr) {
		t.Fatalf("error type = %T, want *types.GibsonError", err)
	}

	if gibsonErr.Code != ErrRedisProxyExecutionFailed {
		t.Errorf("error code = %v, want %v", gibsonErr.Code, ErrRedisProxyExecutionFailed)
	}
}

// ────────────────────────────────────────────────────────────────────────────
// RedisToolProxyFactory Tests
// ────────────────────────────────────────────────────────────────────────────

func TestRedisToolProxyFactory_CreateFromToolMeta_Success(t *testing.T) {
	client := NewMockRedisClient()
	factory := NewRedisToolProxyFactory(client, createTestLogger())

	meta := createTestToolMeta()
	proxy, err := factory.CreateFromToolMeta(meta)

	if err != nil {
		t.Fatalf("CreateFromToolMeta() error = %v, want nil", err)
	}

	if proxy == nil {
		t.Fatal("CreateFromToolMeta() proxy = nil, want non-nil")
	}

	if proxy.Name() != meta.Name {
		t.Errorf("proxy.Name() = %v, want %v", proxy.Name(), meta.Name)
	}
}

func TestRedisToolProxyFactory_CreateFromToolMeta_InvalidMeta(t *testing.T) {
	client := NewMockRedisClient()
	factory := NewRedisToolProxyFactory(client, createTestLogger())

	// Create invalid metadata (missing required fields)
	meta := queue.ToolMeta{
		Name: "test-tool",
		// Missing Version, InputMessageType, OutputMessageType
	}

	proxy, err := factory.CreateFromToolMeta(meta)

	if err == nil {
		t.Fatal("CreateFromToolMeta() error = nil, want validation error")
	}

	if proxy != nil {
		t.Errorf("CreateFromToolMeta() proxy = %v, want nil", proxy)
	}
}

func TestRedisToolProxyFactory_FetchAndCreateProxies_Success(t *testing.T) {
	client := NewMockRedisClient()
	client.Tools = []queue.ToolMeta{
		createTestToolMeta(),
		{
			Name:              "tool2",
			Version:           "2.0.0",
			Description:       "Second tool",
			InputMessageType:  "test.Input",
			OutputMessageType: "test.Output",
		},
	}
	factory := NewRedisToolProxyFactory(client, createTestLogger())

	proxies, err := factory.FetchAndCreateProxies(context.Background())

	if err != nil {
		t.Fatalf("FetchAndCreateProxies() error = %v, want nil", err)
	}

	if len(proxies) != 2 {
		t.Fatalf("FetchAndCreateProxies() len = %v, want 2", len(proxies))
	}

	// Verify proxy names
	names := []string{proxies[0].Name(), proxies[1].Name()}
	expectedNames := []string{"test-tool", "tool2"}

	for i, name := range expectedNames {
		if names[i] != name {
			t.Errorf("proxy[%d].Name() = %v, want %v", i, names[i], name)
		}
	}
}

func TestRedisToolProxyFactory_FetchAndCreateProxies_ListError(t *testing.T) {
	client := NewMockRedisClient()
	client.ListErr = errors.New("redis connection failed")
	factory := NewRedisToolProxyFactory(client, createTestLogger())

	proxies, err := factory.FetchAndCreateProxies(context.Background())

	if err == nil {
		t.Fatal("FetchAndCreateProxies() error = nil, want redis error")
	}

	if proxies != nil {
		t.Errorf("FetchAndCreateProxies() proxies = %v, want nil", proxies)
	}
}

func TestRedisToolProxyFactory_FetchAndCreateProxies_PartialFailure(t *testing.T) {
	client := NewMockRedisClient()
	client.Tools = []queue.ToolMeta{
		createTestToolMeta(), // Valid
		{
			Name: "invalid-tool",
			// Missing required fields - will fail validation
		},
		{
			Name:              "tool3",
			Version:           "3.0.0",
			Description:       "Third tool",
			InputMessageType:  "test.Input3",
			OutputMessageType: "test.Output3",
		}, // Valid
	}
	factory := NewRedisToolProxyFactory(client, createTestLogger())

	proxies, err := factory.FetchAndCreateProxies(context.Background())

	// Should not return an error, just skip invalid tools
	if err != nil {
		t.Fatalf("FetchAndCreateProxies() error = %v, want nil", err)
	}

	// Should only have the 2 valid tools
	if len(proxies) != 2 {
		t.Fatalf("FetchAndCreateProxies() len = %v, want 2 (skipping invalid)", len(proxies))
	}
}

func TestRedisToolProxyFactory_FetchAndCreateProxies_EmptyList(t *testing.T) {
	client := NewMockRedisClient()
	client.Tools = []queue.ToolMeta{} // Empty list
	factory := NewRedisToolProxyFactory(client, createTestLogger())

	proxies, err := factory.FetchAndCreateProxies(context.Background())

	if err != nil {
		t.Fatalf("FetchAndCreateProxies() error = %v, want nil", err)
	}

	if len(proxies) != 0 {
		t.Fatalf("FetchAndCreateProxies() len = %v, want 0", len(proxies))
	}
}

// MockToolRegistry for testing PopulateToolRegistry
type MockToolRegistry struct {
	RegisteredTools []string
	RegisterError   error
	tools           map[string]tool.Tool
}

func (m *MockToolRegistry) RegisterInternal(t tool.Tool) error {
	if m.RegisterError != nil {
		return m.RegisterError
	}
	m.RegisteredTools = append(m.RegisteredTools, t.Name())
	if m.tools == nil {
		m.tools = make(map[string]tool.Tool)
	}
	m.tools[t.Name()] = t
	return nil
}

func (m *MockToolRegistry) RegisterExternal(name string, client tool.ExternalToolClient) error {
	return nil
}

func (m *MockToolRegistry) Unregister(name string) error {
	return nil
}

func (m *MockToolRegistry) Get(name string) (tool.Tool, error) {
	if m.tools == nil {
		return nil, errors.New("tool not found")
	}
	t, ok := m.tools[name]
	if !ok {
		return nil, errors.New("tool not found")
	}
	return t, nil
}

func (m *MockToolRegistry) List() []tool.ToolDescriptor {
	return nil
}

func (m *MockToolRegistry) ListByTag(tag string) []tool.ToolDescriptor {
	return nil
}

func (m *MockToolRegistry) Health(ctx context.Context) types.HealthStatus {
	return types.Healthy("mock registry healthy")
}

func (m *MockToolRegistry) ToolHealth(ctx context.Context, name string) types.HealthStatus {
	return types.Healthy("mock tool healthy")
}

func (m *MockToolRegistry) Metrics(name string) (tool.ToolMetrics, error) {
	return tool.ToolMetrics{}, nil
}

func TestRedisToolProxyFactory_PopulateToolRegistry_Success(t *testing.T) {
	client := NewMockRedisClient()
	client.Tools = []queue.ToolMeta{
		createTestToolMeta(),
		{
			Name:              "tool2",
			Version:           "2.0.0",
			Description:       "Second tool",
			InputMessageType:  "test.Input",
			OutputMessageType: "test.Output",
		},
	}
	factory := NewRedisToolProxyFactory(client, createTestLogger())
	registry := &MockToolRegistry{RegisteredTools: make([]string, 0)}

	count, err := factory.PopulateToolRegistry(context.Background(), registry)

	if err != nil {
		t.Fatalf("PopulateToolRegistry() error = %v, want nil", err)
	}

	if count != 2 {
		t.Errorf("PopulateToolRegistry() count = %v, want 2", count)
	}

	if len(registry.RegisteredTools) != 2 {
		t.Fatalf("registry has %d tools, want 2", len(registry.RegisteredTools))
	}

	expectedNames := []string{"test-tool", "tool2"}
	for i, name := range expectedNames {
		if registry.RegisteredTools[i] != name {
			t.Errorf("registry tool[%d] = %v, want %v", i, registry.RegisteredTools[i], name)
		}
	}
}

func TestRedisToolProxyFactory_PopulateToolRegistry_FetchError(t *testing.T) {
	client := NewMockRedisClient()
	client.ListErr = errors.New("redis connection failed")
	factory := NewRedisToolProxyFactory(client, createTestLogger())
	registry := &MockToolRegistry{RegisteredTools: make([]string, 0)}

	count, err := factory.PopulateToolRegistry(context.Background(), registry)

	if err == nil {
		t.Fatal("PopulateToolRegistry() error = nil, want fetch error")
	}

	if count != 0 {
		t.Errorf("PopulateToolRegistry() count = %v, want 0", count)
	}
}

func TestRedisToolProxyFactory_PopulateToolRegistry_RegistrationFailure(t *testing.T) {
	client := NewMockRedisClient()
	client.Tools = []queue.ToolMeta{
		createTestToolMeta(),
		{
			Name:              "tool2",
			Version:           "2.0.0",
			Description:       "Second tool",
			InputMessageType:  "test.Input",
			OutputMessageType: "test.Output",
		},
	}
	factory := NewRedisToolProxyFactory(client, createTestLogger())
	registry := &MockToolRegistry{
		RegisteredTools: make([]string, 0),
		RegisterError:   errors.New("tool already registered"),
	}

	count, err := factory.PopulateToolRegistry(context.Background(), registry)

	// Should not return an error (registration failures are logged but not fatal)
	if err != nil {
		t.Fatalf("PopulateToolRegistry() error = %v, want nil", err)
	}

	// Count should be 0 since all registrations failed
	if count != 0 {
		t.Errorf("PopulateToolRegistry() count = %v, want 0 (all failed)", count)
	}

	// Registry should be empty
	if len(registry.RegisteredTools) != 0 {
		t.Errorf("registry has %d tools, want 0", len(registry.RegisteredTools))
	}
}
