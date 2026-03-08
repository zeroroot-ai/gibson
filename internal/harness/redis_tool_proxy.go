package harness

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/zero-day-ai/gibson/internal/tool"
	"github.com/zero-day-ai/gibson/internal/types"
	"github.com/zero-day-ai/sdk/queue"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

// Tool execution error codes for RedisToolProxy
const (
	ErrRedisProxyInputSerialization    types.ErrorCode = "REDIS_TOOL_PROXY_INPUT_SERIALIZATION"
	ErrRedisProxyExecutionFailed       types.ErrorCode = "REDIS_TOOL_PROXY_EXECUTION_FAILED"
	ErrRedisProxyOutputDeserialization types.ErrorCode = "REDIS_TOOL_PROXY_OUTPUT_DESERIALIZATION"
	ErrRedisProxyTimeout               types.ErrorCode = "REDIS_TOOL_PROXY_TIMEOUT"
	ErrRedisProxyQueuePush             types.ErrorCode = "REDIS_TOOL_PROXY_QUEUE_PUSH"
	ErrRedisProxySubscribe             types.ErrorCode = "REDIS_TOOL_PROXY_SUBSCRIBE"
)

// RedisToolProxy implements tool.Tool by delegating execution to Redis-based workers.
// It pushes work items to a Redis queue and subscribes to a result channel.
//
// Architecture:
//  1. Proxy generates UUID job ID and serializes proto input to JSON
//  2. WorkItem is pushed to tool-specific Redis queue: "tool:<name>:queue"
//  3. Proxy subscribes to job-specific results channel: "results:<jobID>"
//  4. Worker polls queue, executes tool, publishes Result to results channel
//  5. Proxy receives result, deserializes proto output, returns to caller
type RedisToolProxy struct {
	client  *queue.RedisClient
	meta    queue.ToolMeta
	logger  *slog.Logger
	timeout time.Duration
}

// NewRedisToolProxy creates a new Redis-based tool proxy.
func NewRedisToolProxy(client *queue.RedisClient, meta queue.ToolMeta, logger *slog.Logger) *RedisToolProxy {
	return &RedisToolProxy{
		client:  client,
		meta:    meta,
		logger:  logger.With("tool", meta.Name),
		timeout: 5 * time.Minute, // Default 5-minute timeout
	}
}

// Name returns the tool name.
func (p *RedisToolProxy) Name() string {
	return p.meta.Name
}

// Version returns the tool version.
func (p *RedisToolProxy) Version() string {
	return p.meta.Version
}

// Description returns the tool description.
func (p *RedisToolProxy) Description() string {
	return p.meta.Description
}

// Tags returns the tool tags.
func (p *RedisToolProxy) Tags() []string {
	return p.meta.Tags
}

// InputMessageType returns the fully-qualified input proto message type.
func (p *RedisToolProxy) InputMessageType() string {
	return p.meta.InputMessageType
}

// OutputMessageType returns the fully-qualified output proto message type.
func (p *RedisToolProxy) OutputMessageType() string {
	return p.meta.OutputMessageType
}

// FileDescriptorSet returns the base64-encoded FileDescriptorSet for schema introspection.
// This is used by the harness to convert structpb.Struct inputs to typed proto messages.
func (p *RedisToolProxy) FileDescriptorSet() string {
	return p.meta.FileDescriptorSet
}

// Metadata returns tool metadata as a map, matching the interface used by GRPCToolClient.
func (p *RedisToolProxy) Metadata() map[string]string {
	return map[string]string{
		"file_descriptor_set": p.meta.FileDescriptorSet,
	}
}

// ExecuteProto executes the tool by pushing to Redis queue and waiting for result.
func (p *RedisToolProxy) ExecuteProto(ctx context.Context, input proto.Message) (proto.Message, error) {
	// Generate job ID
	jobID := uuid.New().String()

	// Serialize input to JSON
	inputJSON, err := protojson.Marshal(input)
	if err != nil {
		return nil, types.NewError(
			ErrRedisProxyInputSerialization,
			fmt.Sprintf("failed to marshal proto input: %v", err),
		)
	}

	// Extract trace context from OpenTelemetry span
	var traceID, spanID string
	if span := trace.SpanFromContext(ctx); span.SpanContext().IsValid() {
		spanCtx := span.SpanContext()
		traceID = spanCtx.TraceID().String()
		spanID = spanCtx.SpanID().String()
	}

	// Create work item
	workItem := queue.WorkItem{
		JobID:       jobID,
		Index:       0,
		Total:       1,
		Tool:        p.meta.Name,
		InputJSON:   string(inputJSON),
		InputType:   p.meta.InputMessageType,
		OutputType:  p.meta.OutputMessageType,
		TraceID:     traceID,
		SpanID:      spanID,
		SubmittedAt: time.Now().UnixMilli(),
	}

	// Validate work item
	if err := workItem.IsValid(); err != nil {
		return nil, types.NewError(
			ErrRedisProxyQueuePush,
			fmt.Sprintf("invalid work item: %v", err),
		)
	}

	// Subscribe to results channel before pushing work to avoid race conditions
	resultsChannel := fmt.Sprintf("results:%s", jobID)
	resultsChan, err := p.client.Subscribe(ctx, resultsChannel)
	if err != nil {
		return nil, types.NewError(
			ErrRedisProxySubscribe,
			fmt.Sprintf("failed to subscribe to results channel: %v", err),
		)
	}

	// Push work item to queue
	queueName := fmt.Sprintf("tool:%s:queue", p.meta.Name)
	if err := p.client.Push(ctx, queueName, workItem); err != nil {
		return nil, types.NewError(
			ErrRedisProxyQueuePush,
			fmt.Sprintf("failed to push work to queue: %v", err),
		)
	}

	p.logger.DebugContext(ctx, "pushed work item to queue",
		"job_id", jobID,
		"queue", queueName,
	)

	// Wait for result with timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	select {
	case result, ok := <-resultsChan:
		if !ok {
			// Channel closed unexpectedly
			return nil, types.NewError(
				ErrRedisProxyExecutionFailed,
				"results channel closed before receiving result",
			)
		}

		// Check if result is for our job (should always be true due to channel naming)
		if result.JobID != jobID {
			return nil, types.NewError(
				ErrRedisProxyExecutionFailed,
				fmt.Sprintf("received result for wrong job: expected %s, got %s", jobID, result.JobID),
			)
		}

		// Validate result
		if err := result.IsValid(); err != nil {
			return nil, types.NewError(
				ErrRedisProxyExecutionFailed,
				fmt.Sprintf("invalid result from worker: %v", err),
			)
		}

		// Check for execution error
		if result.HasError() {
			return nil, types.NewError(
				ErrRedisProxyExecutionFailed,
				fmt.Sprintf("tool execution failed: %s", result.Error),
			)
		}

		// Deserialize output
		output, err := p.deserializeOutput(result.OutputJSON)
		if err != nil {
			return nil, types.NewError(
				ErrRedisProxyOutputDeserialization,
				fmt.Sprintf("failed to deserialize output: %v", err),
			)
		}

		p.logger.DebugContext(ctx, "received result",
			"job_id", jobID,
			"worker_id", result.WorkerID,
			"duration_ms", result.Duration().Milliseconds(),
		)

		return output, nil

	case <-timeoutCtx.Done():
		if timeoutCtx.Err() == context.DeadlineExceeded {
			return nil, types.NewError(
				ErrRedisProxyTimeout,
				fmt.Sprintf("tool execution timeout after %v", p.timeout),
			)
		}
		return nil, types.NewError(
			ErrRedisProxyExecutionFailed,
			fmt.Sprintf("context cancelled: %v", timeoutCtx.Err()),
		)
	}
}

// deserializeOutput deserializes a JSON string into a proto message using dynamic type lookup.
// It first tries the global proto registry, then falls back to using the FileDescriptorSet
// from the tool metadata for dynamic proto message creation.
func (p *RedisToolProxy) deserializeOutput(outputJSON string) (proto.Message, error) {
	outputType := p.meta.OutputMessageType

	// First, try GlobalTypes registry (for compiled-in types)
	msgType, err := protoregistry.GlobalTypes.FindMessageByName(protoreflect.FullName(outputType))
	if err == nil {
		// Found in GlobalTypes - use compiled type
		msg := msgType.New().Interface()
		if err := protojson.Unmarshal([]byte(outputJSON), msg); err != nil {
			return nil, fmt.Errorf("failed to unmarshal output: %w", err)
		}
		return msg, nil
	}

	// GlobalTypes lookup failed - try dynamic type from FileDescriptorSet
	if p.meta.FileDescriptorSet == "" {
		return nil, fmt.Errorf("failed to find output message type %s: not in GlobalTypes and no file_descriptor_set available", outputType)
	}

	// Decode base64 file descriptor set
	fdsBytes, err := base64.StdEncoding.DecodeString(p.meta.FileDescriptorSet)
	if err != nil {
		return nil, fmt.Errorf("failed to decode file_descriptor_set: %w", err)
	}

	// Parse the FileDescriptorSet proto
	var fds descriptorpb.FileDescriptorSet
	if err := proto.Unmarshal(fdsBytes, &fds); err != nil {
		return nil, fmt.Errorf("failed to unmarshal file_descriptor_set: %w", err)
	}

	// Create a file registry from the descriptor set
	files, err := protodesc.NewFiles(&fds)
	if err != nil {
		return nil, fmt.Errorf("failed to create file registry: %w", err)
	}

	// Find the output message descriptor
	msgDesc, err := files.FindDescriptorByName(protoreflect.FullName(outputType))
	if err != nil {
		return nil, fmt.Errorf("failed to find message descriptor for %s: %w", outputType, err)
	}

	// Assert it's a message descriptor
	md, ok := msgDesc.(protoreflect.MessageDescriptor)
	if !ok {
		return nil, fmt.Errorf("%s is not a message descriptor", outputType)
	}

	// Create a dynamic message of the correct type
	dynamicMsg := dynamicpb.NewMessage(md)

	// Unmarshal JSON into the dynamic message
	unmarshaler := protojson.UnmarshalOptions{
		DiscardUnknown: true,
	}
	if err := unmarshaler.Unmarshal([]byte(outputJSON), dynamicMsg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal output into dynamic message: %w", err)
	}

	p.logger.Debug("deserialized output using dynamic proto from FileDescriptorSet",
		"output_type", outputType)

	return dynamicMsg, nil
}

// Health checks the health of the tool by checking worker count.
// Note: We only check worker count since the health key is managed by workers themselves.
func (p *RedisToolProxy) Health(ctx context.Context) types.HealthStatus {
	// Check worker count
	workerCount, err := p.client.GetWorkerCount(ctx, p.meta.Name)
	if err != nil {
		return types.NewHealthStatus(types.HealthStateUnhealthy, fmt.Sprintf("failed to get worker count: %v", err))
	}

	if workerCount == 0 {
		return types.NewHealthStatus(types.HealthStateUnhealthy, "no workers available")
	}

	return types.NewHealthStatus(types.HealthStateHealthy, fmt.Sprintf("%d workers available", workerCount))
}

// SetTimeout sets the execution timeout for this proxy.
func (p *RedisToolProxy) SetTimeout(timeout time.Duration) {
	p.timeout = timeout
}

// Ensure RedisToolProxy implements tool.Tool
var _ tool.Tool = (*RedisToolProxy)(nil)

// ────────────────────────────────────────────────────────────────────────────
// RedisToolProxyFactory - Factory for creating Redis tool proxies
// ────────────────────────────────────────────────────────────────────────────

// RedisToolProxyFactory creates RedisToolProxy instances from Redis tool metadata.
// This is used by the harness factory to populate the tool registry.
type RedisToolProxyFactory struct {
	client queue.Client
	logger *slog.Logger
}

// NewRedisToolProxyFactory creates a new factory for creating Redis tool proxies.
func NewRedisToolProxyFactory(client queue.Client, logger *slog.Logger) *RedisToolProxyFactory {
	return &RedisToolProxyFactory{
		client: client,
		logger: logger,
	}
}

// CreateFromToolMeta creates a RedisToolProxy from Redis tool metadata.
func (f *RedisToolProxyFactory) CreateFromToolMeta(meta queue.ToolMeta) (*RedisToolProxy, error) {
	// Validate tool metadata
	if err := meta.IsValid(); err != nil {
		return nil, fmt.Errorf("invalid tool metadata: %w", err)
	}

	// Convert queue.Client to *queue.RedisClient
	redisClient, ok := f.client.(*queue.RedisClient)
	if !ok {
		return nil, fmt.Errorf("client is not a RedisClient")
	}

	return NewRedisToolProxy(redisClient, meta, f.logger), nil
}

// FetchAndCreateProxies fetches all available tools from Redis and creates proxies.
func (f *RedisToolProxyFactory) FetchAndCreateProxies(ctx context.Context) ([]*RedisToolProxy, error) {
	// Get available tools from Redis
	tools, err := f.client.ListTools(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list tools from Redis: %w", err)
	}

	// Create proxies for each tool
	proxies := make([]*RedisToolProxy, 0, len(tools))
	for _, toolMeta := range tools {
		proxy, err := f.CreateFromToolMeta(toolMeta)
		if err != nil {
			// Log warning but continue with other tools
			f.logger.Warn("failed to create proxy for tool",
				"tool", toolMeta.Name,
				"error", err,
			)
			continue
		}
		proxies = append(proxies, proxy)
	}

	return proxies, nil
}

// PopulateToolRegistry fetches all available tools from Redis and registers them
// with the provided tool registry. This is the main integration point for wiring
// Redis-based tool workers into the harness.
//
// Parameters:
//   - ctx: Context for the Redis operations
//   - registry: The tool registry to populate with Redis tools
//
// Returns:
//   - int: Number of tools successfully registered
//   - error: Non-nil if fetching tools fails (individual registration errors are logged but not fatal)
func (f *RedisToolProxyFactory) PopulateToolRegistry(ctx context.Context, registry tool.ToolRegistry) (int, error) {
	proxies, err := f.FetchAndCreateProxies(ctx)
	if err != nil {
		return 0, err
	}

	registered := 0
	for _, proxy := range proxies {
		if err := registry.RegisterInternal(proxy); err != nil {
			// Tool may already be registered, skip but continue
			f.logger.Debug("failed to register tool in registry",
				"tool", proxy.Name(),
				"error", err,
			)
			continue
		}
		registered++
	}

	return registered, nil
}
