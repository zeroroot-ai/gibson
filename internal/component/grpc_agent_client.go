package component

import (
	"context"
	"encoding/json"
	"fmt"

	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"

	"github.com/zeroroot-ai/gibson/internal/agent"
	"github.com/zeroroot-ai/gibson/internal/types"
	agentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/agent/v1"
	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	"github.com/zeroroot-ai/sdk/schema"
)

// GRPCAgentClient implements agent.Agent interface for agents discovered via the component registry.
//
// This client wraps a gRPC connection to a remote agent and translates between
// Gibson's internal agent.Agent interface and the gRPC protocol. It uses ComponentInfo
// from the component registry to populate agent metadata (name, version, capabilities, etc.).
//
// Key features:
// - Implements full agent.Agent interface for remote gRPC agents
// - Parses capabilities, target types, and technique types from ComponentInfo metadata
// - Delegates execution to remote agent via gRPC
// - Handles descriptor caching and health checks
type GRPCAgentClient struct {
	conn   *grpc.ClientConn
	client agentpb.AgentServiceClient
	info   ComponentInfo

	// Cached descriptor from GetDescriptor RPC
	// This avoids repeated gRPC calls for static metadata
	descriptor *agent.AgentDescriptor
}

// NewGRPCAgentClient creates a new GRPCAgentClient wrapping an existing gRPC connection.
//
// The connection should already be established and ready to use. The ComponentInfo
// provides metadata about the agent (name, version, capabilities, etc.)
// that was discovered from the component registry.
//
// Parameters:
//   - conn: Established gRPC connection to the agent
//   - info: ComponentInfo from the component registry with agent metadata
//
// Returns a GRPCAgentClient that implements the agent.Agent interface.
func NewGRPCAgentClient(conn *grpc.ClientConn, info ComponentInfo) *GRPCAgentClient {
	return &GRPCAgentClient{
		conn:   conn,
		client: agentpb.NewAgentServiceClient(conn),
		info:   info,
	}
}

// CallbackInfo contains callback configuration for agent execution.
// It enables external agents to connect back to Gibson Core's HarnessCallbackService
// to access LLM, tools, memory, GraphRAG, and findings functionality.
type CallbackInfo struct {
	// Endpoint is the callback server address (e.g., "gibson:50001")
	Endpoint string
	// Token is the optional authentication token for callback connections
	Token string
	// Mission is the mission context to pass to the agent (typically *harness.MissionContext)
	// This will be JSON-marshaled and sent to the agent via the MissionJson field.
	Mission any
	// Target is the target information to pass to the agent (typically *harness.TargetInfo)
	// This will be JSON-marshaled and sent to the agent via the TargetJson field.
	Target any
	// MissionRunID is the unique identifier for this specific mission execution.
	// Created by MissionGraphManager.CreateMissionRunNode() at mission start.
	// Used for mission-scoped GraphRAG storage.
	MissionRunID string
	// AgentRunID is the unique identifier for this specific agent execution.
	// Used for DISCOVERED relationships and provenance tracking.
	AgentRunID string
	// RunNumber is the sequential run number for this mission (1, 2, 3...).
	// Used for mission memory queries and historical comparisons.
	RunNumber int32
}

// Name returns the agent name from ServiceInfo
func (c *GRPCAgentClient) Name() string {
	return c.info.Name
}

// Version returns the agent version from ServiceInfo
func (c *GRPCAgentClient) Version() string {
	return c.info.Version
}

// Description returns the agent description.
//
// If available, this is retrieved from the cached descriptor (which comes from
// the agent's GetDescriptor RPC). Otherwise, falls back to metadata or empty string.
func (c *GRPCAgentClient) Description() string {
	if c.descriptor != nil {
		return c.descriptor.Description
	}

	// Try to get from metadata
	if desc, ok := c.info.Metadata["description"]; ok {
		return desc
	}

	return ""
}

// Capabilities returns the agent's capabilities from ServiceInfo metadata.
//
// The metadata should contain a "capabilities" key with comma-separated values.
// For example: "prompt_injection,jailbreak,data_extraction"
func (c *GRPCAgentClient) Capabilities() []string {
	if c.descriptor != nil {
		return c.descriptor.Capabilities
	}

	return parseCommaSeparated(c.info.Metadata["capabilities"])
}

// TargetTypes returns the types of targets this agent can operate against.
//
// The metadata should contain a "target_types" key with comma-separated values.
// For example: "llm_chat,llm_api,rag_system"
func (c *GRPCAgentClient) TargetTypes() []TargetType {
	if c.descriptor != nil {
		return c.descriptor.TargetTypes
	}

	targetStrs := parseCommaSeparated(c.info.Metadata["target_types"])
	result := make([]TargetType, len(targetStrs))
	for i, t := range targetStrs {
		result[i] = TargetType(t)
	}
	return result
}

// TechniqueTypes returns the types of techniques this agent can execute.
//
// The metadata should contain a "technique_types" key with comma-separated values.
// For example: "prompt_injection,model_extraction,jailbreak"
func (c *GRPCAgentClient) TechniqueTypes() []TechniqueType {
	if c.descriptor != nil {
		return c.descriptor.TechniqueTypes
	}

	techniqueStrs := parseCommaSeparated(c.info.Metadata["technique_types"])
	result := make([]TechniqueType, len(techniqueStrs))
	for i, t := range techniqueStrs {
		result[i] = TechniqueType(t)
	}
	return result
}

// LLMSlots returns the LLM slot definitions required by this agent.
//
// This calls the GetSlotSchema RPC to fetch detailed slot information.
// The result is cached in the descriptor to avoid repeated RPC calls.
func (c *GRPCAgentClient) LLMSlots() []agent.SlotDefinition {
	// Ensure descriptor is loaded
	if c.descriptor == nil {
		ctx := context.Background()
		_, _ = c.fetchDescriptor(ctx)
	}

	// Try to fetch slots if not already loaded
	if c.descriptor != nil && c.descriptor.Slots == nil {
		ctx := context.Background()
		_ = c.fetchSlots(ctx)
	}

	if c.descriptor != nil && c.descriptor.Slots != nil {
		return c.descriptor.Slots
	}

	return []agent.SlotDefinition{}
}

// Initialize prepares the agent for execution with the given configuration.
//
// For gRPC agents, this is typically a no-op since the remote agent manages
// its own initialization. This method is provided for interface compatibility.
func (c *GRPCAgentClient) Initialize(ctx context.Context, cfg agent.AgentConfig) error {
	// gRPC agents manage their own initialization
	// This could be extended to send an Initialize RPC if needed
	return nil
}

// Execute runs the agent against a task using the provided harness.
//
// This method:
//  1. Marshals the task to JSON
//  2. Sends an Execute RPC to the remote agent
//  3. Receives the result via gRPC
//  4. Unmarshals and returns the result
//
// Note: The harness parameter is currently not used for gRPC agents.
// Future implementations may use bidirectional streaming to support
// harness callbacks (tool execution, plugin queries, sub-agent delegation).
func (c *GRPCAgentClient) Execute(ctx context.Context, task agent.Task, harness agent.AgentHarness) (agent.Result, error) {
	// Convert task to proto
	protoTask := agent.TaskToProto(task)

	// Send Execute RPC
	timeoutMs := int64(task.Timeout.Milliseconds())
	req := &agentpb.ExecuteRequest{
		Task:      protoTask,
		TimeoutMs: timeoutMs,
	}

	// Extract trace context from the current span and add to request
	spanCtx := trace.SpanContextFromContext(ctx)
	if spanCtx.IsValid() {
		req.TraceId = spanCtx.TraceID().String()
		req.ParentSpanId = spanCtx.SpanID().String()
	}

	resp, err := c.client.Execute(ctx, req)
	if err != nil {
		result := agent.NewResult(task.ID)
		result.Fail(fmt.Errorf("agent execution failed: %w", err))
		return result, nil
	}

	// Check for errors in response
	if resp.Error != nil {
		result := agent.NewResult(task.ID)
		result.Fail(fmt.Errorf("%s: %s", resp.Error.Code, resp.Error.Message))
		return result, nil
	}

	// Convert proto result to internal result
	result := agent.ProtoToResult(resp.Result)
	result.TaskID = task.ID // Ensure task ID is set

	return result, nil
}

// ExecuteWithCallback runs the agent against a task with callback configuration.
//
// This method extends Execute() by populating callback fields in the gRPC request,
// enabling external agents to connect back to Gibson Core's HarnessCallbackService
// for LLM operations, tool execution, memory access, and findings submission.
//
// The callback parameter contains:
//   - Endpoint: Callback server address for harness operations
//   - Token: Optional authentication token for secure connections
//   - Mission: Mission context (serialized to JSON)
//   - Target: Target information (serialized to JSON)
//
// If callback is nil, this method behaves identically to Execute() (no callback fields set).
//
// Parameters:
//   - ctx: Context for request cancellation and timeouts
//   - task: Task configuration for the agent
//   - callback: Optional callback configuration (nil falls back to standard execution)
//
// Returns the agent's execution result or an error if execution fails.
func (c *GRPCAgentClient) ExecuteWithCallback(ctx context.Context, task agent.Task, callback *CallbackInfo) (agent.Result, error) {
	// Convert task to proto
	protoTask := agent.TaskToProto(task)

	// Build the base request
	timeoutMs := int64(task.Timeout.Milliseconds())
	req := &agentpb.ExecuteRequest{
		Task:      protoTask,
		TimeoutMs: timeoutMs,
	}

	// Extract trace context from the current span and add to request
	spanCtx := trace.SpanContextFromContext(ctx)
	if spanCtx.IsValid() {
		req.TraceId = spanCtx.TraceID().String()
		req.ParentSpanId = spanCtx.SpanID().String()
	}

	// Populate callback fields if callback info is provided
	if callback != nil {
		req.CallbackEndpoint = callback.Endpoint
		req.CallbackToken = callback.Token

		// Convert mission context to TypedMap if provided
		if callback.Mission != nil {
			// Convert to map[string]any first
			missionJSON, err := json.Marshal(callback.Mission)
			if err != nil {
				result := agent.NewResult(task.ID)
				result.Fail(fmt.Errorf("failed to marshal mission context: %w", err))
				return result, nil
			}
			var missionMap map[string]any
			if err := json.Unmarshal(missionJSON, &missionMap); err != nil {
				result := agent.NewResult(task.ID)
				result.Fail(fmt.Errorf("failed to unmarshal mission context: %w", err))
				return result, nil
			}
			req.Mission = mapToTypedMap(missionMap)
		}

		// Convert target info to TypedMap if provided
		if callback.Target != nil {
			// Convert to map[string]any first
			targetJSON, err := json.Marshal(callback.Target)
			if err != nil {
				result := agent.NewResult(task.ID)
				result.Fail(fmt.Errorf("failed to marshal target info: %w", err))
				return result, nil
			}
			var targetMap map[string]any
			if err := json.Unmarshal(targetJSON, &targetMap); err != nil {
				result := agent.NewResult(task.ID)
				result.Fail(fmt.Errorf("failed to unmarshal target info: %w", err))
				return result, nil
			}
			req.Target = mapToTypedMap(targetMap)
		}

		// Set mission-scoped storage fields
		req.MissionRunId = callback.MissionRunID
		req.AgentRunId = callback.AgentRunID
		req.RunNumber = callback.RunNumber
	}

	// Send Execute RPC
	resp, err := c.client.Execute(ctx, req)
	if err != nil {
		result := agent.NewResult(task.ID)
		result.Fail(fmt.Errorf("agent execution failed: %w", err))
		return result, nil
	}

	// Check for errors in response
	if resp.Error != nil {
		result := agent.NewResult(task.ID)
		result.Fail(fmt.Errorf("%s: %s", resp.Error.Code, resp.Error.Message))
		return result, nil
	}

	// Convert proto result to internal result
	result := agent.ProtoToResult(resp.Result)
	result.TaskID = task.ID // Ensure task ID is set

	return result, nil
}

// unmarshalAgentResult unmarshals the agent result JSON with flexible Output handling.
// The SDK's Result.Output field can be any type (string, map, etc.) while Gibson's
// internal Result expects map[string]any. This function handles the conversion.
func unmarshalAgentResult(resultJSON string, taskID types.ID) (agent.Result, error) {
	// Use flexible struct to handle SDK's Output field which can be any type
	var rawResult struct {
		TaskID      string             `json:"task_id"`
		Status      string             `json:"status"`
		Output      any                `json:"output,omitempty"`
		Findings    []string           `json:"findings,omitempty"`
		Metadata    map[string]any     `json:"metadata,omitempty"`
		Error       *agent.ResultError `json:"error,omitempty"`
		StartedAt   string             `json:"started_at,omitempty"`
		CompletedAt string             `json:"completed_at,omitempty"`
	}
	if err := json.Unmarshal([]byte(resultJSON), &rawResult); err != nil {
		return agent.Result{}, fmt.Errorf("failed to unmarshal result: %w", err)
	}

	// Convert to Gibson Result, wrapping Output in a map if it's a string
	result := agent.NewResult(taskID)
	result.Status = agent.ResultStatus(rawResult.Status)

	// Handle Output - wrap non-map values in a map
	switch v := rawResult.Output.(type) {
	case map[string]any:
		result.Output = v
	case string:
		result.Output = map[string]any{"result": v}
	case nil:
		result.Output = make(map[string]any)
	default:
		result.Output = map[string]any{"data": v}
	}

	// Reconstruct error from serialized ResultError
	if rawResult.Error != nil {
		result.Error = rawResult.Error
	}

	return result, nil
}

// Shutdown cleanly terminates the agent and releases resources.
//
// This closes the underlying gRPC connection. After shutdown, the client
// should not be used for further operations.
func (c *GRPCAgentClient) Shutdown(ctx context.Context) error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// Health returns the current health status of the agent.
//
// This sends a Health RPC to the remote agent to check its status.
// If the RPC fails, the agent is considered unhealthy.
func (c *GRPCAgentClient) Health(ctx context.Context) types.HealthStatus {
	req := &agentpb.HealthRequest{}

	resp, err := c.client.Health(ctx, req)
	if err != nil {
		return types.Unhealthy(fmt.Sprintf("health check failed: %v", err))
	}

	// Convert proto health status to internal type
	// The proto HealthResponse wraps a commonpb.HealthStatus with fields: status, message, checked_at
	hs := resp.GetStatus()
	switch hs.GetStatus() {
	case "healthy":
		return types.Healthy(hs.GetMessage())
	case "degraded":
		return types.Degraded(hs.GetMessage())
	case "unhealthy":
		return types.Unhealthy(hs.GetMessage())
	default:
		return types.Unhealthy("unknown health status")
	}
}

// fetchDescriptor retrieves the agent descriptor from the remote agent via gRPC.
//
// This is called lazily when descriptor information is needed. The result is
// cached in c.descriptor to avoid repeated RPC calls.
// Note: Slots are fetched separately via fetchSlots()
func (c *GRPCAgentClient) fetchDescriptor(ctx context.Context) (*agent.AgentDescriptor, error) {
	if c.descriptor != nil {
		return c.descriptor, nil
	}

	req := &agentpb.GetDescriptorRequest{}
	resp, err := c.client.GetDescriptor(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to get descriptor: %w", err)
	}

	// Convert proto descriptor to internal type
	// Note: Slots field is nil initially and populated by fetchSlots()
	desc := &agent.AgentDescriptor{
		Name:           resp.Name,
		Version:        resp.Version,
		Description:    resp.Description,
		Capabilities:   resp.Capabilities,
		TargetTypes:    convertTargetTypes(resp.TargetTypes),     // Deprecated, for backward compat
		TargetSchemas:  convertTargetSchemas(resp.TargetSchemas), // New schema-based targets
		TechniqueTypes: convertTechniqueTypes(resp.TechniqueTypes),
		Slots:          nil, // Populated by fetchSlots()
		IsExternal:     true,
	}

	c.descriptor = desc
	return desc, nil
}

// fetchSlots retrieves the agent's slot definitions from the remote agent via gRPC.
//
// This is called lazily when slot information is needed. The result is
// cached in c.descriptor.Slots to avoid repeated RPC calls.
func (c *GRPCAgentClient) fetchSlots(ctx context.Context) error {
	if c.descriptor == nil {
		return fmt.Errorf("descriptor not loaded")
	}

	if c.descriptor.Slots != nil {
		return nil // Already fetched
	}

	req := &agentpb.GetSlotSchemaRequest{}
	resp, err := c.client.GetSlotSchema(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to get slot schema: %w", err)
	}

	// Convert proto slots to internal type
	c.descriptor.Slots = convertSlots(resp.Slots)
	return nil
}

// parseCommaSeparated is defined in health.go

// convertTargetTypes converts proto target types to internal TargetType
func convertTargetTypes(protoTypes []string) []TargetType {
	result := make([]TargetType, len(protoTypes))
	for i, t := range protoTypes {
		result[i] = TargetType(t)
	}
	return result
}

// convertTechniqueTypes converts proto technique types to internal TechniqueType
func convertTechniqueTypes(protoTypes []string) []TechniqueType {
	result := make([]TechniqueType, len(protoTypes))
	for i, t := range protoTypes {
		result[i] = TechniqueType(t)
	}
	return result
}

// convertSlots converts proto slot definitions to internal agent.SlotDefinition
func convertSlots(protoSlots []*agentpb.AgentSlotDefinition) []agent.SlotDefinition {
	if protoSlots == nil {
		return []agent.SlotDefinition{}
	}

	result := make([]agent.SlotDefinition, len(protoSlots))
	for i, ps := range protoSlots {
		result[i] = agent.SlotDefinition{
			Name:        ps.Name,
			Description: ps.Description,
			Required:    ps.Required,
			Default: agent.SlotConfig{
				Provider:    ps.DefaultConfig.Provider,
				Model:       ps.DefaultConfig.Model,
				Temperature: ps.DefaultConfig.Temperature,
				MaxTokens:   int(ps.DefaultConfig.MaxTokens),
			},
			Constraints: agent.SlotConstraints{
				MinContextWindow: int(ps.Constraints.MinContextWindow),
				RequiredFeatures: ps.Constraints.RequiredFeatures,
			},
		}
	}
	return result
}

// convertTargetSchemas converts proto target schemas to SDK TargetSchema types.
// It parses the schema_json field and converts it to the schema.JSON type used by the SDK.
func convertTargetSchemas(protoSchemas []*agentpb.TargetSchemaProto) []agent.TargetSchema {
	if protoSchemas == nil {
		return []agent.TargetSchema{}
	}

	result := make([]agent.TargetSchema, 0, len(protoSchemas))
	for _, ps := range protoSchemas {
		// Parse the JSON schema string into a schema.JSON object
		var schemaObj schema.JSON
		if ps.SchemaJson != "" {
			if err := json.Unmarshal([]byte(ps.SchemaJson), &schemaObj); err != nil {
				// Log error but continue - we don't want to fail the entire conversion
				// due to one malformed schema. The schema validation will catch this later.
				continue
			}
		}

		result = append(result, agent.TargetSchema{
			Type:        ps.Type,
			Version:     ps.Version,
			Schema:      schemaObj,
			Description: ps.Description,
		})
	}
	return result
}

// mapToTypedMap converts a map[string]any to a proto TypedMap.
func mapToTypedMap(m map[string]any) *commonpb.TypedMap {
	if m == nil {
		return nil
	}

	entries := make(map[string]*commonpb.TypedValue)
	for k, v := range m {
		entries[k] = anyToTypedValue(v)
	}

	return &commonpb.TypedMap{
		Entries: entries,
	}
}

// anyToTypedValue converts a Go any value to a proto TypedValue.
func anyToTypedValue(v any) *commonpb.TypedValue {
	if v == nil {
		return &commonpb.TypedValue{
			Kind: &commonpb.TypedValue_NullValue{
				NullValue: commonpb.NullValue_NULL_VALUE_UNSPECIFIED,
			},
		}
	}

	switch val := v.(type) {
	case string:
		return &commonpb.TypedValue{
			Kind: &commonpb.TypedValue_StringValue{StringValue: val},
		}
	case int:
		return &commonpb.TypedValue{
			Kind: &commonpb.TypedValue_IntValue{IntValue: int64(val)},
		}
	case int32:
		return &commonpb.TypedValue{
			Kind: &commonpb.TypedValue_IntValue{IntValue: int64(val)},
		}
	case int64:
		return &commonpb.TypedValue{
			Kind: &commonpb.TypedValue_IntValue{IntValue: val},
		}
	case float32:
		return &commonpb.TypedValue{
			Kind: &commonpb.TypedValue_DoubleValue{DoubleValue: float64(val)},
		}
	case float64:
		return &commonpb.TypedValue{
			Kind: &commonpb.TypedValue_DoubleValue{DoubleValue: val},
		}
	case bool:
		return &commonpb.TypedValue{
			Kind: &commonpb.TypedValue_BoolValue{BoolValue: val},
		}
	case []byte:
		return &commonpb.TypedValue{
			Kind: &commonpb.TypedValue_BytesValue{BytesValue: val},
		}
	case []any:
		items := make([]*commonpb.TypedValue, len(val))
		for i, item := range val {
			items[i] = anyToTypedValue(item)
		}
		return &commonpb.TypedValue{
			Kind: &commonpb.TypedValue_ArrayValue{
				ArrayValue: &commonpb.TypedArray{Items: items},
			},
		}
	case map[string]any:
		entries := make(map[string]*commonpb.TypedValue)
		for k, v := range val {
			entries[k] = anyToTypedValue(v)
		}
		return &commonpb.TypedValue{
			Kind: &commonpb.TypedValue_MapValue{
				MapValue: &commonpb.TypedMap{Entries: entries},
			},
		}
	default:
		// For unknown types, convert to string representation
		jsonBytes, _ := json.Marshal(v)
		return &commonpb.TypedValue{
			Kind: &commonpb.TypedValue_StringValue{StringValue: string(jsonBytes)},
		}
	}
}
