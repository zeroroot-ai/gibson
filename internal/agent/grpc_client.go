package agent

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/zero-day-ai/gibson/internal/database"
	"github.com/zero-day-ai/gibson/internal/types"
	agentpb "github.com/zero-day-ai/sdk/api/gen/gibson/agent/v1"
)

// GRPCAgentClient implements the Agent interface for gRPC-based agents.
//
// External agents allow extending Gibson with agents written in any language
// that implements the Gibson agent gRPC protocol. This enables:
// - Language-specific security tools (e.g., Python-based ML models)
// - Legacy tool integration
// - Third-party agent development
// - Distributed agent execution
//
// This client wraps a gRPC connection to a remote agent and translates between
// Gibson's internal Agent interface and the gRPC protocol. It fetches metadata
// from the agent via GetDescriptor and GetSlotSchema RPCs.
type GRPCAgentClient struct {
	conn   *grpc.ClientConn
	client agentpb.AgentServiceClient

	// Cached descriptor from GetDescriptor RPC
	// This avoids repeated gRPC calls for static metadata
	descriptor *AgentDescriptor
}

// NewGRPCAgentClient creates a new gRPC agent client connected to the specified address.
//
// This method establishes a gRPC connection and fetches the agent's descriptor
// to populate metadata (name, version, capabilities, etc.). The descriptor and
// slot information are cached to avoid repeated RPC calls.
//
// Parameters:
//   - address: The agent's gRPC endpoint (e.g., "localhost:50051")
//   - opts: Optional gRPC dial options (credentials, keepalive, interceptors, etc.)
//
// Returns an error if:
//   - The connection cannot be established
//   - The GetDescriptor RPC fails
//   - The GetSlotSchema RPC fails
//   - The descriptor or schemas cannot be parsed
//
// Example:
//
//	client, err := NewGRPCAgentClient(
//	    "localhost:50051",
//	    grpc.WithTransportCredentials(insecure.NewCredentials()),
//	)
func NewGRPCAgentClient(address string, opts ...grpc.DialOption) (*GRPCAgentClient, error) {
	// Add default options if none provided
	if len(opts) == 0 {
		opts = []grpc.DialOption{
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		}
	}

	// Establish gRPC connection
	// Note: Using deprecated Dial for better compatibility with testing (bufconn)
	//nolint:staticcheck // Dial provides better blocking behavior for connection establishment
	conn, err := grpc.Dial(address, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to dial gRPC endpoint %s: %w", address, err)
	}

	client := agentpb.NewAgentServiceClient(conn)

	// Create the agent client
	agentClient := &GRPCAgentClient{
		conn:   conn,
		client: client,
	}

	// Fetch descriptor to populate metadata
	// Use a background context with timeout for fetching metadata
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := agentClient.fetchDescriptor(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to fetch agent descriptor: %w", err)
	}

	// Fetch slots to complete the descriptor
	if err := agentClient.fetchSlots(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to fetch agent slots: %w", err)
	}

	return agentClient, nil
}

// Name returns the unique identifier for this agent
func (c *GRPCAgentClient) Name() string {
	if c.descriptor != nil {
		return c.descriptor.Name
	}
	return ""
}

// Version returns the semantic version of this agent
func (c *GRPCAgentClient) Version() string {
	if c.descriptor != nil {
		return c.descriptor.Version
	}
	return ""
}

// Description returns a human-readable description
func (c *GRPCAgentClient) Description() string {
	if c.descriptor != nil {
		return c.descriptor.Description
	}
	return ""
}

// Capabilities returns the list of capabilities
func (c *GRPCAgentClient) Capabilities() []string {
	if c.descriptor != nil {
		return c.descriptor.Capabilities
	}
	return []string{}
}

// TargetTypes returns the types of targets this agent supports
func (c *GRPCAgentClient) TargetTypes() []types.TargetType {
	if c.descriptor != nil {
		return c.descriptor.TargetTypes
	}
	return []types.TargetType{}
}

// TechniqueTypes returns the types of techniques this agent supports
func (c *GRPCAgentClient) TechniqueTypes() []types.TechniqueType {
	if c.descriptor != nil {
		return c.descriptor.TechniqueTypes
	}
	return []types.TechniqueType{}
}

// LLMSlots returns the LLM slot requirements
func (c *GRPCAgentClient) LLMSlots() []SlotDefinition {
	if c.descriptor != nil && c.descriptor.Slots != nil {
		return c.descriptor.Slots
	}
	return []SlotDefinition{}
}

// Execute runs the agent via gRPC.
//
// This method serializes the task to JSON and sends an Execute RPC to the remote
// agent. The result is received via gRPC and unmarshaled back to a Result struct.
//
// Note: The harness parameter is currently not used for standard execution.
// For harness callbacks (LLM access, tool execution, etc.), use the registry's
// GRPCAgentClient.ExecuteWithCallback() method instead, which provides callback
// endpoint configuration.
//
// Parameters:
//   - ctx: Context for request cancellation and timeouts
//   - task: The task to execute
//   - harness: Agent harness (not used in this implementation)
//
// Returns:
//   - Result with success/failure status and any findings
//   - Error only if the result could not be unmarshaled (execution errors are in Result.Error)
func (c *GRPCAgentClient) Execute(ctx context.Context, task Task, harness AgentHarness) (Result, error) {
	// Convert task to proto
	protoTask := TaskToProto(task)

	// Send Execute RPC
	timeoutMs := int64(task.Timeout.Milliseconds())
	req := &agentpb.ExecuteRequest{
		Task:      protoTask,
		TimeoutMs: timeoutMs,
	}

	resp, err := c.client.Execute(ctx, req)
	if err != nil {
		result := NewResult(task.ID)
		result.Fail(fmt.Errorf("gRPC agent execution failed: %w", err))
		return result, nil
	}

	// Check for errors in response
	if resp.Error != nil {
		result := NewResult(task.ID)
		result.Fail(fmt.Errorf("%s: %s", resp.Error.Code, resp.Error.Message))
		return result, nil
	}

	// Convert proto result to internal result
	result := ProtoToResult(resp.Result)
	result.TaskID = task.ID // Ensure task ID is set

	return result, nil
}

// Initialize initializes the gRPC agent.
//
// For gRPC agents, this is typically a no-op since the remote agent manages
// its own initialization. The agent's GetDescriptor and GetSlotSchema RPCs
// are called during NewGRPCAgentClient() to populate metadata.
//
// This method is provided for interface compatibility and could be extended
// in the future to send an Initialize RPC if needed.
func (c *GRPCAgentClient) Initialize(ctx context.Context, cfg AgentConfig) error {
	// gRPC agents manage their own initialization
	// Descriptor and slots are fetched during NewGRPCAgentClient()
	return nil
}

// Shutdown cleanly shuts down the gRPC connection.
//
// This closes the underlying gRPC connection to the agent. After shutdown,
// the client should not be used for further operations.
func (c *GRPCAgentClient) Shutdown(ctx context.Context) error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// Health checks the health of the gRPC agent.
//
// This sends a Health RPC to the remote agent to check its status.
// If the RPC fails, the agent is considered unhealthy.
//
// Returns a HealthStatus with one of three states:
//   - healthy: Agent is operational
//   - degraded: Agent is partially operational
//   - unhealthy: Agent is not operational or unreachable
func (c *GRPCAgentClient) Health(ctx context.Context) types.HealthStatus {
	req := &agentpb.HealthRequest{}

	resp, err := c.client.Health(ctx, req)
	if err != nil {
		return types.Unhealthy(fmt.Sprintf("gRPC health check failed: %v", err))
	}

	// Convert proto HealthResponse → HealthStatus → internal type
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

// Close closes the gRPC connection
func (c *GRPCAgentClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// Connection returns the underlying gRPC connection.
// This is useful for creating StreamClients directly.
func (c *GRPCAgentClient) Connection() *grpc.ClientConn {
	return c.conn
}

// StreamExecute starts a bidirectional streaming execution.
// Returns a StreamClient for sending steering messages and receiving events.
// Falls back to regular Execute if the agent doesn't support streaming.
func (c *GRPCAgentClient) StreamExecute(ctx context.Context, task Task, sessionID types.ID) (*StreamClient, error) {
	// Check if we have a valid connection
	if c.conn == nil {
		return nil, fmt.Errorf("gRPC connection not established")
	}

	// Create the StreamClient, which internally establishes the bidirectional stream
	streamClient, err := NewStreamClient(ctx, c.conn, c.Name(), sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to create stream client: %w", err)
	}

	// Send the initial task with autonomous mode as default
	if err := streamClient.StartWithTask(task, database.AgentModeAutonomous); err != nil {
		streamClient.Close()
		return nil, fmt.Errorf("failed to start execution: %w", err)
	}

	return streamClient, nil
}

// SupportsStreaming checks if the agent supports bidirectional streaming.
// This can be called before StreamExecute to determine if fallback is needed.
func (c *GRPCAgentClient) SupportsStreaming() bool {
	// For now, assume all gRPC agents support streaming
	// In the future, this could check agent capabilities via GetDescriptor
	return c.conn != nil
}

// fetchDescriptor retrieves the agent descriptor from the remote agent via gRPC.
//
// This is called during NewGRPCAgentClient() to populate metadata. The result is
// cached in c.descriptor to avoid repeated RPC calls.
// Note: Slots are fetched separately via fetchSlots()
func (c *GRPCAgentClient) fetchDescriptor(ctx context.Context) error {
	if c.descriptor != nil {
		return nil
	}

	req := &agentpb.GetDescriptorRequest{}
	resp, err := c.client.GetDescriptor(ctx, req)
	if err != nil {
		return fmt.Errorf("GetDescriptor RPC failed: %w", err)
	}

	// Convert proto descriptor to internal type
	// Note: Slots field is nil initially and populated by fetchSlots()
	c.descriptor = &AgentDescriptor{
		Name:           resp.Name,
		Version:        resp.Version,
		Description:    resp.Description,
		Capabilities:   resp.Capabilities,
		TargetTypes:    convertTargetTypes(resp.TargetTypes),
		TechniqueTypes: convertTechniqueTypes(resp.TechniqueTypes),
		Slots:          nil, // Populated by fetchSlots()
		IsExternal:     true,
	}

	return nil
}

// fetchSlots retrieves the agent's slot definitions from the remote agent via gRPC.
//
// This is called during NewGRPCAgentClient() after fetchDescriptor(). The result is
// cached in c.descriptor.Slots to avoid repeated RPC calls.
func (c *GRPCAgentClient) fetchSlots(ctx context.Context) error {
	if c.descriptor == nil {
		return fmt.Errorf("descriptor not loaded - call fetchDescriptor first")
	}

	if c.descriptor.Slots != nil {
		return nil // Already fetched
	}

	req := &agentpb.GetSlotSchemaRequest{}
	resp, err := c.client.GetSlotSchema(ctx, req)
	if err != nil {
		return fmt.Errorf("GetSlotSchema RPC failed: %w", err)
	}

	// Convert proto slots to internal type
	c.descriptor.Slots = convertSlots(resp.Slots)
	return nil
}

// convertTargetTypes converts proto target types to internal types.TargetType
func convertTargetTypes(protoTypes []string) []types.TargetType {
	result := make([]types.TargetType, len(protoTypes))
	for i, t := range protoTypes {
		result[i] = types.TargetType(t)
	}
	return result
}

// convertTechniqueTypes converts proto technique types to internal types.TechniqueType
func convertTechniqueTypes(protoTypes []string) []types.TechniqueType {
	result := make([]types.TechniqueType, len(protoTypes))
	for i, t := range protoTypes {
		result[i] = types.TechniqueType(t)
	}
	return result
}

// convertSlots converts proto slot definitions to internal SlotDefinition
func convertSlots(protoSlots []*agentpb.AgentSlotDefinition) []SlotDefinition {
	if protoSlots == nil {
		return []SlotDefinition{}
	}

	result := make([]SlotDefinition, len(protoSlots))
	for i, ps := range protoSlots {
		slot := SlotDefinition{
			Name:        ps.Name,
			Description: ps.Description,
			Required:    ps.Required,
		}

		// Handle optional DefaultConfig
		if ps.DefaultConfig != nil {
			slot.Default = SlotConfig{
				Provider:    ps.DefaultConfig.Provider,
				Model:       ps.DefaultConfig.Model,
				Temperature: ps.DefaultConfig.Temperature,
				MaxTokens:   int(ps.DefaultConfig.MaxTokens),
			}
		}

		// Handle optional Constraints
		if ps.Constraints != nil {
			slot.Constraints = SlotConstraints{
				MinContextWindow: int(ps.Constraints.MinContextWindow),
				RequiredFeatures: ps.Constraints.RequiredFeatures,
			}
		}

		result[i] = slot
	}
	return result
}
