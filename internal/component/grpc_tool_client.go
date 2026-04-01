package component

import (
	"context"
	"fmt"
	"log/slog"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	protobuf "google.golang.org/protobuf/proto"

	"github.com/zero-day-ai/gibson/internal/types"
	toolpb "github.com/zero-day-ai/sdk/api/gen/gibson/tool/v1"
	"github.com/zero-day-ai/sdk/protoresolver"
)

// GRPCToolClient implements tool.Tool interface for tools discovered via the component registry.
//
// This client wraps a gRPC connection to a remote tool and translates between
// Gibson's internal tool.Tool interface and the gRPC protocol. It uses ComponentInfo
// from the component registry to populate tool metadata (name, version, tags, etc.).
//
// Key features:
// - Implements full tool.Tool interface for remote gRPC tools
// - Parses tags from ComponentInfo metadata
// - Delegates execution to remote tool via gRPC
// - Handles descriptor caching and health checks
// - Proto-based execution using ExecuteProto
type GRPCToolClient struct {
	conn     *grpc.ClientConn
	client   toolpb.ToolServiceClient
	info     ComponentInfo
	resolver protoresolver.ProtoResolver

	// Cached descriptor from GetDescriptor RPC
	// This avoids repeated gRPC calls for static metadata
	descriptor *toolDescriptor
}

// toolDescriptor holds cached metadata from the tool's GetDescriptor RPC.
// This struct is internal and used only for caching purposes.
type toolDescriptor struct {
	Name              string
	Description       string
	Version           string
	Tags              []string
	InputMessageType  string
	OutputMessageType string
}

// NewGRPCToolClient creates a new GRPCToolClient wrapping an existing gRPC connection.
//
// The connection should already be established and ready to use. The ServiceInfo
// provides metadata about the tool (name, version, endpoint, tags, etc.)
// that was discovered from the etcd registry.
//
// Parameters:
//   - conn: Established gRPC connection to the tool
//   - info: ComponentInfo from the component registry with tool metadata
//   - resolver: ProtoResolver for resolving proto message types
//
// Returns a GRPCToolClient that implements the tool.Tool interface.
func NewGRPCToolClient(conn *grpc.ClientConn, info ComponentInfo, resolver protoresolver.ProtoResolver) *GRPCToolClient {
	return &GRPCToolClient{
		conn:     conn,
		client:   toolpb.NewToolServiceClient(conn),
		info:     info,
		resolver: resolver,
	}
}

// Name returns the tool name from ServiceInfo
func (c *GRPCToolClient) Name() string {
	return c.info.Name
}

// Description returns the tool description.
//
// If available, this is retrieved from the cached descriptor (which comes from
// the tool's GetDescriptor RPC). Otherwise, falls back to metadata or empty string.
func (c *GRPCToolClient) Description() string {
	if c.descriptor != nil {
		return c.descriptor.Description
	}

	// Try to get from metadata
	if desc, ok := c.info.Metadata["description"]; ok {
		return desc
	}

	return ""
}

// Version returns the tool version from ServiceInfo
func (c *GRPCToolClient) Version() string {
	return c.info.Version
}

// Tags returns the tool's tags from ServiceInfo metadata.
//
// The metadata should contain a "tags" key with comma-separated values.
// For example: "network,scanner,recon"
func (c *GRPCToolClient) Tags() []string {
	if c.descriptor != nil {
		return c.descriptor.Tags
	}

	return parseCommaSeparated(c.info.Metadata["tags"])
}

// InputMessageType returns the fully-qualified proto message type name for input
func (c *GRPCToolClient) InputMessageType() string {
	slog.Info("GRPCToolClient.InputMessageType called",
		"tool", c.info.Name,
		"descriptor_nil", c.descriptor == nil,
		"metadata", c.info.Metadata)

	// Ensure descriptor is loaded
	if c.descriptor == nil {
		ctx := context.Background()
		desc, err := c.fetchDescriptor(ctx)
		if err != nil {
			slog.Error("fetchDescriptor failed", "tool", c.info.Name, "error", err)
		}
		slog.Info("fetchDescriptor result",
			"tool", c.info.Name,
			"desc_nil", desc == nil,
			"input_type", func() string {
				if desc != nil {
					return desc.InputMessageType
				}
				return ""
			}())
	}

	if c.descriptor != nil {
		return c.descriptor.InputMessageType
	}

	return ""
}

// OutputMessageType returns the fully-qualified proto message type name for output
func (c *GRPCToolClient) OutputMessageType() string {
	// Ensure descriptor is loaded
	if c.descriptor == nil {
		ctx := context.Background()
		_, _ = c.fetchDescriptor(ctx)
	}

	if c.descriptor != nil {
		return c.descriptor.OutputMessageType
	}

	return ""
}

// ExecuteProto runs the tool with proto message input and returns proto message output.
//
// This method:
//  1. Marshals the proto input to JSON
//  2. Sends an Execute RPC to the remote tool
//  3. Receives the JSON result via gRPC
//  4. Unmarshals JSON to proto message and returns it
//
// Returns an error if execution fails or proto conversion fails.
func (c *GRPCToolClient) ExecuteProto(ctx context.Context, input protobuf.Message) (protobuf.Message, error) {
	// Marshal proto input to JSON
	marshaler := protojson.MarshalOptions{
		UseProtoNames:   true,
		EmitUnpopulated: false,
	}
	inputJSON, err := marshaler.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal proto input: %w", err)
	}

	// Send Execute RPC
	req := &toolpb.ExecuteRequest{
		InputJson: string(inputJSON),
		TimeoutMs: 0, // Use tool's default timeout
	}

	resp, err := c.client.Execute(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("tool execution failed: %w", err)
	}

	// Check for errors in response
	if resp.Error != nil {
		return nil, fmt.Errorf("%s: %s", resp.Error.Code, resp.Error.Message)
	}

	// Get output message type
	outputType := c.OutputMessageType()
	if outputType == "" {
		return nil, fmt.Errorf("output message type not available")
	}

	// Initialize resolver if nil (backward compatibility)
	if c.resolver == nil {
		c.resolver = protoresolver.NewDefaultProtoResolver(protoresolver.DefaultConfig())
	}

	// Use ProtoResolver to resolve output type
	output, err := c.resolver.ResolveOutputType(ctx, outputType, c.Metadata())
	if err != nil {
		return nil, fmt.Errorf("failed to resolve output type: %w", err)
	}

	// Unmarshal JSON to proto
	unmarshaler := protojson.UnmarshalOptions{
		DiscardUnknown: true,
	}
	if err := unmarshaler.Unmarshal([]byte(resp.OutputJson), output); err != nil {
		return nil, fmt.Errorf("failed to unmarshal output: %w", err)
	}

	return output, nil
}

// Health returns the current health status of the tool.
//
// This sends a Health RPC to the remote tool to check its status.
// If the RPC fails, the tool is considered unhealthy.
func (c *GRPCToolClient) Health(ctx context.Context) types.HealthStatus {
	req := &toolpb.HealthRequest{}

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

// fetchDescriptor retrieves the tool descriptor from the remote tool via gRPC.
//
// This is called lazily when descriptor information is needed. The result is
// cached in c.descriptor to avoid repeated RPC calls.
//
// Proto message types are retrieved from ComponentInfo metadata (populated during
// registration) since the gRPC GetDescriptor response doesn't include them.
func (c *GRPCToolClient) fetchDescriptor(ctx context.Context) (*toolDescriptor, error) {
	if c.descriptor != nil {
		return c.descriptor, nil
	}

	req := &toolpb.GetDescriptorRequest{}
	resp, err := c.client.GetDescriptor(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to get descriptor: %w", err)
	}

	// Get proto message types from ComponentInfo metadata (set during tool registration)
	// The SDK's serve.Tool() populates these in metadata when registering with the platform.
	inputMsgType := c.info.Metadata["input_message_type"]
	outputMsgType := c.info.Metadata["output_message_type"]

	// Log metadata for debugging
	slog.Info("fetchDescriptor: checking ServiceInfo metadata",
		"tool", c.info.Name,
		"metadata", c.info.Metadata,
		"input_message_type", inputMsgType,
		"output_message_type", outputMsgType)

	// Fallback to google.protobuf.Struct if metadata is missing (legacy tools)
	if inputMsgType == "" {
		inputMsgType = "google.protobuf.Struct"
	}
	if outputMsgType == "" {
		outputMsgType = "google.protobuf.Struct"
	}

	// Build descriptor
	desc := &toolDescriptor{
		Name:              resp.Name,
		Description:       resp.Description,
		Version:           resp.Version,
		Tags:              resp.Tags,
		InputMessageType:  inputMsgType,
		OutputMessageType: outputMsgType,
	}

	c.descriptor = desc
	return desc, nil
}

// GetConn returns the underlying gRPC connection for streaming operations.
func (c *GRPCToolClient) GetConn() *grpc.ClientConn {
	return c.conn
}

// Metadata returns the tool's metadata from the ServiceInfo.
// This includes file_descriptor_set, input_message_type, output_message_type, etc.
func (c *GRPCToolClient) Metadata() map[string]string {
	return c.info.Metadata
}
