package tool

import (
	"context"
	"fmt"
	"time"

	"github.com/zero-day-ai/gibson/internal/types"
	"github.com/zero-day-ai/sdk/api/gen/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	protobuf "google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

// GRPCToolClient wraps a gRPC connection to implement the Tool interface.
// It communicates with external gRPC tools using the ToolService proto definition.
//
// The client handles:
// - gRPC connection management
// - Protocol buffer marshaling/unmarshaling
// - Proto message type resolution and dynamic creation
// - Health check integration with gRPC health protocol
type GRPCToolClient struct {
	name              string
	description       string
	version           string
	tags              []string
	inputMessageType  string
	outputMessageType string
	conn              *grpc.ClientConn
	client            proto.ToolServiceClient
}

// NewGRPCToolClient creates a new GRPCToolClient by connecting to a gRPC tool service.
// It dials the endpoint, creates the client, and fetches the tool descriptor to populate
// metadata and schemas.
//
// Parameters:
//   - endpoint: gRPC server address (e.g., "localhost:50051")
//   - opts: Optional gRPC dial options (uses insecure credentials if none provided)
//
// Returns error if connection fails or GetDescriptor RPC fails.
func NewGRPCToolClient(endpoint string, opts ...grpc.DialOption) (*GRPCToolClient, error) {
	// Use insecure credentials if no options provided
	if len(opts) == 0 {
		opts = []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	}

	// Dial the gRPC server
	// Note: Using deprecated Dial for better compatibility with testing (bufconn)
	//nolint:staticcheck // Dial provides better blocking behavior for connection establishment
	conn, err := grpc.Dial(endpoint, opts...)
	if err != nil {
		return nil, types.WrapError(ErrToolExecutionFailed, fmt.Sprintf("failed to dial gRPC endpoint %q", endpoint), err)
	}

	// Create the ToolService client
	client := proto.NewToolServiceClient(conn)

	// Fetch the tool descriptor
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	descriptor, err := client.GetDescriptor(ctx, &proto.ToolGetDescriptorRequest{})
	if err != nil {
		conn.Close()
		return nil, types.WrapError(ErrToolExecutionFailed, "failed to get tool descriptor", err)
	}

	// TODO: Once SDK task 1.3 is complete and tool.proto has input_message_type/output_message_type fields,
	// use descriptor.GetInputMessageType() and descriptor.GetOutputMessageType() instead.
	// For now, default to google.protobuf.Struct as the proto interface.
	inputMsgType := "google.protobuf.Struct"
	outputMsgType := "google.protobuf.Struct"

	return &GRPCToolClient{
		name:              descriptor.GetName(),
		description:       descriptor.GetDescription(),
		version:           descriptor.GetVersion(),
		tags:              descriptor.GetTags(),
		inputMessageType:  inputMsgType,
		outputMessageType: outputMsgType,
		conn:              conn,
		client:            client,
	}, nil
}

// Name returns the unique identifier for this tool
func (c *GRPCToolClient) Name() string {
	return c.name
}

// Description returns a human-readable description of what this tool does
func (c *GRPCToolClient) Description() string {
	return c.description
}

// Version returns the semantic version of this tool
func (c *GRPCToolClient) Version() string {
	return c.version
}

// Tags returns a list of tags for categorization and discovery
func (c *GRPCToolClient) Tags() []string {
	return c.tags
}

// InputMessageType returns the fully-qualified proto message type name for input
func (c *GRPCToolClient) InputMessageType() string {
	return c.inputMessageType
}

// OutputMessageType returns the fully-qualified proto message type name for output
func (c *GRPCToolClient) OutputMessageType() string {
	return c.outputMessageType
}

// ExecuteProto runs the tool via gRPC with proto message input.
// It marshals the proto to JSON, makes the gRPC call, and unmarshals the JSON output back to proto.
func (c *GRPCToolClient) ExecuteProto(ctx context.Context, input protobuf.Message) (protobuf.Message, error) {
	// Marshal proto input to JSON
	marshaler := protojson.MarshalOptions{
		UseProtoNames: true,
		EmitUnpopulated: false,
	}
	inputJSON, err := marshaler.Marshal(input)
	if err != nil {
		return nil, types.WrapError(ErrToolInvalidInput, "failed to marshal proto input to JSON", err)
	}

	// Create the gRPC request
	req := &proto.ToolExecuteRequest{
		InputJson: string(inputJSON),
	}

	// Make the gRPC call
	resp, err := c.client.Execute(ctx, req)
	if err != nil {
		return nil, types.WrapError(ErrToolExecutionFailed, fmt.Sprintf("gRPC tool %q execution failed", c.name), err)
	}

	// Check for proto-level error in response
	if protoErr := resp.GetError(); protoErr != nil {
		gibsonErr := &types.GibsonError{
			Code:      types.ErrorCode(protoErr.GetCode()),
			Message:   protoErr.GetMessage(),
			Retryable: protoErr.GetRetryable(),
		}
		return nil, gibsonErr
	}

	// Create output proto message dynamically
	outputType, err := protoregistry.GlobalTypes.FindMessageByName(protoreflect.FullName(c.outputMessageType))
	if err != nil {
		return nil, types.WrapError(ErrToolInvalidOutput, fmt.Sprintf("failed to find output message type %q", c.outputMessageType), err)
	}

	output := outputType.New().Interface()

	// Unmarshal JSON to proto
	unmarshaler := protojson.UnmarshalOptions{
		DiscardUnknown: true,
	}
	if err := unmarshaler.Unmarshal([]byte(resp.GetOutputJson()), output); err != nil {
		return nil, types.WrapError(ErrToolInvalidOutput, "failed to unmarshal output JSON to proto", err)
	}

	return output, nil
}

// Health returns the current health status of this tool by calling the gRPC Health endpoint.
func (c *GRPCToolClient) Health(ctx context.Context) types.HealthStatus {
	// Make health check call with timeout
	healthCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	resp, err := c.client.Health(healthCtx, &proto.ToolHealthRequest{})
	if err != nil {
		return types.Unhealthy(fmt.Sprintf("gRPC health check failed: %v", err))
	}

	// Convert proto HealthStatus to internal type
	return types.HealthStatus{
		State:     types.HealthState(resp.GetStatus()),
		Message:   resp.GetMessage(),
		CheckedAt: time.UnixMilli(resp.GetCheckedAt()),
	}
}

// GetConn returns the underlying gRPC connection for streaming operations.
func (c *GRPCToolClient) GetConn() *grpc.ClientConn {
	return c.conn
}

// Close closes the underlying gRPC connection.
func (c *GRPCToolClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}
