package component

import (
	"context"
	"encoding/json"
	"fmt"

	"google.golang.org/grpc"

	"github.com/zero-day-ai/gibson/internal/plugin"
	"github.com/zero-day-ai/gibson/internal/types"
	commonpb "github.com/zero-day-ai/sdk/api/gen/commonpb"
	proto "github.com/zero-day-ai/sdk/api/gen/proto"
	"github.com/zero-day-ai/sdk/schema"
)

// GRPCPluginClient implements plugin.Plugin interface for plugins discovered via the component registry.
//
// This client wraps a gRPC connection to a remote plugin and translates between
// Gibson's internal plugin.Plugin interface and the gRPC protocol. It uses ComponentInfo
// from the component registry to populate plugin metadata (name, version, etc.).
//
// Key features:
// - Implements full plugin.Plugin interface for remote gRPC plugins
// - Caches method descriptors to avoid repeated gRPC calls
// - Handles JSON marshaling/unmarshaling for Query RPC
// - Validates method exists before invoking Query RPC
type GRPCPluginClient struct {
	conn   *grpc.ClientConn
	client proto.PluginServiceClient
	info   ComponentInfo

	// Cached methods from ListMethods RPC
	// This avoids repeated gRPC calls for static metadata
	methods []plugin.MethodDescriptor
}

// NewGRPCPluginClient creates a new GRPCPluginClient wrapping an existing gRPC connection.
//
// The connection should already be established and ready to use. The ComponentInfo
// provides metadata about the plugin (name, version) that was discovered
// from the component registry.
//
// Parameters:
//   - conn: Established gRPC connection to the plugin
//   - info: ComponentInfo from the component registry with plugin metadata
//
// Returns a GRPCPluginClient that implements the plugin.Plugin interface.
func NewGRPCPluginClient(conn *grpc.ClientConn, info ComponentInfo) *GRPCPluginClient {
	return &GRPCPluginClient{
		conn:   conn,
		client: proto.NewPluginServiceClient(conn),
		info:   info,
	}
}

// Name returns the plugin name from ServiceInfo
func (c *GRPCPluginClient) Name() string {
	return c.info.Name
}

// Version returns the plugin version from ServiceInfo
func (c *GRPCPluginClient) Version() string {
	return c.info.Version
}

// Initialize prepares the plugin for use with the given configuration.
//
// This sends an Initialize RPC to the remote plugin with the configuration
// marshaled as JSON. The plugin is responsible for parsing and applying the
// configuration.
//
// Returns an error if the RPC fails or the plugin returns an error.
func (c *GRPCPluginClient) Initialize(ctx context.Context, cfg plugin.PluginConfig) error {
	// Marshal configuration to JSON
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal plugin config: %w", err)
	}

	// Send Initialize RPC
	req := &proto.PluginInitializeRequest{
		ConfigJson: string(cfgJSON),
	}

	resp, err := c.client.Initialize(ctx, req)
	if err != nil {
		return fmt.Errorf("plugin initialization failed: %w", err)
	}

	// Check for errors in response
	if resp.Error != nil {
		return fmt.Errorf("%s: %s", resp.Error.Code, resp.Error.Message)
	}

	return nil
}

// Shutdown gracefully stops the plugin and releases resources.
//
// This sends a Shutdown RPC to the remote plugin and closes the underlying
// gRPC connection. After shutdown, the client should not be used for further
// operations.
func (c *GRPCPluginClient) Shutdown(ctx context.Context) error {
	// Send Shutdown RPC
	req := &proto.PluginShutdownRequest{}

	resp, err := c.client.Shutdown(ctx, req)
	if err != nil {
		// Try to close connection even if RPC fails
		if c.conn != nil {
			_ = c.conn.Close()
		}
		return fmt.Errorf("plugin shutdown failed: %w", err)
	}

	// Check for errors in response
	if resp.Error != nil {
		// Try to close connection even if plugin reports error
		if c.conn != nil {
			_ = c.conn.Close()
		}
		return fmt.Errorf("%s: %s", resp.Error.Code, resp.Error.Message)
	}

	// Close the connection
	if c.conn != nil {
		if err := c.conn.Close(); err != nil {
			return fmt.Errorf("failed to close connection: %w", err)
		}
	}

	return nil
}

// Query executes a plugin method with the given parameters.
//
// This method:
//  1. Fetches and caches methods on first call (if not already cached)
//  2. Validates the method exists
//  3. Marshals parameters to JSON
//  4. Sends Query RPC to the remote plugin
//  5. Unmarshals and returns the result
//
// Returns an error if:
//   - The method doesn't exist
//   - Parameter marshaling fails
//   - The RPC fails
//   - The plugin returns an error
//   - Result unmarshaling fails
func (c *GRPCPluginClient) Query(ctx context.Context, method string, params map[string]any) (any, error) {
	// Ensure methods are loaded (fetches on first call)
	if c.methods == nil {
		if err := c.fetchMethods(ctx); err != nil {
			return nil, fmt.Errorf("failed to fetch plugin methods: %w", err)
		}
	}

	// Validate method exists
	methodExists := false
	for _, m := range c.methods {
		if m.Name == method {
			methodExists = true
			break
		}
	}
	if !methodExists {
		return nil, fmt.Errorf("method '%s' not found in plugin '%s'", method, c.info.Name)
	}

	// Marshal parameters to JSON
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal query params: %w", err)
	}

	// Send Query RPC
	req := &proto.PluginQueryRequest{
		Method:     method,
		ParamsJson: string(paramsJSON),
		TimeoutMs:  0, // Use default timeout
	}

	resp, err := c.client.Query(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("plugin query failed: %w", err)
	}

	// Check for errors in response
	if resp.Error != nil {
		return nil, fmt.Errorf("%s: %s", resp.Error.Code, resp.Error.Message)
	}

	// Unmarshal result from JSON
	// We return the raw unmarshaled value (any type)
	var result any
	if resp.ResultJson != "" {
		if err := json.Unmarshal([]byte(resp.ResultJson), &result); err != nil {
			return nil, fmt.Errorf("failed to unmarshal query result: %w", err)
		}
	}

	return result, nil
}

// Methods returns the list of available methods this plugin supports.
//
// This fetches methods from the remote plugin on first call and caches them
// to avoid repeated RPC calls.
//
// Returns an empty slice if method fetching fails.
func (c *GRPCPluginClient) Methods() []plugin.MethodDescriptor {
	// Ensure methods are loaded
	if c.methods == nil {
		ctx := context.Background()
		_ = c.fetchMethods(ctx)
	}

	// Return cached methods (may be nil if fetch failed)
	if c.methods == nil {
		return []plugin.MethodDescriptor{}
	}

	return c.methods
}

// Health returns the current health status of the plugin.
//
// This sends a Health RPC to the remote plugin to check its status.
// If the RPC fails, the plugin is considered unhealthy.
func (c *GRPCPluginClient) Health(ctx context.Context) types.HealthStatus {
	req := &proto.PluginHealthRequest{}

	resp, err := c.client.Health(ctx, req)
	if err != nil {
		return types.Unhealthy(fmt.Sprintf("health check failed: %v", err))
	}

	// Convert proto health status to internal type
	// The proto HealthStatus has a "state" field with values: "healthy", "degraded", "unhealthy"
	switch resp.Status {
	case "healthy":
		return types.Healthy(resp.Message)
	case "degraded":
		return types.Degraded(resp.Message)
	case "unhealthy":
		return types.Unhealthy(resp.Message)
	default:
		return types.Unhealthy("unknown health status")
	}
}

// fetchMethods retrieves the method list from the remote plugin via gRPC.
//
// This is called lazily when method information is needed. The result is
// cached in c.methods to avoid repeated RPC calls.
func (c *GRPCPluginClient) fetchMethods(ctx context.Context) error {
	if c.methods != nil {
		return nil // Already fetched
	}

	req := &proto.PluginListMethodsRequest{}
	resp, err := c.client.ListMethods(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to list plugin methods: %w", err)
	}

	// Convert proto method descriptors to internal type
	c.methods = convertMethodDescriptors(resp.Methods)
	return nil
}

// convertMethodDescriptors converts proto method descriptors to internal plugin.MethodDescriptor
func convertMethodDescriptors(protoMethods []*proto.PluginMethodDescriptor) []plugin.MethodDescriptor {
	if protoMethods == nil {
		return []plugin.MethodDescriptor{}
	}

	result := make([]plugin.MethodDescriptor, len(protoMethods))
	for i, pm := range protoMethods {
		result[i] = plugin.MethodDescriptor{
			Name:         pm.Name,
			Description:  pm.Description,
			InputSchema:  convertJSONSchema(pm.InputSchema),
			OutputSchema: convertJSONSchema(pm.OutputSchema),
		}
	}
	return result
}

// convertJSONSchema converts proto JSONSchema to SDK schema.JSON
func convertJSONSchema(protoSchema *commonpb.JSONSchema) schema.JSON {
	if protoSchema == nil {
		return schema.JSON{}
	}

	// The proto JSONSchema is just a JSON string - unmarshal it
	var result schema.JSON
	if protoSchema.Json != "" {
		if err := json.Unmarshal([]byte(protoSchema.Json), &result); err != nil {
			// If unmarshaling fails, return empty schema
			return schema.JSON{}
		}
	}

	return result
}
