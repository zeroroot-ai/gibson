// Package client provides a client library for connecting to the Gibson daemon.
//
// The client package implements the client-side of the daemon-client architecture,
// allowing CLI commands to connect to the running daemon and invoke operations via gRPC.
// It handles connection management, streaming RPCs, and provides high-level convenience
// methods for common daemon operations.
package client

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/zero-day-ai/gibson/internal/daemon"
	"github.com/zero-day-ai/gibson/internal/daemon/api"
)

// Client represents a connection to the Gibson daemon.
//
// The client wraps a gRPC connection and provides high-level methods for
// interacting with the daemon. It supports both Unix socket and TCP connections,
// automatically handling the appropriate connection setup based on address format.
//
// Example usage:
//
//	// Connect directly to an address
//	client, err := Connect(ctx, "unix:///home/user/.gibson/daemon.sock")
//	if err != nil {
//	    return err
//	}
//	defer client.Close()
//
//	// Or connect using daemon info file
//	client, err := ConnectFromInfo(ctx, "/home/user/.gibson/daemon.json")
//	if err != nil {
//	    return err
//	}
//	defer client.Close()
//
//	// Use the client
//	status, err := client.Status(ctx)
//	if err != nil {
//	    return err
//	}
//	fmt.Printf("Daemon running: %v\n", status.Running)
type Client struct {
	// conn is the underlying gRPC connection
	conn *grpc.ClientConn

	// daemon is the gRPC service client for daemon operations
	daemon api.DaemonServiceClient
}

// Connect establishes a connection to the Gibson daemon at the specified address.
//
// The address can be either:
//   - Unix socket: "unix:///path/to/socket" (recommended for local connections)
//   - TCP: "localhost:50002" or "127.0.0.1:50002"
//
// Unix socket connections are preferred for security and performance when connecting
// to a local daemon. TCP connections are useful for remote daemon connections or
// container environments where Unix sockets are not available.
//
// Parameters:
//   - ctx: Context with timeout for connection establishment
//   - address: Daemon address (unix:// or TCP host:port)
//
// Returns:
//   - *Client: Connected client instance
//   - error: Non-nil if connection fails
//
// Example:
//
//	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
//	defer cancel()
//
//	client, err := Connect(ctx, "unix:///home/user/.gibson/daemon.sock")
//	if err != nil {
//	    return fmt.Errorf("failed to connect to daemon: %w", err)
//	}
//	defer client.Close()
func Connect(ctx context.Context, address string) (*Client, error) {
	if address == "" {
		return nil, fmt.Errorf("daemon address cannot be empty")
	}

	// Add default timeout if context has none
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}

	// Determine connection type and format address correctly
	var target string
	if strings.HasPrefix(address, "unix://") {
		// Unix socket - use the path directly
		target = address
	} else if strings.HasPrefix(address, "/") {
		// Unix socket path without scheme
		target = "unix://" + address
	} else {
		// TCP address (host:port)
		target = address
	}

	// Establish gRPC connection
	// Note: grpc.NewClient doesn't actually connect until the first RPC.
	// We use DialContext for immediate connection validation.
	conn, err := grpc.DialContext(
		ctx,
		target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(), // Block until connection is ready or context timeout
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to daemon at %s: %w", address, err)
	}

	// Create daemon service client
	daemonClient := api.NewDaemonServiceClient(conn)

	return &Client{
		conn:   conn,
		daemon: daemonClient,
	}, nil
}

// ConnectFromInfo reads daemon connection information from a JSON file and connects.
//
// This function reads the daemon.json file (created by WriteDaemonInfo) to discover
// the daemon's gRPC address, then establishes a connection using that address.
// This is the recommended way for CLI commands to connect to the daemon, as it
// automatically handles address discovery.
//
// Parameters:
//   - ctx: Context with timeout for connection
//   - infoPath: Path to daemon.json file (typically ~/.gibson/daemon.json)
//
// Returns:
//   - *Client: Connected client instance
//   - error: Non-nil if file read or connection fails
//
// Example:
//
//	ctx := context.Background()
//	client, err := ConnectFromInfo(ctx, "/home/user/.gibson/daemon.json")
//	if err != nil {
//	    if os.IsNotExist(err) {
//	        return fmt.Errorf("daemon not running")
//	    }
//	    return err
//	}
//	defer client.Close()
func ConnectFromInfo(ctx context.Context, infoPath string) (*Client, error) {
	if infoPath == "" {
		return nil, fmt.Errorf("daemon info path cannot be empty")
	}

	// Read daemon connection info from file
	info, err := daemon.ReadDaemonInfo(infoPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read daemon info: %w", err)
	}

	// Prefer Unix socket if available, otherwise use gRPC address
	address := info.GRPCAddress
	if info.SocketPath != "" {
		address = info.SocketPath
	}

	// Connect using the discovered address
	client, err := Connect(ctx, address)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to daemon (PID %d): %w", info.PID, err)
	}

	return client, nil
}

// Close closes the connection to the daemon.
//
// This method should be called when the client is no longer needed, typically
// using defer immediately after successful connection:
//
//	client, err := Connect(ctx, address)
//	if err != nil {
//	    return err
//	}
//	defer client.Close()
//
// Returns:
//   - error: Non-nil if connection close fails
func (c *Client) Close() error {
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

// Ping checks if the daemon is responsive.
//
// This is a lightweight health check that can be used to verify the daemon
// is running and responding to requests. Useful for status commands and
// connection validation.
//
// Parameters:
//   - ctx: Context for the RPC call
//
// Returns:
//   - error: Non-nil if daemon doesn't respond or responds with an error
//
// Example:
//
//	if err := client.Ping(ctx); err != nil {
//	    return fmt.Errorf("daemon not responding: %w", err)
//	}
func (c *Client) Ping(ctx context.Context) error {
	_, err := c.daemon.Ping(ctx, &api.PingRequest{})
	if err != nil {
		// Wrap error with user-friendly message
		if st, ok := status.FromError(err); ok {
			switch st.Code() {
			case codes.Unavailable:
				return fmt.Errorf("daemon not responding (connection unavailable)")
			case codes.DeadlineExceeded:
				return fmt.Errorf("daemon ping timeout")
			default:
				return fmt.Errorf("daemon ping failed: %s", st.Message())
			}
		}
		return fmt.Errorf("daemon ping failed: %w", err)
	}
	return nil
}

// Status retrieves the daemon's current status and health information.
//
// This method queries the daemon for comprehensive status including:
//   - Process state (running, PID, uptime)
//   - Service endpoints (registry, callback, gRPC)
//   - Component counts (agents, missions, active missions)
//
// Parameters:
//   - ctx: Context for the RPC call
//
// Returns:
//   - *daemon.DaemonStatus: Complete status information
//   - error: Non-nil if RPC fails or daemon is unhealthy
//
// Example:
//
//	status, err := client.Status(ctx)
//	if err != nil {
//	    return err
//	}
//	fmt.Printf("Daemon uptime: %s\n", status.Uptime)
//	fmt.Printf("Registered agents: %d\n", status.AgentCount)
func (c *Client) Status(ctx context.Context) (*daemon.DaemonStatus, error) {
	resp, err := c.daemon.Status(ctx, &api.StatusRequest{})
	if err != nil {
		// Wrap error with user-friendly message
		if st, ok := status.FromError(err); ok {
			switch st.Code() {
			case codes.Unavailable:
				return nil, fmt.Errorf("daemon not responding (is it running?)")
			case codes.DeadlineExceeded:
				return nil, fmt.Errorf("daemon status request timeout")
			default:
				return nil, fmt.Errorf("failed to get daemon status: %s", st.Message())
			}
		}
		return nil, fmt.Errorf("failed to get daemon status: %w", err)
	}

	return convertProtoStatus(resp), nil
}

// AgentInfo represents information about a registered agent.
type AgentInfo struct {
	Name        string
	Version     string
	Description string
	Address     string
	Status      string
}

// ToolInfo represents information about a registered tool.
type ToolInfo struct {
	Name         string
	Version      string
	Description  string
	Address      string
	Status       string
	Capabilities *Capabilities
}

// Capabilities represents the runtime privileges and features available to a tool.
type Capabilities struct {
	HasRoot         bool
	HasSudo         bool
	CanRawSocket    bool
	Features        map[string]bool
	BlockedArgs     []string
	ArgAlternatives map[string]string
}

// PluginInfo represents information about a registered plugin.
type PluginInfo struct {
	Name        string
	Version     string
	Description string
	Address     string
	Status      string
}

// ListAgents retrieves a list of all registered agents from the daemon.
//
// This method queries the daemon's agent registry to get information about
// all agents that are currently registered and available for mission execution.
//
// Parameters:
//   - ctx: Context for the RPC call
//
// Returns:
//   - []AgentInfo: List of agent information
//   - error: Non-nil if RPC fails
//
// Example:
//
//	agents, err := client.ListAgents(ctx)
//	if err != nil {
//	    return err
//	}
//	for _, agent := range agents {
//	    fmt.Printf("Agent: %s (v%s) - %s\n", agent.Name, agent.Version, agent.Status)
//	}
func (c *Client) ListAgents(ctx context.Context) ([]AgentInfo, error) {
	resp, err := c.daemon.ListAgents(ctx, &api.ListAgentsRequest{})
	if err != nil {
		// Wrap error with user-friendly message
		if st, ok := status.FromError(err); ok {
			switch st.Code() {
			case codes.Unavailable:
				return nil, fmt.Errorf("daemon not responding (is it running?)")
			case codes.DeadlineExceeded:
				return nil, fmt.Errorf("daemon request timeout while listing agents")
			default:
				return nil, fmt.Errorf("failed to list agents: %s", st.Message())
			}
		}
		return nil, fmt.Errorf("failed to list agents: %w", err)
	}

	// Convert proto agents to domain types
	agents := convertProtoAgents(resp.Agents)
	return agents, nil
}

// ListTools retrieves a list of all registered tools from the daemon.
//
// This method queries the daemon's tool registry to get information about
// all tools that are currently registered and available for use.
//
// Parameters:
//   - ctx: Context for the RPC call
//
// Returns:
//   - []ToolInfo: List of tool information
//   - error: Non-nil if RPC fails
//
// Example:
//
//	tools, err := client.ListTools(ctx)
//	if err != nil {
//	    return err
//	}
//	for _, tool := range tools {
//	    fmt.Printf("Tool: %s (v%s) - %s\n", tool.Name, tool.Version, tool.Status)
//	}
func (c *Client) ListTools(ctx context.Context) ([]ToolInfo, error) {
	resp, err := c.daemon.ListTools(ctx, &api.ListToolsRequest{})
	if err != nil {
		// Wrap error with user-friendly message
		if st, ok := status.FromError(err); ok {
			switch st.Code() {
			case codes.Unavailable:
				return nil, fmt.Errorf("daemon not responding (is it running?)")
			case codes.DeadlineExceeded:
				return nil, fmt.Errorf("daemon request timeout while listing tools")
			default:
				return nil, fmt.Errorf("failed to list tools: %s", st.Message())
			}
		}
		return nil, fmt.Errorf("failed to list tools: %w", err)
	}

	// Convert proto tools to domain types
	tools := convertProtoTools(resp.Tools)
	return tools, nil
}

// ListPlugins retrieves a list of all registered plugins from the daemon.
//
// This method queries the daemon's plugin registry to get information about
// all plugins that are currently registered and available for use.
//
// Parameters:
//   - ctx: Context for the RPC call
//
// Returns:
//   - []PluginInfo: List of plugin information
//   - error: Non-nil if RPC fails
//
// Example:
//
//	plugins, err := client.ListPlugins(ctx)
//	if err != nil {
//	    return err
//	}
//	for _, plugin := range plugins {
//	    fmt.Printf("Plugin: %s (v%s) - %s\n", plugin.Name, plugin.Version, plugin.Status)
//	}
func (c *Client) ListPlugins(ctx context.Context) ([]PluginInfo, error) {
	resp, err := c.daemon.ListPlugins(ctx, &api.ListPluginsRequest{})
	if err != nil {
		// Wrap error with user-friendly message
		if st, ok := status.FromError(err); ok {
			switch st.Code() {
			case codes.Unavailable:
				return nil, fmt.Errorf("daemon not responding (is it running?)")
			case codes.DeadlineExceeded:
				return nil, fmt.Errorf("daemon request timeout while listing plugins")
			default:
				return nil, fmt.Errorf("failed to list plugins: %s", st.Message())
			}
		}
		return nil, fmt.Errorf("failed to list plugins: %w", err)
	}

	// Convert proto plugins to domain types
	plugins := convertProtoPlugins(resp.Plugins)
	return plugins, nil
}

// PluginQueryResult represents the result of a plugin query.
type PluginQueryResult struct {
	// Result is the unmarshaled result from the plugin method
	Result any
	// DurationMs is how long the query took in milliseconds
	DurationMs int64
}

// QueryPlugin executes a method on a plugin and returns the result.
//
// This method discovers the plugin via the etcd registry and executes
// the specified method with the given parameters via gRPC.
//
// Parameters:
//   - ctx: Context for the RPC call
//   - name: Plugin name (e.g., "scope-ingestion")
//   - method: Method name to execute (e.g., "list_programs")
//   - params: Parameters for the method (will be JSON-encoded)
//
// Returns:
//   - *PluginQueryResult: Query result including duration
//   - error: Non-nil if RPC fails or plugin returns an error
//
// Example:
//
//	result, err := client.QueryPlugin(ctx, "scope-ingestion", "list_programs", map[string]any{"platform": "hackerone"})
//	if err != nil {
//	    return err
//	}
//	fmt.Printf("Result: %v (took %dms)\n", result.Result, result.DurationMs)
func (c *Client) QueryPlugin(ctx context.Context, name, method string, params map[string]any) (*PluginQueryResult, error) {
	resp, err := c.daemon.QueryPlugin(ctx, &api.QueryPluginRequest{
		Name:   name,
		Method: method,
		Params: api.MapToTypedMap(params),
	})
	if err != nil {
		// Wrap error with user-friendly message
		if st, ok := status.FromError(err); ok {
			switch st.Code() {
			case codes.Unavailable:
				return nil, fmt.Errorf("daemon not responding (is it running?)")
			case codes.DeadlineExceeded:
				return nil, fmt.Errorf("daemon request timeout while querying plugin")
			default:
				return nil, fmt.Errorf("failed to query plugin: %s", st.Message())
			}
		}
		return nil, fmt.Errorf("failed to query plugin: %w", err)
	}

	// Check for error in response
	if resp.Error != "" {
		return nil, fmt.Errorf("plugin error: %s", resp.Error)
	}

	// Convert TypedValue result to any
	result := api.TypedValueToAny(resp.Result)

	return &PluginQueryResult{
		Result:     result,
		DurationMs: resp.DurationMs,
	}, nil
}

// MissionEvent represents an event from a running mission.
type MissionEvent struct {
	Type      string
	Timestamp time.Time
	Message   string
	Data      map[string]interface{}
}

// isRemoteDaemon checks if the client is connecting to a remote daemon.
//
// A daemon is considered remote if GIBSON_DAEMON_ADDRESS is set to a value
// that is NOT:
//   - Empty string
//   - localhost (any port)
//   - 127.0.0.1 (any port)
//   - Unix socket (starts with unix:// or /)
//
// This function is used to determine whether to send workflow files inline
// (remote daemon) or as file paths (local daemon with shared filesystem).
//
// Returns:
//   - true: Connecting to a remote daemon, files should be sent inline
//   - false: Connecting to local daemon or no env var set, use file paths
//
// Example:
//
//	if isRemoteDaemon() {
//	    // Read local file and send content inline
//	} else {
//	    // Send file path (daemon has filesystem access)
//	}
func isRemoteDaemon() bool {
	address := os.Getenv(EnvDaemonAddress)

	// No env var set = local daemon
	if address == "" {
		return false
	}

	// Unix socket = local daemon (shared filesystem)
	if strings.HasPrefix(address, "unix://") || strings.HasPrefix(address, "/") {
		return false
	}

	// Check for localhost/127.0.0.1
	if strings.HasPrefix(address, "localhost:") ||
	   strings.HasPrefix(address, "127.0.0.1:") ||
	   address == "localhost" ||
	   address == "127.0.0.1" {
		return false
	}

	// Everything else is considered remote
	return true
}

// RunMission executes a mission workflow via the daemon and streams events.
//
// This method starts a mission execution on the daemon and returns a channel
// that receives mission events as they occur. Events include mission start,
// agent execution, tool invocations, findings, and mission completion.
//
// The returned channel is closed when the mission completes or encounters an error.
// Callers should read from the channel until it closes to get all mission events.
//
// When connecting to a remote daemon (detected via GIBSON_DAEMON_ADDRESS), this method
// automatically reads the local workflow file and transmits its content inline. For
// local daemon connections, it passes the file path directly.
//
// Parameters:
//   - ctx: Context for the mission execution (cancellation stops the mission)
//   - workflowPath: Path to the workflow YAML file
//   - memoryContinuity: Memory continuity mode (isolated, inherit, shared) - empty defaults to isolated
//
// Returns:
//   - <-chan MissionEvent: Channel receiving mission events
//   - error: Non-nil if mission start fails (not for mission execution errors)
//
// Example:
//
//	events, err := client.RunMission(ctx, "/path/to/workflow.yaml", "isolated")
//	if err != nil {
//	    return err
//	}
//
//	for event := range events {
//	    fmt.Printf("[%s] %s: %s\n", event.Timestamp, event.Type, event.Message)
//	}
func (c *Client) RunMission(ctx context.Context, workflowPath string, memoryContinuity string) (<-chan MissionEvent, error) {
	// Build the request based on whether we're connecting to a remote daemon
	req := &api.RunMissionRequest{
		MemoryContinuity: memoryContinuity,
	}

	if isRemoteDaemon() {
		// Remote daemon: read local file and send content inline
		workflowContent, err := os.ReadFile(workflowPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read workflow file %s: %w", workflowPath, err)
		}

		// Validate file size (10MB limit as per proto spec)
		const maxFileSize = 10 * 1024 * 1024 // 10MB
		if len(workflowContent) > maxFileSize {
			return nil, fmt.Errorf("workflow file %s is too large (%d bytes, max %d bytes)",
				workflowPath, len(workflowContent), maxFileSize)
		}

		req.WorkflowYaml = string(workflowContent)
	} else {
		// Local daemon: send file path (shared filesystem)
		req.WorkflowPath = workflowPath
	}

	// Start streaming RPC
	stream, err := c.daemon.RunMission(ctx, req)
	if err != nil {
		// Wrap error with user-friendly message
		if st, ok := status.FromError(err); ok {
			switch st.Code() {
			case codes.Unavailable:
				return nil, fmt.Errorf("daemon not responding (is it running?)")
			case codes.NotFound:
				return nil, fmt.Errorf("workflow file not found: %s", workflowPath)
			case codes.InvalidArgument:
				return nil, fmt.Errorf("invalid workflow: %s", st.Message())
			default:
				return nil, fmt.Errorf("failed to start mission: %s", st.Message())
			}
		}
		return nil, fmt.Errorf("failed to start mission: %w", err)
	}

	// Create event channel and spawn goroutine to read from stream
	eventChan := make(chan MissionEvent, 10) // Buffer to avoid blocking daemon
	go func() {
		defer close(eventChan)
		for {
			event, err := stream.Recv()
			if err == io.EOF {
				// Stream completed normally
				return
			}
			if err != nil {
				// Check if context was cancelled
				if ctx.Err() != nil {
					return
				}
				// Stream error - log and exit
				// TODO: Consider sending error event to channel
				return
			}

			// Convert and send event
			select {
			case eventChan <- convertProtoMissionEvent(event):
			case <-ctx.Done():
				return
			}
		}
	}()

	return eventChan, nil
}

// MissionInfo represents information about a mission.
type MissionInfo struct {
	ID           string
	Name         string
	WorkflowPath string
	Status       string
	StartTime    time.Time
	EndTime      time.Time
	FindingCount int
}

// ListMissions retrieves a list of missions from the daemon.
//
// This method queries the daemon's mission store with optional filtering by
// status and name pattern. It supports pagination via limit and offset parameters.
//
// Parameters:
//   - ctx: Context for the RPC call
//   - activeOnly: If true, only return running/paused missions
//   - statusFilter: Filter by specific status (running, completed, failed, cancelled) - empty means all
//   - namePattern: Filter by mission name using pattern matching - empty means all
//   - limit: Maximum number of missions to return (0 = use default)
//   - offset: Number of missions to skip for pagination
//
// Returns:
//   - []MissionInfo: List of missions matching the filter
//   - int: Total count of missions (for pagination)
//   - error: Non-nil if RPC fails
//
// Example:
//
//	missions, total, err := client.ListMissions(ctx, false, "running", "", 10, 0)
//	if err != nil {
//	    return err
//	}
//	fmt.Printf("Found %d missions (showing %d)\n", total, len(missions))
func (c *Client) ListMissions(ctx context.Context, activeOnly bool, statusFilter, namePattern string, limit, offset int) ([]MissionInfo, int, error) {
	resp, err := c.daemon.ListMissions(ctx, &api.ListMissionsRequest{
		ActiveOnly:   activeOnly,
		StatusFilter: statusFilter,
		NamePattern:  namePattern,
		Limit:        int32(limit),
		Offset:       int32(offset),
	})
	if err != nil {
		// Wrap error with user-friendly message
		if st, ok := status.FromError(err); ok {
			switch st.Code() {
			case codes.Unavailable:
				return nil, 0, fmt.Errorf("daemon not responding (is it running?)")
			case codes.DeadlineExceeded:
				return nil, 0, fmt.Errorf("daemon request timeout while listing missions")
			default:
				return nil, 0, fmt.Errorf("failed to list missions: %s", st.Message())
			}
		}
		return nil, 0, fmt.Errorf("failed to list missions: %w", err)
	}

	// Convert proto missions to domain types
	missions := make([]MissionInfo, len(resp.Missions))
	for i, m := range resp.Missions {
		missions[i] = MissionInfo{
			ID:           m.Id,
			Name:         m.Name,
			WorkflowPath: m.WorkflowPath,
			Status:       m.Status,
			StartTime:    time.Unix(m.StartTime, 0),
			EndTime:      time.Unix(m.EndTime, 0),
			FindingCount: int(m.FindingCount),
		}
	}

	return missions, int(resp.Total), nil
}

// StopMission stops a running mission via the daemon.
//
// This method requests graceful termination of a mission. If force is true,
// the mission is killed immediately without cleanup.
//
// Parameters:
//   - ctx: Context for the RPC call
//   - missionID: The unique identifier of the mission to stop
//   - force: If true, force-kill the mission immediately
//
// Returns:
//   - error: Non-nil if stop request fails
//
// Example:
//
//	err := client.StopMission(ctx, "mission-123", false)
//	if err != nil {
//	    return err
//	}
//	fmt.Println("Mission stopped successfully")
func (c *Client) StopMission(ctx context.Context, missionID string, force bool) error {
	resp, err := c.daemon.StopMission(ctx, &api.StopMissionRequest{
		MissionId: missionID,
		Force:     force,
	})
	if err != nil {
		// Wrap error with user-friendly message
		if st, ok := status.FromError(err); ok {
			switch st.Code() {
			case codes.Unavailable:
				return fmt.Errorf("daemon not responding (is it running?)")
			case codes.NotFound:
				return fmt.Errorf("mission not found: %s", missionID)
			case codes.FailedPrecondition:
				return fmt.Errorf("mission is not running: %s", missionID)
			default:
				return fmt.Errorf("failed to stop mission: %s", st.Message())
			}
		}
		return fmt.Errorf("failed to stop mission: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("failed to stop mission: %s", resp.Message)
	}

	return nil
}

// AttackOptions contains options for running an attack.
type AttackOptions struct {
	Target      string
	TargetName  string
	AttackType  string
	Credentials []string
	Payloads    []string
	MaxDepth    int
	Timeout     time.Duration
}

// AttackEvent represents an event from a running attack.
type AttackEvent struct {
	Type      string
	Timestamp time.Time
	Message   string
	Severity  string
	Data      map[string]interface{}
	Result    *OperationResult
}

// OperationResult represents typed operation metrics.
type OperationResult struct {
	Status        string
	DurationMs    int64
	StartedAt     int64
	CompletedAt   int64
	TurnsUsed     int32
	TokensUsed    int64
	NodesExecuted int32
	NodesFailed   int32
	FindingsCount int32
	CriticalCount int32
	HighCount     int32
	MediumCount   int32
	LowCount      int32
	ErrorMessage  string
	ErrorCode     string
}

// RunAttack executes an attack via the daemon and streams events.
//
// This method starts an attack execution on the daemon and returns a channel
// that receives attack events as they occur. Events include attack start,
// payload execution, vulnerability discovery, and attack completion.
//
// The returned channel is closed when the attack completes or encounters an error.
// Callers should read from the channel until it closes to get all attack events.
//
// Parameters:
//   - ctx: Context for the attack execution (cancellation stops the attack)
//   - opts: Attack configuration options
//
// Returns:
//   - <-chan AttackEvent: Channel receiving attack events
//   - error: Non-nil if attack start fails (not for attack execution errors)
//
// Example:
//
//	opts := AttackOptions{
//	    Target:     "http://target.example.com",
//	    AttackType: "prompt-injection",
//	    MaxDepth:   3,
//	    Timeout:    30 * time.Minute,
//	}
//	events, err := client.RunAttack(ctx, opts)
//	if err != nil {
//	    return err
//	}
//
//	for event := range events {
//	    if event.Severity == "high" {
//	        fmt.Printf("[!] %s: %s\n", event.Type, event.Message)
//	    }
//	}
func (c *Client) RunAttack(ctx context.Context, opts AttackOptions) (<-chan AttackEvent, error) {
	// Start streaming RPC
	stream, err := c.daemon.RunAttack(ctx, &api.RunAttackRequest{
		Target:     opts.Target,
		TargetName: opts.TargetName,
		AttackType: opts.AttackType,
		AgentId:    opts.AttackType, // Use attack type as agent ID
	})
	if err != nil {
		// Wrap error with user-friendly message
		if st, ok := status.FromError(err); ok {
			switch st.Code() {
			case codes.Unavailable:
				return nil, fmt.Errorf("daemon not responding (is it running?)")
			case codes.NotFound:
				return nil, fmt.Errorf("attack agent not found: %s", opts.AttackType)
			case codes.InvalidArgument:
				return nil, fmt.Errorf("invalid attack configuration: %s", st.Message())
			default:
				return nil, fmt.Errorf("failed to start attack: %s", st.Message())
			}
		}
		return nil, fmt.Errorf("failed to start attack: %w", err)
	}

	// Create event channel and spawn goroutine to read from stream
	eventChan := make(chan AttackEvent, 10) // Buffer to avoid blocking daemon
	go func() {
		defer close(eventChan)
		for {
			event, err := stream.Recv()
			if err == io.EOF {
				// Stream completed normally
				return
			}
			if err != nil {
				// Check if context was cancelled
				if ctx.Err() != nil {
					return
				}
				// Stream error - log and exit
				// TODO: Consider sending error event to channel
				return
			}

			// Convert and send event
			select {
			case eventChan <- convertProtoAttackEvent(event):
			case <-ctx.Done():
				return
			}
		}
	}()

	return eventChan, nil
}

// Event represents a generic daemon event for TUI subscription.
type Event struct {
	Type      string
	Source    string
	Timestamp time.Time
	Data      map[string]interface{}
}

// Subscribe subscribes to all daemon events for real-time updates.
//
// This method establishes a streaming connection to the daemon that receives
// all significant events including:
//   - Agent registration/deregistration
//   - Mission start/stop
//   - Finding discoveries
//   - System health changes
//
// The returned channel is closed when the subscription ends (context cancellation,
// daemon shutdown, or connection loss). This is primarily used by the TUI for
// real-time dashboard updates.
//
// Parameters:
//   - ctx: Context for the subscription (cancellation stops the stream)
//
// Returns:
//   - <-chan Event: Channel receiving all daemon events
//   - error: Non-nil if subscription setup fails
//
// Example:
//
//	events, err := client.Subscribe(ctx)
//	if err != nil {
//	    return err
//	}
//
//	for event := range events {
//	    switch event.Type {
//	    case "agent_registered":
//	        updateAgentList(event.Data)
//	    case "mission_started":
//	        updateMissionView(event.Data)
//	    case "finding_discovered":
//	        showFindingNotification(event.Data)
//	    }
//	}
func (c *Client) Subscribe(ctx context.Context) (<-chan Event, error) {
	// Start streaming RPC
	stream, err := c.daemon.Subscribe(ctx, &api.SubscribeRequest{})
	if err != nil {
		// Wrap error with user-friendly message
		if st, ok := status.FromError(err); ok {
			switch st.Code() {
			case codes.Unavailable:
				return nil, fmt.Errorf("daemon not responding (is it running?)")
			case codes.PermissionDenied:
				return nil, fmt.Errorf("permission denied for event subscription")
			default:
				return nil, fmt.Errorf("failed to subscribe to events: %s", st.Message())
			}
		}
		return nil, fmt.Errorf("failed to subscribe to events: %w", err)
	}

	// Create event channel and spawn goroutine to read from stream
	eventChan := make(chan Event, 50) // Larger buffer for high-frequency events
	go func() {
		defer close(eventChan)
		for {
			event, err := stream.Recv()
			if err == io.EOF {
				// Stream completed normally
				return
			}
			if err != nil {
				// Check if context was cancelled
				if ctx.Err() != nil {
					return
				}
				// Stream error - log and exit
				// TODO: Consider sending error event to channel
				return
			}

			// Convert and send event
			select {
			case eventChan <- convertProtoEvent(event):
			case <-ctx.Done():
				return
			}
		}
	}()

	return eventChan, nil
}

// StartResult represents the result of starting a component.
type StartResult struct {
	PID     int
	Port    int
	LogPath string
}

// StopResult represents the result of stopping a component.
type StopResult struct {
	StoppedCount int
	TotalCount   int
}

// StartAgent starts an agent by name.
func (c *Client) StartAgent(ctx context.Context, name string) (*StartResult, error) {
	return c.startComponent(ctx, "agent", name)
}

// StopAgent stops an agent by name.
func (c *Client) StopAgent(ctx context.Context, name string) (*StopResult, error) {
	return c.stopComponent(ctx, "agent", name, false)
}

// StartTool starts a tool by name.
func (c *Client) StartTool(ctx context.Context, name string) (*StartResult, error) {
	return c.startComponent(ctx, "tool", name)
}

// StopTool stops a tool by name.
func (c *Client) StopTool(ctx context.Context, name string) (*StopResult, error) {
	return c.stopComponent(ctx, "tool", name, false)
}

// StartPlugin starts a plugin by name.
func (c *Client) StartPlugin(ctx context.Context, name string) (*StartResult, error) {
	return c.startComponent(ctx, "plugin", name)
}

// StopPlugin stops a plugin by name.
func (c *Client) StopPlugin(ctx context.Context, name string) (*StopResult, error) {
	return c.stopComponent(ctx, "plugin", name, false)
}

// startComponent is the internal method that starts a component via the daemon.
func (c *Client) startComponent(ctx context.Context, kind, name string) (*StartResult, error) {
	resp, err := c.daemon.StartComponent(ctx, &api.StartComponentRequest{
		Kind: kind,
		Name: name,
	})
	if err != nil {
		// Wrap error with user-friendly message
		if st, ok := status.FromError(err); ok {
			switch st.Code() {
			case codes.Unavailable:
				return nil, fmt.Errorf("daemon not responding (is it running?)")
			case codes.NotFound:
				return nil, fmt.Errorf("component '%s' not found", name)
			case codes.AlreadyExists:
				return nil, fmt.Errorf("component '%s' is already running", name)
			case codes.InvalidArgument:
				return nil, fmt.Errorf("invalid component kind or name: %s", st.Message())
			default:
				return nil, fmt.Errorf("failed to start component: %s", st.Message())
			}
		}
		return nil, fmt.Errorf("failed to start component: %w", err)
	}

	if !resp.Success {
		return nil, fmt.Errorf("failed to start component: %s", resp.Message)
	}

	return &StartResult{
		PID:     int(resp.Pid),
		Port:    int(resp.Port),
		LogPath: resp.LogPath,
	}, nil
}

// stopComponent is the internal method that stops a component via the daemon.
func (c *Client) stopComponent(ctx context.Context, kind, name string, force bool) (*StopResult, error) {
	resp, err := c.daemon.StopComponent(ctx, &api.StopComponentRequest{
		Kind:  kind,
		Name:  name,
		Force: force,
	})
	if err != nil {
		// Wrap error with user-friendly message
		if st, ok := status.FromError(err); ok {
			switch st.Code() {
			case codes.Unavailable:
				return nil, fmt.Errorf("daemon not responding (is it running?)")
			case codes.NotFound:
				return nil, fmt.Errorf("component '%s' is not running", name)
			case codes.InvalidArgument:
				return nil, fmt.Errorf("invalid component kind or name: %s", st.Message())
			default:
				return nil, fmt.Errorf("failed to stop component: %s", st.Message())
			}
		}
		return nil, fmt.Errorf("failed to stop component: %w", err)
	}

	if !resp.Success {
		return nil, fmt.Errorf("failed to stop component: %s", resp.Message)
	}

	return &StopResult{
		StoppedCount: int(resp.StoppedCount),
		TotalCount:   int(resp.TotalCount),
	}, nil
}

// InstallOptions contains options for installing a component.
type InstallOptions struct {
	Branch    string // Git branch to install
	Tag       string // Git tag to install
	Force     bool   // Force reinstall if exists
	SkipBuild bool   // Skip building after clone
	Verbose   bool   // Stream build output
}

// InstallResult represents the result of installing a component.
type InstallResult struct {
	Name        string        // Component name
	Version     string        // Component version
	Kind        string        // Component kind
	RepoPath    string        // Local repository path
	BinPath     string        // Binary path (if built)
	BuildOutput string        // Build stdout (if verbose)
	Duration    time.Duration // Total install time
}

// InstallAllResult represents the result of installing multiple components.
type InstallAllResult struct {
	ComponentsFound int                 // Total components discovered
	SuccessfulCount int                 // Number of successful installs
	SkippedCount    int                 // Number of skipped components
	FailedCount     int                 // Number of failed installs
	Successful      []InstallResultItem // Successfully installed components
	Skipped         []InstallResultItem // Skipped components
	Failed          []InstallFailedItem // Failed components
	Duration        time.Duration       // Total installation time
}

// InstallResultItem represents a single component install result.
type InstallResultItem struct {
	Name    string // Component name
	Version string // Component version
	Path    string // Local repository path
}

// InstallFailedItem represents a failed component installation.
type InstallFailedItem struct {
	Name  string // Component name (if available)
	Path  string // Path where failure occurred
	Error string // Error message
}

// InstallAgent installs an agent from a Git repository.
func (c *Client) InstallAgent(ctx context.Context, url string, opts InstallOptions) (*InstallResult, error) {
	return c.installComponent(ctx, "agent", url, opts)
}

// InstallTool installs a tool from a Git repository.
func (c *Client) InstallTool(ctx context.Context, url string, opts InstallOptions) (*InstallResult, error) {
	return c.installComponent(ctx, "tool", url, opts)
}

// InstallPlugin installs a plugin from a Git repository.
func (c *Client) InstallPlugin(ctx context.Context, url string, opts InstallOptions) (*InstallResult, error) {
	return c.installComponent(ctx, "plugin", url, opts)
}

// InstallAllAgent installs all agents from a mono-repo.
func (c *Client) InstallAllAgent(ctx context.Context, url string, opts InstallOptions) (*InstallAllResult, error) {
	return c.installAllComponent(ctx, "agent", url, opts)
}

// InstallAllTool installs all tools from a mono-repo.
func (c *Client) InstallAllTool(ctx context.Context, url string, opts InstallOptions) (*InstallAllResult, error) {
	return c.installAllComponent(ctx, "tool", url, opts)
}

// InstallAllPlugin installs all plugins from a mono-repo.
func (c *Client) InstallAllPlugin(ctx context.Context, url string, opts InstallOptions) (*InstallAllResult, error) {
	return c.installAllComponent(ctx, "plugin", url, opts)
}

// installAllComponent is the internal method that installs all components from a mono-repo via the daemon.
func (c *Client) installAllComponent(ctx context.Context, kind, url string, opts InstallOptions) (*InstallAllResult, error) {
	resp, err := c.daemon.InstallAllComponent(ctx, &api.InstallAllComponentRequest{
		Kind:      kind,
		Url:       url,
		Branch:    opts.Branch,
		Tag:       opts.Tag,
		Force:     opts.Force,
		SkipBuild: opts.SkipBuild,
		Verbose:   opts.Verbose,
	})
	if err != nil {
		// Wrap error with user-friendly message
		if st, ok := status.FromError(err); ok {
			switch st.Code() {
			case codes.Unavailable:
				return nil, fmt.Errorf("daemon not responding (is it running?)")
			case codes.InvalidArgument:
				return nil, fmt.Errorf("invalid component URL or options: %s", st.Message())
			case codes.NotFound:
				return nil, fmt.Errorf("repository not found or no components found: %s", url)
			default:
				return nil, fmt.Errorf("failed to install components: %s", st.Message())
			}
		}
		return nil, fmt.Errorf("failed to install components: %w", err)
	}

	if !resp.Success {
		return nil, fmt.Errorf("failed to install components: %s", resp.Message)
	}

	// Convert proto response to client types
	successful := make([]InstallResultItem, len(resp.Successful))
	for i, item := range resp.Successful {
		successful[i] = InstallResultItem{
			Name:    item.Name,
			Version: item.Version,
			Path:    item.Path,
		}
	}

	skipped := make([]InstallResultItem, len(resp.Skipped))
	for i, item := range resp.Skipped {
		skipped[i] = InstallResultItem{
			Name:    item.Name,
			Version: item.Version,
			Path:    item.Path,
		}
	}

	failed := make([]InstallFailedItem, len(resp.Failed))
	for i, item := range resp.Failed {
		failed[i] = InstallFailedItem{
			Name:  item.Name,
			Path:  item.Path,
			Error: item.Error,
		}
	}

	return &InstallAllResult{
		ComponentsFound: int(resp.ComponentsFound),
		SuccessfulCount: int(resp.SuccessfulCount),
		SkippedCount:    int(resp.SkippedCount),
		FailedCount:     int(resp.FailedCount),
		Successful:      successful,
		Skipped:         skipped,
		Failed:          failed,
		Duration:        time.Duration(resp.DurationMs) * time.Millisecond,
	}, nil
}

// installComponent is the internal method that installs a component via the daemon.
func (c *Client) installComponent(ctx context.Context, kind, url string, opts InstallOptions) (*InstallResult, error) {
	resp, err := c.daemon.InstallComponent(ctx, &api.InstallComponentRequest{
		Kind:      kind,
		Url:       url,
		Branch:    opts.Branch,
		Tag:       opts.Tag,
		Force:     opts.Force,
		SkipBuild: opts.SkipBuild,
		Verbose:   opts.Verbose,
	})
	if err != nil {
		// Wrap error with user-friendly message
		if st, ok := status.FromError(err); ok {
			switch st.Code() {
			case codes.Unavailable:
				return nil, fmt.Errorf("daemon not responding (is it running?)")
			case codes.AlreadyExists:
				return nil, fmt.Errorf("component already exists (use --force to reinstall)")
			case codes.InvalidArgument:
				return nil, fmt.Errorf("invalid component URL or options: %s", st.Message())
			case codes.NotFound:
				return nil, fmt.Errorf("repository not found: %s", url)
			default:
				return nil, fmt.Errorf("failed to install component: %s", st.Message())
			}
		}
		return nil, fmt.Errorf("failed to install component: %w", err)
	}

	if !resp.Success {
		return nil, fmt.Errorf("failed to install component: %s", resp.Message)
	}

	return &InstallResult{
		Name:        resp.Name,
		Version:     resp.Version,
		Kind:        kind,
		RepoPath:    resp.RepoPath,
		BinPath:     resp.BinPath,
		BuildOutput: resp.BuildOutput,
		Duration:    time.Duration(resp.DurationMs) * time.Millisecond,
	}, nil
}

// UninstallAgent uninstalls an agent by name.
func (c *Client) UninstallAgent(ctx context.Context, name string, force bool) error {
	return c.uninstallComponent(ctx, "agent", name, force)
}

// UninstallTool uninstalls a tool by name.
func (c *Client) UninstallTool(ctx context.Context, name string, force bool) error {
	return c.uninstallComponent(ctx, "tool", name, force)
}

// UninstallPlugin uninstalls a plugin by name.
func (c *Client) UninstallPlugin(ctx context.Context, name string, force bool) error {
	return c.uninstallComponent(ctx, "plugin", name, force)
}

// uninstallComponent is the internal method that uninstalls a component via the daemon.
func (c *Client) uninstallComponent(ctx context.Context, kind, name string, force bool) error {
	resp, err := c.daemon.UninstallComponent(ctx, &api.UninstallComponentRequest{
		Kind:  kind,
		Name:  name,
		Force: force,
	})
	if err != nil {
		// Wrap error with user-friendly message
		if st, ok := status.FromError(err); ok {
			switch st.Code() {
			case codes.Unavailable:
				return fmt.Errorf("daemon not responding (is it running?)")
			case codes.NotFound:
				return fmt.Errorf("component '%s' not found", name)
			case codes.FailedPrecondition:
				return fmt.Errorf("component '%s' is running (stop it first or use --force)", name)
			case codes.InvalidArgument:
				return fmt.Errorf("invalid component kind or name: %s", st.Message())
			default:
				return fmt.Errorf("failed to uninstall component: %s", st.Message())
			}
		}
		return fmt.Errorf("failed to uninstall component: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("failed to uninstall component: %s", resp.Message)
	}

	return nil
}

// UpdateOptions contains options for updating a component.
type UpdateOptions struct {
	Restart   bool // Restart after update if running
	SkipBuild bool // Skip rebuild
	Verbose   bool // Stream build output
}

// UpdateResult represents the result of updating a component.
type UpdateResult struct {
	Updated     bool          // True if updated, false if already latest
	OldVersion  string        // Previous version
	NewVersion  string        // New version
	BuildOutput string        // Build stdout (if verbose)
	Duration    time.Duration // Total update time
}

// UpdateAgent updates an agent to the latest version.
func (c *Client) UpdateAgent(ctx context.Context, name string, opts UpdateOptions) (*UpdateResult, error) {
	return c.updateComponent(ctx, "agent", name, opts)
}

// UpdateTool updates a tool to the latest version.
func (c *Client) UpdateTool(ctx context.Context, name string, opts UpdateOptions) (*UpdateResult, error) {
	return c.updateComponent(ctx, "tool", name, opts)
}

// UpdatePlugin updates a plugin to the latest version.
func (c *Client) UpdatePlugin(ctx context.Context, name string, opts UpdateOptions) (*UpdateResult, error) {
	return c.updateComponent(ctx, "plugin", name, opts)
}

// updateComponent is the internal method that updates a component via the daemon.
func (c *Client) updateComponent(ctx context.Context, kind, name string, opts UpdateOptions) (*UpdateResult, error) {
	resp, err := c.daemon.UpdateComponent(ctx, &api.UpdateComponentRequest{
		Kind:      kind,
		Name:      name,
		Restart:   opts.Restart,
		SkipBuild: opts.SkipBuild,
		Verbose:   opts.Verbose,
	})
	if err != nil {
		// Wrap error with user-friendly message
		if st, ok := status.FromError(err); ok {
			switch st.Code() {
			case codes.Unavailable:
				return nil, fmt.Errorf("daemon not responding (is it running?)")
			case codes.NotFound:
				return nil, fmt.Errorf("component '%s' not found", name)
			case codes.InvalidArgument:
				return nil, fmt.Errorf("invalid component kind or name: %s", st.Message())
			default:
				return nil, fmt.Errorf("failed to update component: %s", st.Message())
			}
		}
		return nil, fmt.Errorf("failed to update component: %w", err)
	}

	if !resp.Success {
		return nil, fmt.Errorf("failed to update component: %s", resp.Message)
	}

	return &UpdateResult{
		Updated:     resp.Updated,
		OldVersion:  resp.OldVersion,
		NewVersion:  resp.NewVersion,
		BuildOutput: resp.BuildOutput,
		Duration:    time.Duration(resp.DurationMs) * time.Millisecond,
	}, nil
}

// BuildResult represents the result of building a component.
type BuildResult struct {
	Success  bool          // Build success
	Stdout   string        // Build stdout
	Stderr   string        // Build stderr
	Duration time.Duration // Build time
}

// BuildAgent rebuilds an agent from source.
func (c *Client) BuildAgent(ctx context.Context, name string) (*BuildResult, error) {
	return c.buildComponent(ctx, "agent", name)
}

// BuildTool rebuilds a tool from source.
func (c *Client) BuildTool(ctx context.Context, name string) (*BuildResult, error) {
	return c.buildComponent(ctx, "tool", name)
}

// BuildPlugin rebuilds a plugin from source.
func (c *Client) BuildPlugin(ctx context.Context, name string) (*BuildResult, error) {
	return c.buildComponent(ctx, "plugin", name)
}

// buildComponent is the internal method that builds a component via the daemon.
func (c *Client) buildComponent(ctx context.Context, kind, name string) (*BuildResult, error) {
	resp, err := c.daemon.BuildComponent(ctx, &api.BuildComponentRequest{
		Kind: kind,
		Name: name,
	})
	if err != nil {
		// Wrap error with user-friendly message
		if st, ok := status.FromError(err); ok {
			switch st.Code() {
			case codes.Unavailable:
				return nil, fmt.Errorf("daemon not responding (is it running?)")
			case codes.NotFound:
				return nil, fmt.Errorf("component '%s' not found", name)
			case codes.InvalidArgument:
				return nil, fmt.Errorf("invalid component kind or name: %s", st.Message())
			default:
				return nil, fmt.Errorf("failed to build component: %s", st.Message())
			}
		}
		return nil, fmt.Errorf("failed to build component: %w", err)
	}

	return &BuildResult{
		Success:  resp.Success,
		Stdout:   resp.Stdout,
		Stderr:   resp.Stderr,
		Duration: time.Duration(resp.DurationMs) * time.Millisecond,
	}, nil
}

// ComponentInfo represents detailed information about a component.
type ComponentInfo struct {
	Name      string
	Version   string
	Kind      string
	Status    string
	Source    string
	RepoPath  string
	BinPath   string
	Port      int
	PID       int
	CreatedAt time.Time
	UpdatedAt time.Time
	StartedAt *time.Time
	StoppedAt *time.Time
	Manifest  string // JSON-encoded manifest info
}

// ShowAgent retrieves detailed information about an agent.
func (c *Client) ShowAgent(ctx context.Context, name string) (*ComponentInfo, error) {
	return c.showComponent(ctx, "agent", name)
}

// ShowTool retrieves detailed information about a tool.
func (c *Client) ShowTool(ctx context.Context, name string) (*ComponentInfo, error) {
	return c.showComponent(ctx, "tool", name)
}

// ShowPlugin retrieves detailed information about a plugin.
func (c *Client) ShowPlugin(ctx context.Context, name string) (*ComponentInfo, error) {
	return c.showComponent(ctx, "plugin", name)
}

// showComponent is the internal method that retrieves component details via the daemon.
func (c *Client) showComponent(ctx context.Context, kind, name string) (*ComponentInfo, error) {
	resp, err := c.daemon.ShowComponent(ctx, &api.ShowComponentRequest{
		Kind: kind,
		Name: name,
	})
	if err != nil {
		// Wrap error with user-friendly message
		if st, ok := status.FromError(err); ok {
			switch st.Code() {
			case codes.Unavailable:
				return nil, fmt.Errorf("daemon not responding (is it running?)")
			case codes.NotFound:
				return nil, fmt.Errorf("component '%s' not found", name)
			case codes.InvalidArgument:
				return nil, fmt.Errorf("invalid component kind or name: %s", st.Message())
			default:
				return nil, fmt.Errorf("failed to get component info: %s", st.Message())
			}
		}
		return nil, fmt.Errorf("failed to get component info: %w", err)
	}

	if !resp.Success {
		return nil, fmt.Errorf("failed to get component info: %s", resp.Message)
	}

	info := &ComponentInfo{
		Name:      resp.Name,
		Version:   resp.Version,
		Kind:      resp.Kind,
		Status:    resp.Status,
		Source:    resp.Source,
		RepoPath:  resp.RepoPath,
		BinPath:   resp.BinPath,
		Port:      int(resp.Port),
		PID:       int(resp.Pid),
		CreatedAt: time.Unix(resp.CreatedAt, 0),
		UpdatedAt: time.Unix(resp.UpdatedAt, 0),
		Manifest:  resp.ManifestInfo,
	}

	// Handle optional timestamps
	if resp.StartedAt > 0 {
		t := time.Unix(resp.StartedAt, 0)
		info.StartedAt = &t
	}
	if resp.StoppedAt > 0 {
		t := time.Unix(resp.StoppedAt, 0)
		info.StoppedAt = &t
	}

	return info, nil
}

// LogsOptions contains options for retrieving component logs.
type LogsOptions struct {
	Follow bool // Stream logs continuously
	Lines  int  // Number of lines to return (default 50)
}

// LogEntry represents a single log entry from a component.
type LogEntry struct {
	Timestamp time.Time
	Level     string
	Message   string
	Fields    map[string]string
}

// GetAgentLogs retrieves log entries for an agent.
func (c *Client) GetAgentLogs(ctx context.Context, name string, opts LogsOptions) (<-chan LogEntry, error) {
	return c.getComponentLogs(ctx, "agent", name, opts)
}

// GetToolLogs retrieves log entries for a tool.
func (c *Client) GetToolLogs(ctx context.Context, name string, opts LogsOptions) (<-chan LogEntry, error) {
	return c.getComponentLogs(ctx, "tool", name, opts)
}

// GetPluginLogs retrieves log entries for a plugin.
func (c *Client) GetPluginLogs(ctx context.Context, name string, opts LogsOptions) (<-chan LogEntry, error) {
	return c.getComponentLogs(ctx, "plugin", name, opts)
}

// getComponentLogs is the internal method that retrieves component logs via the daemon.
func (c *Client) getComponentLogs(ctx context.Context, kind, name string, opts LogsOptions) (<-chan LogEntry, error) {
	// Start streaming RPC
	stream, err := c.daemon.GetComponentLogs(ctx, &api.GetComponentLogsRequest{
		Kind:   kind,
		Name:   name,
		Follow: opts.Follow,
		Lines:  int32(opts.Lines),
	})
	if err != nil {
		// Wrap error with user-friendly message
		if st, ok := status.FromError(err); ok {
			switch st.Code() {
			case codes.Unavailable:
				return nil, fmt.Errorf("daemon not responding (is it running?)")
			case codes.NotFound:
				return nil, fmt.Errorf("component '%s' not found or no logs available", name)
			case codes.InvalidArgument:
				return nil, fmt.Errorf("invalid component kind or name: %s", st.Message())
			default:
				return nil, fmt.Errorf("failed to get component logs: %s", st.Message())
			}
		}
		return nil, fmt.Errorf("failed to get component logs: %w", err)
	}

	// Create log channel and spawn goroutine to read from stream
	logChan := make(chan LogEntry, 50) // Buffer for high-frequency logs
	go func() {
		defer close(logChan)
		for {
			entry, err := stream.Recv()
			if err == io.EOF {
				// Stream completed normally
				return
			}
			if err != nil {
				// Check if context was cancelled
				if ctx.Err() != nil {
					return
				}
				// Stream error - exit
				return
			}

			// Convert TypedMap fields to map[string]string
			var fields map[string]string
			if entry.Fields != nil {
				rawFields := api.TypedMapToMap(entry.Fields)
				fields = make(map[string]string, len(rawFields))
				for k, v := range rawFields {
					fields[k] = fmt.Sprintf("%v", v)
				}
			}

			// Convert and send log entry
			select {
			case logChan <- LogEntry{
				Timestamp: time.Unix(entry.Timestamp, 0),
				Level:     entry.Level,
				Message:   entry.Message,
				Fields:    fields,
			}:
			case <-ctx.Done():
				return
			}
		}
	}()

	return logChan, nil
}

// PauseMission pauses a running mission at the next clean checkpoint.
//
// This method triggers a graceful pause of the specified mission. The mission
// will complete its current node execution and save a checkpoint before pausing.
// If force is true, the mission will pause immediately without waiting for a
// clean checkpoint boundary.
//
// Parameters:
//   - ctx: Context for the RPC call
//   - missionID: ID of the mission to pause
//   - force: If true, pause immediately without waiting for clean boundary
//
// Returns:
//   - checkpointID: ID of the checkpoint created during pause
//   - error: Non-nil if the pause operation fails
func (c *Client) PauseMission(ctx context.Context, missionID string, force bool) (string, error) {
	resp, err := c.daemon.PauseMission(ctx, &api.PauseMissionRequest{
		MissionId: missionID,
		Force:     force,
	})
	if err != nil {
		// Wrap error with user-friendly message
		if st, ok := status.FromError(err); ok {
			switch st.Code() {
			case codes.Unavailable:
				return "", fmt.Errorf("daemon not responding (is it running?)")
			case codes.NotFound:
				return "", fmt.Errorf("mission not found: %s", missionID)
			case codes.FailedPrecondition:
				return "", fmt.Errorf("mission is not running: %s", missionID)
			default:
				return "", fmt.Errorf("failed to pause mission: %s", st.Message())
			}
		}
		return "", fmt.Errorf("failed to pause mission: %w", err)
	}

	if !resp.Success {
		return "", fmt.Errorf("failed to pause mission: %s", resp.Message)
	}

	return resp.CheckpointId, nil
}

// ResumeMission resumes a paused mission from its last checkpoint.
//
// This method resumes execution of a paused mission, restoring its state from
// the last saved checkpoint. Events are streamed back via the returned channel
// similar to RunMission.
//
// Parameters:
//   - ctx: Context for the RPC call
//   - missionID: ID of the mission to resume
//   - fromCheckpoint: Optional specific checkpoint ID to resume from (empty for latest)
//
// Returns:
//   - <-chan MissionEvent: Channel streaming mission events during execution
//   - error: Non-nil if the resume operation fails to start
func (c *Client) ResumeMission(ctx context.Context, missionID string, fromCheckpoint string) (<-chan MissionEvent, error) {
	stream, err := c.daemon.ResumeMission(ctx, &api.ResumeMissionRequest{
		MissionId:    missionID,
		CheckpointId: fromCheckpoint,
	})
	if err != nil {
		// Wrap error with user-friendly message
		if st, ok := status.FromError(err); ok {
			switch st.Code() {
			case codes.Unavailable:
				return nil, fmt.Errorf("daemon not responding (is it running?)")
			case codes.NotFound:
				return nil, fmt.Errorf("mission not found: %s", missionID)
			case codes.FailedPrecondition:
				return nil, fmt.Errorf("mission cannot be resumed (wrong status or no checkpoint)")
			default:
				return nil, fmt.Errorf("failed to resume mission: %s", st.Message())
			}
		}
		return nil, fmt.Errorf("failed to resume mission: %w", err)
	}

	// Stream events in background goroutine
	eventChan := make(chan MissionEvent, 10)
	go func() {
		defer close(eventChan)
		for {
			event, err := stream.Recv()
			if err == io.EOF {
				return
			}
			if err != nil {
				// Send error event
				eventChan <- MissionEvent{
					Type:      "error",
					Timestamp: time.Now(),
					Message:   fmt.Sprintf("stream error: %v", err),
				}
				return
			}

			// Convert proto event to client event
			// Convert TypedMap data to map[string]interface{}
			var data map[string]interface{}
			if event.Data != nil {
				data = api.TypedMapToMap(event.Data)
			}

			eventChan <- MissionEvent{
				Type:      event.EventType,
				Timestamp: time.Unix(event.Timestamp, 0),
				Message:   event.Message,
				Data:      data,
			}
		}
	}()

	return eventChan, nil
}

// MissionRun represents a single execution run of a mission with a given name.
type MissionRun struct {
	MissionID     string
	RunNumber     int
	Status        string
	CreatedAt     time.Time
	CompletedAt   *time.Time
	FindingsCount int
}

// GetMissionHistory returns all runs for a mission name.
//
// This method retrieves the complete history of executions for a given mission
// name, including all run numbers, statuses, and timestamps. Runs are returned
// in chronological order (most recent first).
//
// Parameters:
//   - ctx: Context for the RPC call
//   - name: Name of the mission to get history for
//   - limit: Maximum number of runs to return (0 for all)
//   - offset: Number of runs to skip for pagination
//
// Returns:
//   - []MissionRun: List of mission runs
//   - int: Total number of runs available
//   - error: Non-nil if the query fails
func (c *Client) GetMissionHistory(ctx context.Context, name string, limit, offset int) ([]MissionRun, int, error) {
	resp, err := c.daemon.GetMissionHistory(ctx, &api.GetMissionHistoryRequest{
		Name:   name,
		Limit:  int32(limit),
		Offset: int32(offset),
	})
	if err != nil {
		// Wrap error with user-friendly message
		if st, ok := status.FromError(err); ok {
			switch st.Code() {
			case codes.Unavailable:
				return nil, 0, fmt.Errorf("daemon not responding (is it running?)")
			case codes.NotFound:
				return nil, 0, fmt.Errorf("no missions found with name: %s", name)
			default:
				return nil, 0, fmt.Errorf("failed to get mission history: %s", st.Message())
			}
		}
		return nil, 0, fmt.Errorf("failed to get mission history: %w", err)
	}

	// Convert proto runs to client runs
	runs := make([]MissionRun, len(resp.Runs))
	for i, r := range resp.Runs {
		run := MissionRun{
			MissionID:     r.MissionId,
			RunNumber:     int(r.RunNumber),
			Status:        r.Status,
			CreatedAt:     time.Unix(r.CreatedAt, 0),
			FindingsCount: int(r.FindingsCount),
		}
		if r.CompletedAt > 0 {
			t := time.Unix(r.CompletedAt, 0)
			run.CompletedAt = &t
		}
		runs[i] = run
	}

	return runs, int(resp.Total), nil
}

// MissionCheckpoint represents a saved checkpoint of mission execution state.
type MissionCheckpoint struct {
	CheckpointID   string
	CreatedAt      time.Time
	CompletedNodes int
	TotalNodes     int
	FindingsCount  int
}

// GetMissionCheckpoints returns all checkpoints for a mission.
//
// This method retrieves all saved checkpoints for the specified mission,
// sorted by creation time (most recent first). Each checkpoint contains
// metadata about the mission state at the time it was saved.
//
// Parameters:
//   - ctx: Context for the RPC call
//   - missionID: ID of the mission to get checkpoints for
//
// Returns:
//   - []MissionCheckpoint: List of checkpoints
//   - error: Non-nil if the query fails
func (c *Client) GetMissionCheckpoints(ctx context.Context, missionID string) ([]MissionCheckpoint, error) {
	resp, err := c.daemon.GetMissionCheckpoints(ctx, &api.GetMissionCheckpointsRequest{
		MissionId: missionID,
	})
	if err != nil {
		// Wrap error with user-friendly message
		if st, ok := status.FromError(err); ok {
			switch st.Code() {
			case codes.Unavailable:
				return nil, fmt.Errorf("daemon not responding (is it running?)")
			case codes.NotFound:
				return nil, fmt.Errorf("mission not found: %s", missionID)
			default:
				return nil, fmt.Errorf("failed to get checkpoints: %s", st.Message())
			}
		}
		return nil, fmt.Errorf("failed to get checkpoints: %w", err)
	}

	// Convert proto checkpoints to client checkpoints
	checkpoints := make([]MissionCheckpoint, len(resp.Checkpoints))
	for i, cp := range resp.Checkpoints {
		checkpoints[i] = MissionCheckpoint{
			CheckpointID:   cp.CheckpointId,
			CreatedAt:      time.Unix(cp.CreatedAt, 0),
			CompletedNodes: int(cp.CompletedNodes),
			TotalNodes:     int(cp.TotalNodes),
			FindingsCount:  int(cp.FindingsCount),
		}
	}

	return checkpoints, nil
}

// Mission installation and management types

// MissionInstallOptions contains options for installing a mission
type MissionInstallOptions struct {
	Branch  string        // Git branch to install
	Tag     string        // Git tag to install
	Force   bool          // Force reinstall if exists
	Yes     bool          // Auto-confirm dependency installation
	Timeout time.Duration // Installation timeout
}

// MissionInstallResult represents the result of a mission installation
type MissionInstallResult struct {
	Name         string                           // Mission name
	Version      string                           // Mission version
	Duration     time.Duration                    // Installation duration
	Dependencies []MissionDependencyInstallResult // Installed dependencies
}

// MissionDependencyInstallResult represents an installed dependency
type MissionDependencyInstallResult struct {
	Type             string // agent, tool, or plugin
	Name             string // Dependency name
	AlreadyInstalled bool   // Was it already installed
}

// MissionUpdateOptions contains options for updating a mission
type MissionUpdateOptions struct {
	// Currently empty but here for future expansion
}

// MissionUpdateResult represents the result of a mission update
type MissionUpdateResult struct {
	Name       string        // Mission name
	Updated    bool          // Was the mission actually updated
	OldVersion string        // Version before update
	NewVersion string        // Version after update
	Duration   time.Duration // Update duration
}

// MissionDefinition represents an installed mission definition
type MissionDefinition struct {
	Name         string                  // Mission name
	Version      string                  // Mission version
	Description  string                  // Mission description
	Source       string                  // Git URL source
	InstalledAt  time.Time               // Installation timestamp
	Dependencies *MissionDependencyList  // Required dependencies
	Nodes        map[string]*MissionNode // Mission nodes
	Edges        []MissionEdge           // Mission edges
	EntryPoints  []string                // Entry point node IDs
	ExitPoints   []string                // Exit point node IDs
}

// MissionDependencyList contains lists of required dependencies
type MissionDependencyList struct {
	Agents  []string
	Tools   []string
	Plugins []string
}

// MissionNode represents a node in a mission DAG
type MissionNode struct {
	ID   string
	Type string
	Name string
}

// MissionEdge represents an edge in a mission DAG
type MissionEdge struct {
	From string
	To   string
}

// InstallMission installs a mission from a git repository URL
func (c *Client) InstallMission(ctx context.Context, url string, opts MissionInstallOptions) (*MissionInstallResult, error) {
	// TODO: This will be implemented when the gRPC methods are added (task 7.1/7.2)
	// For now, return an error indicating the feature is not yet available
	return nil, fmt.Errorf("mission installation via daemon not yet implemented (requires gRPC methods from task 7.1/7.2)")
}

// UninstallMission uninstalls an installed mission
func (c *Client) UninstallMission(ctx context.Context, name string, force bool) error {
	// TODO: This will be implemented when the gRPC methods are added (task 7.1/7.2)
	return fmt.Errorf("mission uninstallation via daemon not yet implemented (requires gRPC methods from task 7.1/7.2)")
}

// UpdateMission updates an installed mission to the latest version
func (c *Client) UpdateMission(ctx context.Context, name string, opts MissionUpdateOptions) (*MissionUpdateResult, error) {
	// TODO: This will be implemented when the gRPC methods are added (task 7.1/7.2)
	return nil, fmt.Errorf("mission update via daemon not yet implemented (requires gRPC methods from task 7.1/7.2)")
}

// GetMissionDefinition retrieves an installed mission definition
func (c *Client) GetMissionDefinition(ctx context.Context, name string) (*MissionDefinition, error) {
	// TODO: This will be implemented when the gRPC methods are added (task 7.1/7.2)
	return nil, fmt.Errorf("mission definition retrieval via daemon not yet implemented (requires gRPC methods from task 7.1/7.2)")
}

// ListMissionDefinitions lists all installed mission definitions
func (c *Client) ListMissionDefinitions(ctx context.Context) ([]*MissionDefinition, error) {
	// TODO: This will be implemented when the gRPC methods are added (task 7.1/7.2)
	return nil, fmt.Errorf("mission definition listing via daemon not yet implemented (requires gRPC methods from task 7.1/7.2)")
}

// ValidationResult contains the outcome of dependency validation.
// It provides comprehensive information about the state of all components
// in a dependency tree, including counts, problem components, and version mismatches.
type ValidationResult struct {
	// Valid is true if all dependencies are satisfied and running
	Valid bool `json:"valid" yaml:"valid"`

	// Summary is a human-readable summary of the validation result
	Summary string `json:"summary" yaml:"summary"`

	// TotalComponents is the total number of components in the dependency tree
	TotalComponents int `json:"totalComponents" yaml:"totalComponents"`

	// InstalledCount is the number of components that are installed
	InstalledCount int `json:"installedCount" yaml:"installedCount"`

	// RunningCount is the number of components that are currently running
	RunningCount int `json:"runningCount" yaml:"runningCount"`

	// HealthyCount is the number of components that are healthy
	HealthyCount int `json:"healthyCount" yaml:"healthyCount"`

	// NotInstalled contains components that are not installed
	NotInstalled []*DependencyNode `json:"notInstalled,omitempty" yaml:"notInstalled,omitempty"`

	// NotRunning contains components that are installed but not running
	NotRunning []*DependencyNode `json:"notRunning,omitempty" yaml:"notRunning,omitempty"`

	// Unhealthy contains components that are running but not healthy
	Unhealthy []*DependencyNode `json:"unhealthy,omitempty" yaml:"unhealthy,omitempty"`

	// VersionMismatch contains components with version constraint violations
	VersionMismatch []*VersionMismatchInfo `json:"versionMismatch,omitempty" yaml:"versionMismatch,omitempty"`

	// ValidatedAt is the timestamp when validation was performed
	ValidatedAt time.Time `json:"validatedAt" yaml:"validatedAt"`

	// Duration is how long the validation took
	Duration time.Duration `json:"duration" yaml:"duration"`
}

// DependencyNode represents a single component in the dependency tree.
type DependencyNode struct {
	// Identity fields
	Kind    string `json:"kind" yaml:"kind"`       // Type of component (agent, tool, plugin)
	Name    string `json:"name" yaml:"name"`       // Component name
	Version string `json:"version" yaml:"version"` // Required version (semantic version or constraint)

	// Source tracking
	Source    string `json:"source" yaml:"source"`         // Where this dependency requirement came from
	SourceRef string `json:"source_ref" yaml:"source_ref"` // Reference to the source (mission ID, node ID, component name)

	// Current state (populated by resolution)
	Installed     bool   `json:"installed" yaml:"installed"`                     // True if component is registered in the component store
	Running       bool   `json:"running" yaml:"running"`                         // True if component is currently running
	Healthy       bool   `json:"healthy" yaml:"healthy"`                         // True if component passed health checks
	ActualVersion string `json:"actual_version,omitempty" yaml:"actual_version"` // Actual installed version (may differ from required)
}

// VersionMismatchInfo describes a version constraint violation.
type VersionMismatchInfo struct {
	// Node is the dependency node with the version mismatch
	Node *DependencyNode `json:"node" yaml:"node"`

	// RequiredVersion is the version constraint that was specified
	RequiredVersion string `json:"requiredVersion" yaml:"requiredVersion"`

	// ActualVersion is the version that is actually installed
	ActualVersion string `json:"actualVersion" yaml:"actualVersion"`
}

// ValidateMissionDependencies validates that all dependencies required by a mission workflow
// are installed, running, and healthy. This method connects to the daemon's dependency
// resolver to build a complete dependency tree and validate component state.
//
// Parameters:
//   - ctx: Context for the RPC call
//   - workflowPath: Absolute path to the workflow YAML file
//
// Returns:
//   - *ValidationResult: Detailed validation results with component states
//   - error: Non-nil if the validation process fails (not if validation finds issues)
//
// Example:
//
//	result, err := client.ValidateMissionDependencies(ctx, "/path/to/workflow.yaml")
//	if err != nil {
//	    return fmt.Errorf("validation failed: %w", err)
//	}
//	if !result.Valid {
//	    fmt.Printf("Validation issues: %s\n", result.Summary)
//	}
func (c *Client) ValidateMissionDependencies(ctx context.Context, workflowPath string) (*ValidationResult, error) {
	// TODO: This will be implemented when the gRPC methods are added
	// For now, return an error indicating the feature is not yet available
	return nil, fmt.Errorf("mission dependency validation via daemon not yet implemented (requires gRPC methods and daemon integration)")
}
