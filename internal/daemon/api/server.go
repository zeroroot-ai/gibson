package api

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zero-day-ai/gibson/internal/mission"
)

// DaemonServer implements the DaemonServiceServer interface.
//
// This server exposes all daemon functionality via gRPC including mission
// execution, agent management, attack operations, and real-time event streaming.
// It acts as a facade that delegates to the daemon's internal services.
type DaemonServer struct {
	UnimplementedDaemonServiceServer

	// daemon is the daemon instance this server exposes
	daemon DaemonInterface

	// logger is the structured logger
	logger *slog.Logger

	// sessionCounter generates unique session IDs
	sessionCounter int64
}

// DaemonInterface defines the interface that the daemon must implement
// for the gRPC server to delegate operations.
//
// This abstraction allows the server to work with the daemon without
// creating circular dependencies.
type DaemonInterface interface {
	// Status returns the current daemon status
	Status() (DaemonStatus, error)

	// ListAgents returns all registered agents
	ListAgents(ctx context.Context, kind string) ([]AgentInfoInternal, error)

	// GetAgentStatus returns status for a specific agent
	GetAgentStatus(ctx context.Context, agentID string) (AgentStatusInternal, error)

	// ListTools returns all registered tools
	ListTools(ctx context.Context) ([]ToolInfoInternal, error)

	// ListPlugins returns all registered plugins
	ListPlugins(ctx context.Context) ([]PluginInfoInternal, error)

	// QueryPlugin executes a method on a plugin
	QueryPlugin(ctx context.Context, name, method string, params map[string]any) (any, error)

	// RunMission starts a mission and returns an event channel
	RunMission(ctx context.Context, workflowPath string, missionID string, variables map[string]string, memoryContinuity string) (<-chan MissionEventData, error)

	// StopMission stops a running mission
	StopMission(ctx context.Context, missionID string, force bool) error

	// ListMissions returns mission list
	ListMissions(ctx context.Context, activeOnly bool, statusFilter, namePattern string, limit, offset int) ([]MissionData, int, error)

	// RunAttack executes an attack and returns an event channel
	RunAttack(ctx context.Context, req AttackRequest) (<-chan AttackEventData, error)

	// Subscribe establishes an event stream
	Subscribe(ctx context.Context, eventTypes []string, missionID string) (<-chan EventData, error)

	// StartComponent starts a component by kind and name
	StartComponent(ctx context.Context, kind string, name string) (StartComponentResult, error)

	// StopComponent stops a component by kind and name
	StopComponent(ctx context.Context, kind string, name string, force bool) (StopComponentResult, error)

	// PauseMission pauses a running mission at the next clean checkpoint boundary
	PauseMission(ctx context.Context, missionID string, force bool) error

	// ResumeMission resumes a paused mission from its last checkpoint
	ResumeMission(ctx context.Context, missionID string) (<-chan MissionEventData, error)

	// GetMissionHistory returns all runs for a mission name
	GetMissionHistory(ctx context.Context, name string, limit int, offset int) ([]MissionRunData, int, error)

	// GetMissionCheckpoints returns all checkpoints for a mission
	GetMissionCheckpoints(ctx context.Context, missionID string) ([]CheckpointData, error)

	// InstallComponent installs a component from a git repository
	InstallComponent(ctx context.Context, kind string, url string, branch string, tag string, force bool, skipBuild bool, verbose bool) (InstallComponentResult, error)

	// InstallAllComponent installs all components from a mono-repo
	InstallAllComponent(ctx context.Context, kind string, url string, branch string, tag string, force bool, skipBuild bool, verbose bool) (InstallAllComponentResult, error)

	// UninstallComponent uninstalls a component by kind and name
	UninstallComponent(ctx context.Context, kind string, name string, force bool) error

	// UpdateComponent updates a component to the latest version
	UpdateComponent(ctx context.Context, kind string, name string, restart bool, skipBuild bool, verbose bool) (UpdateComponentResult, error)

	// BuildComponent rebuilds a component from source
	BuildComponent(ctx context.Context, kind string, name string) (BuildComponentResult, error)

	// ShowComponent returns detailed information about a component
	ShowComponent(ctx context.Context, kind string, name string) (ComponentInfoInternal, error)

	// GetComponentLogs streams log entries for a component
	GetComponentLogs(ctx context.Context, kind string, name string, follow bool, lines int) (<-chan LogEntryData, error)

	// InstallMission installs a mission from a git repository
	InstallMission(ctx context.Context, url string, branch string, tag string, force bool, yes bool, timeoutMs int64) (InstallMissionResult, error)

	// UninstallMission removes an installed mission
	UninstallMission(ctx context.Context, name string, force bool) error

	// ListMissionDefinitions returns all installed mission definitions
	ListMissionDefinitions(ctx context.Context, limit int, offset int) ([]MissionDefinitionData, int, error)

	// UpdateMission updates an installed mission to the latest version
	UpdateMission(ctx context.Context, name string, timeoutMs int64) (UpdateMissionResult, error)

	// ResolveMissionDependencies resolves and returns the dependency tree for a mission workflow
	ResolveMissionDependencies(ctx context.Context, missionPath string) (DependencyTreeData, error)

	// ValidateMissionDependencies validates the state of all dependencies for a mission workflow
	ValidateMissionDependencies(ctx context.Context, missionPath string) (ValidationResultData, error)

	// EnsureMissionDependencies ensures all dependencies for a mission workflow are running
	EnsureMissionDependencies(ctx context.Context, missionPath string) error
}

// DaemonStatus represents daemon status information.
type DaemonStatus struct {
	Running            bool
	PID                int32
	StartTime          time.Time
	Uptime             string
	GRPCAddress        string
	RegistryType       string
	RegistryAddr       string
	CallbackAddr       string
	AgentCount         int32
	MissionCount       int32
	ActiveMissionCount int32
}

// AgentInfoInternal represents agent information for internal daemon operations.
// This is separate from the proto-generated AgentInfo to avoid naming conflicts.
type AgentInfoInternal struct {
	ID           string
	Name         string
	Kind         string
	Version      string
	Endpoint     string
	Capabilities []string
	Health       string
	LastSeen     time.Time
}

// AgentStatusInternal represents detailed agent status for internal daemon operations.
// This is separate from the proto-generated types to avoid naming conflicts.
type AgentStatusInternal struct {
	Agent         AgentInfoInternal
	Active        bool
	CurrentTask   string
	TaskStartTime time.Time
}

// ToolInfoInternal represents tool information for internal daemon operations.
// This is separate from the proto-generated ToolInfo to avoid naming conflicts.
type ToolInfoInternal struct {
	ID           string
	Name         string
	Version      string
	Endpoint     string
	Description  string
	Health       string
	LastSeen     time.Time
	Capabilities *Capabilities
}

// PluginInfoInternal represents plugin information for internal daemon operations.
// This is separate from the proto-generated PluginInfo to avoid naming conflicts.
type PluginInfoInternal struct {
	ID          string
	Name        string
	Version     string
	Endpoint    string
	Description string
	Health      string
	LastSeen    time.Time
}

// MissionData represents mission information.
type MissionData struct {
	ID           string
	Name         string
	WorkflowPath string
	Status       string
	StartTime    time.Time
	EndTime      time.Time
	FindingCount int32
}

// MissionEventData represents mission event data from the daemon.
type MissionEventData struct {
	EventType string
	Timestamp time.Time
	MissionID string
	NodeID    string
	Message   string
	Data      string
	Error     string
	Result    *OperationResult
	Payload   map[string]interface{} // Additional payload data (workflow_name, duration, status, etc.)
}

// AttackRequest represents an attack request.
type AttackRequest struct {
	Target        string
	TargetName    string
	AttackType    string
	AgentID       string
	PayloadFilter string
	Options       map[string]string
}

// AttackEventData represents attack event data from the daemon.
type AttackEventData struct {
	EventType string
	Timestamp time.Time
	AttackID  string
	Message   string
	Data      string
	Error     string
	Finding   *FindingData
	Result    *OperationResult
}

// FindingData represents finding information.
type FindingData struct {
	ID          string
	Title       string
	Severity    string
	Category    string
	Description string
	Technique   string
	Evidence    string
	Timestamp   time.Time
}

// EventData represents a generic event from the daemon.
type EventData struct {
	EventType    string
	Timestamp    time.Time
	Source       string
	Data         string
	Metadata     map[string]interface{} // Additional metadata (e.g., trace_id, span_id, parent_span_id)
	MissionEvent *MissionEventData
	AttackEvent  *AttackEventData
	AgentEvent   *AgentEventData
	FindingEvent *FindingEventData
}

// AgentEventData represents agent event data.
type AgentEventData struct {
	EventType string
	Timestamp time.Time
	AgentID   string
	AgentName string
	Message   string
	Data      string
	Metadata  map[string]interface{} // Additional metadata (duration, output_summary, etc.)
}

// FindingEventData represents finding event data.
type FindingEventData struct {
	EventType string
	Timestamp time.Time
	Finding   FindingData
	MissionID string
}

// StartComponentResult represents the result of starting a component.
type StartComponentResult struct {
	PID     int
	Port    int
	LogPath string
}

// StopComponentResult represents the result of stopping a component.
type StopComponentResult struct {
	StoppedCount int
	TotalCount   int
}

// InstallComponentResult represents the result of installing a component.
type InstallComponentResult struct {
	Name        string
	Version     string
	RepoPath    string
	BinPath     string
	BuildOutput string
	DurationMs  int64
}

// InstallAllComponentResult represents the result of installing multiple components.
type InstallAllComponentResult struct {
	Success         bool
	ComponentsFound int
	SuccessfulCount int
	SkippedCount    int
	FailedCount     int
	Successful      []InstallAllResultItem
	Skipped         []InstallAllResultItem
	Failed          []InstallAllFailedItem
	DurationMs      int64
	Message         string
}

// UpdateComponentResult represents the result of updating a component.
type UpdateComponentResult struct {
	Updated     bool
	OldVersion  string
	NewVersion  string
	BuildOutput string
	DurationMs  int64
}

// BuildComponentResult represents the result of building a component.
type BuildComponentResult struct {
	Success    bool
	Stdout     string
	Stderr     string
	DurationMs int64
}

// ComponentInfoInternal represents detailed component information.
type ComponentInfoInternal struct {
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
}

// LogEntryData represents a single log entry.
type LogEntryData struct {
	Timestamp int64
	Level     string
	Message   string
}

// MissionRunData represents a single execution instance of a mission.
type MissionRunData struct {
	MissionID     string
	RunNumber     int
	Status        string
	CreatedAt     int64
	CompletedAt   int64
	FindingsCount int
	PreviousRunID string
}

// CheckpointData provides metadata about a mission checkpoint.
type CheckpointData struct {
	CheckpointID   string
	CreatedAt      int64
	CompletedNodes int
	TotalNodes     int
	FindingsCount  int
	Version        int
}

// InstallMissionResult represents the result of installing a mission.
type InstallMissionResult struct {
	Name         string
	Version      string
	Path         string
	Dependencies []InstalledDependencyData
	DurationMs   int64
}

// InstalledDependencyData represents a dependency that was installed.
type InstalledDependencyData struct {
	Type             string
	Name             string
	AlreadyInstalled bool
}

// UpdateMissionResult represents the result of updating a mission.
type UpdateMissionResult struct {
	Updated    bool
	OldVersion string
	NewVersion string
	DurationMs int64
}

// MissionDefinitionData represents an installed mission definition.
type MissionDefinitionData struct {
	Name        string
	Version     string
	Description string
	Source      string
	InstalledAt time.Time
	UpdatedAt   time.Time
	NodeCount   int
}

// DependencyTreeData represents the complete dependency graph for a mission.
type DependencyTreeData struct {
	MissionRef  string
	ResolvedAt  time.Time
	TotalNodes  int
	AgentCount  int
	ToolCount   int
	PluginCount int
	Nodes       []DependencyNodeData
}

// DependencyNodeData represents a single component in the dependency tree.
type DependencyNodeData struct {
	Kind          string
	Name          string
	Version       string
	Source        string
	SourceRef     string
	Installed     bool
	Running       bool
	Healthy       bool
	ActualVersion string
}

// ValidationResultData contains the outcome of dependency validation.
type ValidationResultData struct {
	Valid                bool
	Summary              string
	TotalComponents      int
	InstalledCount       int
	RunningCount         int
	HealthyCount         int
	NotInstalledCount    int
	NotRunningCount      int
	UnhealthyCount       int
	VersionMismatchCount int
	ValidatedAt          time.Time
	DurationMs           int64
	NotInstalled         []DependencyNodeData
	NotRunning           []DependencyNodeData
	Unhealthy            []DependencyNodeData
	VersionMismatch      []VersionMismatchData
}

// VersionMismatchData describes a version constraint violation.
type VersionMismatchData struct {
	ComponentKind   string
	ComponentName   string
	RequiredVersion string
	ActualVersion   string
}

// NewDaemonServer creates a new gRPC server that exposes daemon functionality.
//
// Parameters:
//   - daemon: The daemon instance to expose via gRPC
//   - logger: Structured logger for request logging
//
// Returns:
//   - *DaemonServer: A new gRPC server ready to be registered
func NewDaemonServer(daemon DaemonInterface, logger *slog.Logger) *DaemonServer {
	if logger == nil {
		logger = slog.Default().With("component", "daemon-grpc")
	}

	return &DaemonServer{
		daemon:         daemon,
		logger:         logger.With("component", "daemon-grpc"),
		sessionCounter: 0,
	}
}

// Connect establishes a client connection to the daemon.
func (s *DaemonServer) Connect(ctx context.Context, req *ConnectRequest) (*ConnectResponse, error) {
	s.logger.Info("client connecting",
		"client_version", req.ClientVersion,
		"client_id", req.ClientId,
	)

	// Generate unique session ID
	s.sessionCounter++
	sessionID := fmt.Sprintf("session-%d-%d", time.Now().Unix(), s.sessionCounter)

	// Get daemon status to include address
	status, err := s.daemon.Status()
	if err != nil {
		s.logger.Error("failed to get daemon status", "error", err)
		return nil, status_grpc.Errorf(codes.Internal, "failed to get daemon status: %v", err)
	}

	return &ConnectResponse{
		DaemonVersion: "0.1.0", // TODO: Get from version package
		SessionId:     sessionID,
		GrpcAddress:   status.GRPCAddress,
	}, nil
}

// Ping checks if the daemon is responsive.
func (s *DaemonServer) Ping(ctx context.Context, req *PingRequest) (*PingResponse, error) {
	return &PingResponse{
		Timestamp: time.Now().Unix(),
	}, nil
}

// Status returns the current daemon status.
func (s *DaemonServer) Status(ctx context.Context, req *StatusRequest) (*StatusResponse, error) {
	s.logger.Debug("status request received")

	status, err := s.daemon.Status()
	if err != nil {
		s.logger.Error("failed to get daemon status", "error", err)
		return nil, status_grpc.Errorf(codes.Internal, "failed to get daemon status: %v", err)
	}

	return &StatusResponse{
		Running:            status.Running,
		Pid:                status.PID,
		StartTime:          status.StartTime.Unix(),
		Uptime:             status.Uptime,
		GrpcAddress:        status.GRPCAddress,
		RegistryType:       status.RegistryType,
		RegistryAddr:       status.RegistryAddr,
		CallbackAddr:       status.CallbackAddr,
		AgentCount:         status.AgentCount,
		MissionCount:       status.MissionCount,
		ActiveMissionCount: status.ActiveMissionCount,
	}, nil
}

// RunMission starts a mission and streams execution events.
func (s *DaemonServer) RunMission(req *RunMissionRequest, stream grpc.ServerStreamingServer[MissionEvent]) error {
	s.logger.Info("mission run request received",
		"workflow_path", req.WorkflowPath,
		"workflow_yaml_size", len(req.WorkflowYaml),
		"mission_id", req.MissionId,
		"memory_continuity", req.MemoryContinuity,
	)

	// Determine workflow path to use
	var workflowPath string
	var cleanupTempFile func()

	if req.WorkflowYaml != "" {
		// Inline YAML provided - validate size (max 10MB)
		const maxYamlSize = 10 * 1024 * 1024 // 10MB
		if len(req.WorkflowYaml) > maxYamlSize {
			s.logger.Error("workflow YAML exceeds size limit",
				"size", len(req.WorkflowYaml),
				"max_size", maxYamlSize,
			)
			return status_grpc.Errorf(codes.InvalidArgument,
				"workflow YAML size (%d bytes) exceeds maximum allowed size (%d bytes)",
				len(req.WorkflowYaml), maxYamlSize)
		}

		// Validate YAML by parsing it
		if _, err := mission.ParseYAML([]byte(req.WorkflowYaml)); err != nil {
			s.logger.Error("failed to parse workflow YAML", "error", err)
			return status_grpc.Errorf(codes.InvalidArgument, "invalid workflow YAML: %v", err)
		}

		// Write to temporary file
		tmpFile, err := os.CreateTemp("", "gibson-mission-*.yaml")
		if err != nil {
			s.logger.Error("failed to create temporary file", "error", err)
			return status_grpc.Errorf(codes.Internal, "failed to create temporary file: %v", err)
		}
		workflowPath = tmpFile.Name()

		// Write YAML content
		if _, err := tmpFile.WriteString(req.WorkflowYaml); err != nil {
			tmpFile.Close()
			os.Remove(tmpFile.Name())
			s.logger.Error("failed to write workflow YAML to temporary file", "error", err)
			return status_grpc.Errorf(codes.Internal, "failed to write workflow YAML: %v", err)
		}
		if err := tmpFile.Close(); err != nil {
			os.Remove(tmpFile.Name())
			s.logger.Error("failed to close temporary file", "error", err)
			return status_grpc.Errorf(codes.Internal, "failed to close temporary file: %v", err)
		}

		// Setup cleanup function to remove temp file when done
		cleanupTempFile = func() {
			if err := os.Remove(workflowPath); err != nil {
				s.logger.Warn("failed to remove temporary workflow file",
					"path", workflowPath,
					"error", err,
				)
			} else {
				s.logger.Debug("removed temporary workflow file", "path", workflowPath)
			}
		}
		defer cleanupTempFile()

		s.logger.Debug("wrote workflow YAML to temporary file", "path", workflowPath)
	} else if req.WorkflowPath != "" {
		// Use provided workflow path
		workflowPath = req.WorkflowPath
	} else {
		// Neither provided - return error
		s.logger.Error("neither workflow_path nor workflow_yaml provided")
		return status_grpc.Errorf(codes.InvalidArgument,
			"either workflow_path or workflow_yaml must be provided")
	}

	// Start mission and get event channel
	eventChan, err := s.daemon.RunMission(stream.Context(), workflowPath, req.MissionId, req.Variables, req.MemoryContinuity)
	if err != nil {
		s.logger.Error("failed to start mission", "error", err)
		return status_grpc.Errorf(codes.Internal, "failed to start mission: %v", err)
	}

	// Stream events to client
	for {
		select {
		case <-stream.Context().Done():
			s.logger.Info("mission stream cancelled", "mission_id", req.MissionId)
			return stream.Context().Err()

		case event, ok := <-eventChan:
			if !ok {
				// Event channel closed, mission completed
				s.logger.Info("mission completed", "mission_id", req.MissionId)
				return nil
			}

			// Convert event to proto message
			protoEvent := &MissionEvent{
				EventType: event.EventType,
				Timestamp: event.Timestamp.Unix(),
				MissionId: event.MissionID,
				NodeId:    event.NodeID,
				Message:   event.Message,
				Data:      StringToTypedMap(event.Data),
				Error:     event.Error,
			}

			// Send event to client
			if err := stream.Send(protoEvent); err != nil {
				s.logger.Error("failed to send mission event", "error", err)
				return status_grpc.Errorf(codes.Internal, "failed to send event: %v", err)
			}
		}
	}
}

// StopMission gracefully stops a running mission.
func (s *DaemonServer) StopMission(ctx context.Context, req *StopMissionRequest) (*StopMissionResponse, error) {
	s.logger.Info("mission stop request received",
		"mission_id", req.MissionId,
		"force", req.Force,
	)

	err := s.daemon.StopMission(ctx, req.MissionId, req.Force)
	if err != nil {
		s.logger.Error("failed to stop mission", "error", err, "mission_id", req.MissionId)
		return &StopMissionResponse{
			Success: false,
			Message: fmt.Sprintf("failed to stop mission: %v", err),
		}, nil
	}

	return &StopMissionResponse{
		Success: true,
		Message: "Mission stop requested",
	}, nil
}

// ListMissions returns all missions (past and active).
func (s *DaemonServer) ListMissions(ctx context.Context, req *ListMissionsRequest) (*ListMissionsResponse, error) {
	s.logger.Debug("mission list request received",
		"active_only", req.ActiveOnly,
		"status_filter", req.StatusFilter,
		"name_pattern", req.NamePattern,
		"limit", req.Limit,
		"offset", req.Offset,
	)

	missions, total, err := s.daemon.ListMissions(ctx, req.ActiveOnly, req.StatusFilter, req.NamePattern, int(req.Limit), int(req.Offset))
	if err != nil {
		s.logger.Error("failed to list missions", "error", err)
		return nil, status_grpc.Errorf(codes.Internal, "failed to list missions: %v", err)
	}

	// Convert to proto messages
	protoMissions := make([]*MissionInfo, len(missions))
	for i, m := range missions {
		protoMissions[i] = &MissionInfo{
			Id:           m.ID,
			Name:         m.Name,
			WorkflowPath: m.WorkflowPath,
			Status:       m.Status,
			StartTime:    m.StartTime.Unix(),
			EndTime:      m.EndTime.Unix(),
			FindingCount: m.FindingCount,
		}
	}

	return &ListMissionsResponse{
		Missions: protoMissions,
		Total:    int32(total),
	}, nil
}

// ListAgents returns all registered agents from the etcd registry.
func (s *DaemonServer) ListAgents(ctx context.Context, req *ListAgentsRequest) (*ListAgentsResponse, error) {
	s.logger.Debug("agent list request received", "kind", req.Kind)

	agents, err := s.daemon.ListAgents(ctx, req.Kind)
	if err != nil {
		s.logger.Error("failed to list agents", "error", err)
		return nil, status_grpc.Errorf(codes.Internal, "failed to list agents: %v", err)
	}

	// Convert to proto messages
	protoAgents := make([]*AgentInfo, len(agents))
	for i, a := range agents {
		protoAgents[i] = &AgentInfo{
			Id:           a.ID,
			Name:         a.Name,
			Kind:         a.Kind,
			Version:      a.Version,
			Endpoint:     a.Endpoint,
			Capabilities: a.Capabilities,
			Health:       a.Health,
			LastSeen:     a.LastSeen.Unix(),
		}
	}

	return &ListAgentsResponse{
		Agents: protoAgents,
	}, nil
}

// GetAgentStatus returns the current status of a specific agent.
func (s *DaemonServer) GetAgentStatus(ctx context.Context, req *GetAgentStatusRequest) (*AgentStatusResponse, error) {
	s.logger.Debug("agent status request received", "agent_id", req.AgentId)

	agentStatus, err := s.daemon.GetAgentStatus(ctx, req.AgentId)
	if err != nil {
		s.logger.Error("failed to get agent status", "error", err, "agent_id", req.AgentId)
		return nil, status_grpc.Errorf(codes.Internal, "failed to get agent status: %v", err)
	}

	return &AgentStatusResponse{
		Agent: &AgentInfo{
			Id:           agentStatus.Agent.ID,
			Name:         agentStatus.Agent.Name,
			Kind:         agentStatus.Agent.Kind,
			Version:      agentStatus.Agent.Version,
			Endpoint:     agentStatus.Agent.Endpoint,
			Capabilities: agentStatus.Agent.Capabilities,
			Health:       agentStatus.Agent.Health,
			LastSeen:     agentStatus.Agent.LastSeen.Unix(),
		},
		Active:        agentStatus.Active,
		CurrentTask:   agentStatus.CurrentTask,
		TaskStartTime: agentStatus.TaskStartTime.Unix(),
	}, nil
}

// ListTools returns all registered tools from the etcd registry.
func (s *DaemonServer) ListTools(ctx context.Context, req *ListToolsRequest) (*ListToolsResponse, error) {
	s.logger.Debug("tool list request received")

	tools, err := s.daemon.ListTools(ctx)
	if err != nil {
		s.logger.Error("failed to list tools", "error", err)
		return nil, status_grpc.Errorf(codes.Internal, "failed to list tools: %v", err)
	}

	// Convert to proto messages
	protoTools := make([]*ToolInfo, len(tools))
	for i, t := range tools {
		var protoCaps *Capabilities
		if t.Capabilities != nil {
			protoCaps = &Capabilities{
				HasRoot:         t.Capabilities.HasRoot,
				HasSudo:         t.Capabilities.HasSudo,
				CanRawSocket:    t.Capabilities.CanRawSocket,
				Features:        t.Capabilities.Features,
				BlockedArgs:     t.Capabilities.BlockedArgs,
				ArgAlternatives: t.Capabilities.ArgAlternatives,
			}
		}
		protoTools[i] = &ToolInfo{
			Id:           t.ID,
			Name:         t.Name,
			Version:      t.Version,
			Endpoint:     t.Endpoint,
			Description:  t.Description,
			Health:       t.Health,
			LastSeen:     t.LastSeen.Unix(),
			Capabilities: protoCaps,
		}
	}

	return &ListToolsResponse{
		Tools: protoTools,
	}, nil
}

// ListPlugins returns all registered plugins from the etcd registry.
func (s *DaemonServer) ListPlugins(ctx context.Context, req *ListPluginsRequest) (*ListPluginsResponse, error) {
	s.logger.Debug("plugin list request received")

	plugins, err := s.daemon.ListPlugins(ctx)
	if err != nil {
		s.logger.Error("failed to list plugins", "error", err)
		return nil, status_grpc.Errorf(codes.Internal, "failed to list plugins: %v", err)
	}

	// Convert to proto messages
	protoPlugins := make([]*PluginInfo, len(plugins))
	for i, p := range plugins {
		protoPlugins[i] = &PluginInfo{
			Id:          p.ID,
			Name:        p.Name,
			Version:     p.Version,
			Endpoint:    p.Endpoint,
			Description: p.Description,
			Health:      p.Health,
			LastSeen:    p.LastSeen.Unix(),
		}
	}

	return &ListPluginsResponse{
		Plugins: protoPlugins,
	}, nil
}

// QueryPlugin executes a method on a plugin and returns the result.
func (s *DaemonServer) QueryPlugin(ctx context.Context, req *QueryPluginRequest) (*QueryPluginResponse, error) {
	s.logger.Debug("plugin query request received", "plugin", req.Name, "method", req.Method)

	// Convert params from TypedMap to map[string]any
	params := TypedMapToMap(req.Params)
	if params == nil {
		params = make(map[string]any)
	}

	// Execute query
	startTime := time.Now()
	result, err := s.daemon.QueryPlugin(ctx, req.Name, req.Method, params)
	duration := time.Since(startTime)

	if err != nil {
		s.logger.Error("plugin query failed", "plugin", req.Name, "method", req.Method, "error", err)
		return &QueryPluginResponse{
			Error:      err.Error(),
			DurationMs: duration.Milliseconds(),
		}, nil
	}

	// Convert result to TypedValue
	s.logger.Debug("plugin query completed", "plugin", req.Name, "method", req.Method, "duration_ms", duration.Milliseconds())
	return &QueryPluginResponse{
		Result:     anyToTypedValue(result),
		DurationMs: duration.Milliseconds(),
	}, nil
}

// RunAttack executes an attack and streams progress events.
func (s *DaemonServer) RunAttack(req *RunAttackRequest, stream grpc.ServerStreamingServer[AttackEvent]) error {
	s.logger.Info("attack run request received",
		"target", req.Target,
		"attack_type", req.AttackType,
		"agent_id", req.AgentId,
	)

	// Convert proto request to internal request
	attackReq := AttackRequest{
		Target:        req.Target,
		TargetName:    req.TargetName,
		AttackType:    req.AttackType,
		AgentID:       req.AgentId,
		PayloadFilter: req.PayloadFilter,
		Options:       req.Options,
	}

	// Start attack and get event channel
	eventChan, err := s.daemon.RunAttack(stream.Context(), attackReq)
	if err != nil {
		s.logger.Error("failed to start attack", "error", err)
		return status_grpc.Errorf(codes.Internal, "failed to start attack: %v", err)
	}

	// Stream events to client
	for {
		select {
		case <-stream.Context().Done():
			s.logger.Info("attack stream cancelled", "target", req.Target)
			return stream.Context().Err()

		case event, ok := <-eventChan:
			if !ok {
				// Event channel closed, attack completed
				s.logger.Info("attack completed", "target", req.Target)
				return nil
			}

			// Convert event to proto message
			protoEvent := &AttackEvent{
				EventType: event.EventType,
				Timestamp: event.Timestamp.Unix(),
				AttackId:  event.AttackID,
				Message:   event.Message,
				Data:      StringToTypedMap(event.Data),
				Error:     event.Error,
			}

			// Add operation result if present
			if event.Result != nil {
				protoEvent.Result = event.Result
			}

			// Add finding if present
			if event.Finding != nil {
				protoEvent.Finding = &FindingInfo{
					Id:          event.Finding.ID,
					Title:       event.Finding.Title,
					Severity:    event.Finding.Severity,
					Category:    event.Finding.Category,
					Description: event.Finding.Description,
					Technique:   event.Finding.Technique,
					Evidence:    event.Finding.Evidence,
					Timestamp:   event.Finding.Timestamp.Unix(),
				}
			}

			// Send event to client
			if err := stream.Send(protoEvent); err != nil {
				s.logger.Error("failed to send attack event", "error", err)
				return status_grpc.Errorf(codes.Internal, "failed to send event: %v", err)
			}
		}
	}
}

// Subscribe establishes an event stream for TUI real-time updates.
func (s *DaemonServer) Subscribe(req *SubscribeRequest, stream grpc.ServerStreamingServer[Event]) error {
	s.logger.Info("event subscription request received",
		"event_types", req.EventTypes,
		"mission_id", req.MissionId,
	)

	// Subscribe to daemon events
	eventChan, err := s.daemon.Subscribe(stream.Context(), req.EventTypes, req.MissionId)
	if err != nil {
		s.logger.Error("failed to subscribe to events", "error", err)
		return status_grpc.Errorf(codes.Internal, "failed to subscribe: %v", err)
	}

	// Stream events to client
	for {
		select {
		case <-stream.Context().Done():
			s.logger.Info("event subscription cancelled")
			return stream.Context().Err()

		case event, ok := <-eventChan:
			if !ok {
				// Event channel closed
				s.logger.Info("event subscription closed")
				return nil
			}

			// Convert event to proto message
			protoEvent := &Event{
				EventType: event.EventType,
				Timestamp: event.Timestamp.Unix(),
				Source:    event.Source,
				Data:      StringToTypedMap(event.Data),
			}

			// Add specific event type if present
			if event.MissionEvent != nil {
				protoEvent.Event = &Event_MissionEvent{
					MissionEvent: &MissionEvent{
						EventType: event.MissionEvent.EventType,
						Timestamp: event.MissionEvent.Timestamp.Unix(),
						MissionId: event.MissionEvent.MissionID,
						NodeId:    event.MissionEvent.NodeID,
						Message:   event.MissionEvent.Message,
						Data:      StringToTypedMap(event.MissionEvent.Data),
						Error:     event.MissionEvent.Error,
					},
				}
			} else if event.AttackEvent != nil {
				var finding *FindingInfo
				if event.AttackEvent.Finding != nil {
					finding = &FindingInfo{
						Id:          event.AttackEvent.Finding.ID,
						Title:       event.AttackEvent.Finding.Title,
						Severity:    event.AttackEvent.Finding.Severity,
						Category:    event.AttackEvent.Finding.Category,
						Description: event.AttackEvent.Finding.Description,
						Technique:   event.AttackEvent.Finding.Technique,
						Evidence:    event.AttackEvent.Finding.Evidence,
						Timestamp:   event.AttackEvent.Finding.Timestamp.Unix(),
					}
				}
				protoEvent.Event = &Event_AttackEvent{
					AttackEvent: &AttackEvent{
						EventType: event.AttackEvent.EventType,
						Timestamp: event.AttackEvent.Timestamp.Unix(),
						AttackId:  event.AttackEvent.AttackID,
						Message:   event.AttackEvent.Message,
						Data:      StringToTypedMap(event.AttackEvent.Data),
						Error:     event.AttackEvent.Error,
						Finding:   finding,
					},
				}
			} else if event.AgentEvent != nil {
				protoEvent.Event = &Event_AgentEvent{
					AgentEvent: &AgentEvent{
						EventType: event.AgentEvent.EventType,
						Timestamp: event.AgentEvent.Timestamp.Unix(),
						AgentId:   event.AgentEvent.AgentID,
						AgentName: event.AgentEvent.AgentName,
						Message:   event.AgentEvent.Message,
						Data:      StringToTypedMap(event.AgentEvent.Data),
					},
				}
			} else if event.FindingEvent != nil {
				protoEvent.Event = &Event_FindingEvent{
					FindingEvent: &FindingEvent{
						EventType: event.FindingEvent.EventType,
						Timestamp: event.FindingEvent.Timestamp.Unix(),
						Finding: &FindingInfo{
							Id:          event.FindingEvent.Finding.ID,
							Title:       event.FindingEvent.Finding.Title,
							Severity:    event.FindingEvent.Finding.Severity,
							Category:    event.FindingEvent.Finding.Category,
							Description: event.FindingEvent.Finding.Description,
							Technique:   event.FindingEvent.Finding.Technique,
							Evidence:    event.FindingEvent.Finding.Evidence,
							Timestamp:   event.FindingEvent.Finding.Timestamp.Unix(),
						},
						MissionId: event.FindingEvent.MissionID,
					},
				}
			}

			// Send event to client
			if err := stream.Send(protoEvent); err != nil {
				s.logger.Error("failed to send event", "error", err)
				return status_grpc.Errorf(codes.Internal, "failed to send event: %v", err)
			}
		}
	}
}

// StartComponent starts a component (agent, tool, or plugin) by kind and name.
func (s *DaemonServer) StartComponent(ctx context.Context, req *StartComponentRequest) (*StartComponentResponse, error) {
	s.logger.Info("start component request received",
		"kind", req.Kind,
		"name", req.Name,
	)

	// Validate request
	if req.Kind == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "component kind is required")
	}
	if req.Name == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "component name is required")
	}

	// Validate kind is one of the supported types
	if req.Kind != "agent" && req.Kind != "tool" && req.Kind != "plugin" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "invalid component kind: %s (must be agent, tool, or plugin)", req.Kind)
	}

	// Call daemon implementation
	result, err := s.daemon.StartComponent(ctx, req.Kind, req.Name)
	if err != nil {
		s.logger.Error("failed to start component", "error", err, "kind", req.Kind, "name", req.Name)

		// Map errors to appropriate gRPC codes
		if strings.Contains(err.Error(), "not found") {
			return nil, status_grpc.Errorf(codes.NotFound, "component '%s' not found", req.Name)
		}
		if strings.Contains(err.Error(), "already running") {
			return nil, status_grpc.Errorf(codes.AlreadyExists, "component '%s' is already running", req.Name)
		}

		return nil, status_grpc.Errorf(codes.Internal, "failed to start component: %v", err)
	}

	s.logger.Info("component started successfully",
		"kind", req.Kind,
		"name", req.Name,
		"pid", result.PID,
		"port", result.Port,
	)

	return &StartComponentResponse{
		Success: true,
		Pid:     int32(result.PID),
		Port:    int32(result.Port),
		Message: fmt.Sprintf("Component '%s' started successfully", req.Name),
		LogPath: result.LogPath,
	}, nil
}

// StopComponent stops a running component (agent, tool, or plugin) by kind and name.
func (s *DaemonServer) StopComponent(ctx context.Context, req *StopComponentRequest) (*StopComponentResponse, error) {
	s.logger.Info("stop component request received",
		"kind", req.Kind,
		"name", req.Name,
		"force", req.Force,
	)

	// Validate request
	if req.Kind == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "component kind is required")
	}
	if req.Name == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "component name is required")
	}

	// Validate kind is one of the supported types
	if req.Kind != "agent" && req.Kind != "tool" && req.Kind != "plugin" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "invalid component kind: %s (must be agent, tool, or plugin)", req.Kind)
	}

	// Call daemon implementation
	result, err := s.daemon.StopComponent(ctx, req.Kind, req.Name, req.Force)
	if err != nil {
		s.logger.Error("failed to stop component", "error", err, "kind", req.Kind, "name", req.Name)

		// Map errors to appropriate gRPC codes
		if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "not running") {
			return nil, status_grpc.Errorf(codes.NotFound, "component '%s' is not running", req.Name)
		}

		return nil, status_grpc.Errorf(codes.Internal, "failed to stop component: %v", err)
	}

	s.logger.Info("component stopped successfully",
		"kind", req.Kind,
		"name", req.Name,
		"stopped_count", result.StoppedCount,
		"total_count", result.TotalCount,
	)

	return &StopComponentResponse{
		Success:      true,
		StoppedCount: int32(result.StoppedCount),
		TotalCount:   int32(result.TotalCount),
		Message:      fmt.Sprintf("Stopped %d/%d instances of component '%s'", result.StoppedCount, result.TotalCount, req.Name),
	}, nil
}

// PauseMission pauses a running mission at the next clean checkpoint boundary.
func (s *DaemonServer) PauseMission(ctx context.Context, req *PauseMissionRequest) (*PauseMissionResponse, error) {
	s.logger.Info("mission pause request received",
		"mission_id", req.MissionId,
		"force", req.Force,
	)

	// Validate mission ID
	if req.MissionId == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "mission ID is required")
	}

	// Call daemon implementation
	err := s.daemon.PauseMission(ctx, req.MissionId, req.Force)
	if err != nil {
		s.logger.Error("failed to pause mission", "error", err, "mission_id", req.MissionId)

		// Map errors to appropriate gRPC codes
		if strings.Contains(err.Error(), "not found") {
			return nil, status_grpc.Errorf(codes.NotFound, "mission not found: %s", req.MissionId)
		}
		if strings.Contains(err.Error(), "not running") {
			return nil, status_grpc.Errorf(codes.FailedPrecondition, "mission is not running: %s", req.MissionId)
		}

		return nil, status_grpc.Errorf(codes.Internal, "failed to pause mission: %v", err)
	}

	s.logger.Info("mission paused successfully", "mission_id", req.MissionId)

	return &PauseMissionResponse{
		Success:      true,
		CheckpointId: "", // Will be populated when checkpoint system is fully integrated
		Message:      fmt.Sprintf("Mission %s paused successfully", req.MissionId),
	}, nil
}

// ResumeMission resumes a paused mission from its last checkpoint and streams execution events.
func (s *DaemonServer) ResumeMission(req *ResumeMissionRequest, stream grpc.ServerStreamingServer[MissionEvent]) error {
	s.logger.Info("mission resume request received",
		"mission_id", req.MissionId,
		"checkpoint_id", req.CheckpointId,
	)

	// Validate mission ID
	if req.MissionId == "" {
		return status_grpc.Errorf(codes.InvalidArgument, "mission ID is required")
	}

	// Call daemon implementation to resume the mission
	eventChan, err := s.daemon.ResumeMission(stream.Context(), req.MissionId)
	if err != nil {
		s.logger.Error("failed to resume mission", "error", err, "mission_id", req.MissionId)

		// Map errors to appropriate gRPC codes
		if strings.Contains(err.Error(), "not found") {
			return status_grpc.Errorf(codes.NotFound, "mission not found: %s", req.MissionId)
		}
		if strings.Contains(err.Error(), "not paused") {
			return status_grpc.Errorf(codes.FailedPrecondition, "mission is not paused: %s", req.MissionId)
		}
		if strings.Contains(err.Error(), "no checkpoint") {
			return status_grpc.Errorf(codes.FailedPrecondition, "no checkpoint available for mission: %s", req.MissionId)
		}

		return status_grpc.Errorf(codes.Internal, "failed to resume mission: %v", err)
	}

	// Stream events to client (similar to RunMission)
	for {
		select {
		case <-stream.Context().Done():
			s.logger.Info("mission resume stream cancelled", "mission_id", req.MissionId)
			return stream.Context().Err()

		case event, ok := <-eventChan:
			if !ok {
				// Event channel closed, mission completed
				s.logger.Info("mission resumed and completed", "mission_id", req.MissionId)
				return nil
			}

			// Convert event to proto message
			protoEvent := &MissionEvent{
				EventType: event.EventType,
				Timestamp: event.Timestamp.Unix(),
				MissionId: event.MissionID,
				NodeId:    event.NodeID,
				Message:   event.Message,
				Data:      StringToTypedMap(event.Data),
				Error:     event.Error,
			}

			// Add operation result if present
			if event.Result != nil {
				protoEvent.Result = event.Result
			}

			// Send event to client
			if err := stream.Send(protoEvent); err != nil {
				s.logger.Error("failed to send mission event", "error", err)
				return status_grpc.Errorf(codes.Internal, "failed to send event: %v", err)
			}
		}
	}
}

// GetMissionHistory returns all runs for a mission name.
func (s *DaemonServer) GetMissionHistory(ctx context.Context, req *GetMissionHistoryRequest) (*GetMissionHistoryResponse, error) {
	s.logger.Debug("mission history request received",
		"name", req.Name,
		"limit", req.Limit,
		"offset", req.Offset,
	)

	// Validate request
	if req.Name == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "mission name is required")
	}

	// Set defaults for pagination
	limit := int(req.Limit)
	if limit <= 0 {
		limit = 100
	}
	offset := int(req.Offset)
	if offset < 0 {
		offset = 0
	}

	// Call daemon implementation
	runs, total, err := s.daemon.GetMissionHistory(ctx, req.Name, limit, offset)
	if err != nil {
		s.logger.Error("failed to get mission history", "error", err, "name", req.Name)
		return nil, status_grpc.Errorf(codes.Internal, "failed to get mission history: %v", err)
	}

	// Convert internal types to proto types
	protoRuns := make([]*MissionRun, len(runs))
	for i, run := range runs {
		protoRuns[i] = &MissionRun{
			MissionId:     run.MissionID,
			RunNumber:     int32(run.RunNumber),
			Status:        run.Status,
			CreatedAt:     run.CreatedAt,
			CompletedAt:   run.CompletedAt,
			FindingsCount: int32(run.FindingsCount),
			PreviousRunId: run.PreviousRunID,
		}
	}

	s.logger.Debug("mission history retrieved", "name", req.Name, "count", len(runs), "total", total)

	return &GetMissionHistoryResponse{
		Runs:  protoRuns,
		Total: int32(total),
	}, nil
}

// GetMissionCheckpoints returns all checkpoints for a specific mission.
func (s *DaemonServer) GetMissionCheckpoints(ctx context.Context, req *GetMissionCheckpointsRequest) (*GetMissionCheckpointsResponse, error) {
	s.logger.Debug("mission checkpoints request received",
		"mission_id", req.MissionId,
	)

	// Validate request
	if req.MissionId == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "mission ID is required")
	}

	// Call daemon implementation
	checkpoints, err := s.daemon.GetMissionCheckpoints(ctx, req.MissionId)
	if err != nil {
		s.logger.Error("failed to get mission checkpoints", "error", err, "mission_id", req.MissionId)

		// Map errors to appropriate gRPC codes
		if strings.Contains(err.Error(), "not found") {
			return nil, status_grpc.Errorf(codes.NotFound, "mission not found: %s", req.MissionId)
		}

		return nil, status_grpc.Errorf(codes.Internal, "failed to get mission checkpoints: %v", err)
	}

	// Convert internal types to proto types
	protoCheckpoints := make([]*CheckpointInfo, len(checkpoints))
	for i, cp := range checkpoints {
		protoCheckpoints[i] = &CheckpointInfo{
			CheckpointId:   cp.CheckpointID,
			CreatedAt:      cp.CreatedAt,
			CompletedNodes: int32(cp.CompletedNodes),
			TotalNodes:     int32(cp.TotalNodes),
			FindingsCount:  int32(cp.FindingsCount),
			Version:        int32(cp.Version),
		}
	}

	s.logger.Debug("mission checkpoints retrieved", "mission_id", req.MissionId, "count", len(checkpoints))

	return &GetMissionCheckpointsResponse{
		Checkpoints: protoCheckpoints,
	}, nil
}

// InstallAllComponent installs all components from a mono-repo.
func (s *DaemonServer) InstallAllComponent(ctx context.Context, req *InstallAllComponentRequest) (*InstallAllComponentResponse, error) {
	s.logger.Info("install all components request received",
		"kind", req.Kind,
		"url", req.Url,
		"branch", req.Branch,
		"tag", req.Tag,
		"force", req.Force,
	)

	// Validate request
	if req.Kind == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "component kind is required")
	}
	if req.Url == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "component URL is required")
	}

	// Validate kind is one of the supported types
	if req.Kind != "agent" && req.Kind != "tool" && req.Kind != "plugin" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "invalid component kind: %s (must be agent, tool, or plugin)", req.Kind)
	}

	// Call daemon implementation
	result, err := s.daemon.InstallAllComponent(ctx, req.Kind, req.Url, req.Branch, req.Tag, req.Force, req.SkipBuild, req.Verbose)
	if err != nil {
		s.logger.Error("failed to install all components", "error", err, "kind", req.Kind, "url", req.Url)

		// Map errors to appropriate gRPC codes
		if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "clone failed") {
			return nil, status_grpc.Errorf(codes.NotFound, "%v", err)
		}
		if strings.Contains(err.Error(), "no components found") {
			return nil, status_grpc.Errorf(codes.NotFound, "%v", err)
		}

		return nil, status_grpc.Errorf(codes.Internal, "failed to install components: %v", err)
	}

	s.logger.Info("components installed",
		"kind", req.Kind,
		"found", result.ComponentsFound,
		"successful", result.SuccessfulCount,
		"skipped", result.SkippedCount,
		"failed", result.FailedCount,
	)

	// Convert result to proto response
	protoSuccessful := make([]*InstallAllResultItem, len(result.Successful))
	for i, item := range result.Successful {
		protoSuccessful[i] = &InstallAllResultItem{
			Name:    item.Name,
			Version: item.Version,
			Path:    item.Path,
		}
	}

	protoSkipped := make([]*InstallAllResultItem, len(result.Skipped))
	for i, item := range result.Skipped {
		protoSkipped[i] = &InstallAllResultItem{
			Name:    item.Name,
			Version: item.Version,
			Path:    item.Path,
		}
	}

	protoFailed := make([]*InstallAllFailedItem, len(result.Failed))
	for i, item := range result.Failed {
		protoFailed[i] = &InstallAllFailedItem{
			Name:  item.Name,
			Path:  item.Path,
			Error: item.Error,
		}
	}

	return &InstallAllComponentResponse{
		Success:         result.Success,
		ComponentsFound: int32(result.ComponentsFound),
		SuccessfulCount: int32(result.SuccessfulCount),
		SkippedCount:    int32(result.SkippedCount),
		FailedCount:     int32(result.FailedCount),
		Successful:      protoSuccessful,
		Skipped:         protoSkipped,
		Failed:          protoFailed,
		DurationMs:      result.DurationMs,
		Message:         result.Message,
	}, nil
}

// UninstallComponent removes a component (agent, tool, or plugin) by kind and name.
func (s *DaemonServer) UninstallComponent(ctx context.Context, req *UninstallComponentRequest) (*UninstallComponentResponse, error) {
	s.logger.Info("uninstall component request received",
		"kind", req.Kind,
		"name", req.Name,
		"force", req.Force,
	)

	// Validate request
	if req.Kind == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "component kind is required")
	}
	if req.Name == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "component name is required")
	}

	// Validate kind is one of the supported types
	if req.Kind != "agent" && req.Kind != "tool" && req.Kind != "plugin" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "invalid component kind: %s (must be agent, tool, or plugin)", req.Kind)
	}

	// Call daemon implementation
	err := s.daemon.UninstallComponent(ctx, req.Kind, req.Name, req.Force)
	if err != nil {
		s.logger.Error("failed to uninstall component", "error", err, "kind", req.Kind, "name", req.Name)

		// Map errors to appropriate gRPC codes
		if strings.Contains(err.Error(), "not found") {
			return nil, status_grpc.Errorf(codes.NotFound, "component '%s' not found", req.Name)
		}
		if strings.Contains(err.Error(), "running") && !req.Force {
			return nil, status_grpc.Errorf(codes.FailedPrecondition, "component '%s' is running. Stop it first or use --force", req.Name)
		}

		return nil, status_grpc.Errorf(codes.Internal, "failed to uninstall component: %v", err)
	}

	s.logger.Info("component uninstalled successfully",
		"kind", req.Kind,
		"name", req.Name,
	)

	return &UninstallComponentResponse{
		Success: true,
		Message: fmt.Sprintf("Component '%s' uninstalled successfully", req.Name),
	}, nil
}

// UpdateComponent updates a component (agent, tool, or plugin) to the latest version.
func (s *DaemonServer) UpdateComponent(ctx context.Context, req *UpdateComponentRequest) (*UpdateComponentResponse, error) {
	s.logger.Info("update component request received",
		"kind", req.Kind,
		"name", req.Name,
		"restart", req.Restart,
	)

	// Validate request
	if req.Kind == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "component kind is required")
	}
	if req.Name == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "component name is required")
	}

	// Validate kind is one of the supported types
	if req.Kind != "agent" && req.Kind != "tool" && req.Kind != "plugin" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "invalid component kind: %s (must be agent, tool, or plugin)", req.Kind)
	}

	// Call daemon implementation
	result, err := s.daemon.UpdateComponent(ctx, req.Kind, req.Name, req.Restart, req.SkipBuild, req.Verbose)
	if err != nil {
		s.logger.Error("failed to update component", "error", err, "kind", req.Kind, "name", req.Name)

		// Map errors to appropriate gRPC codes
		if strings.Contains(err.Error(), "not found") {
			return nil, status_grpc.Errorf(codes.NotFound, "component '%s' not found", req.Name)
		}

		return nil, status_grpc.Errorf(codes.Internal, "failed to update component: %v", err)
	}

	s.logger.Info("component updated successfully",
		"kind", req.Kind,
		"name", req.Name,
		"updated", result.Updated,
		"old_version", result.OldVersion,
		"new_version", result.NewVersion,
	)

	msg := fmt.Sprintf("Component '%s' updated successfully", req.Name)
	if !result.Updated {
		msg = fmt.Sprintf("Component '%s' is already at the latest version", req.Name)
	}

	return &UpdateComponentResponse{
		Success:     true,
		Updated:     result.Updated,
		OldVersion:  result.OldVersion,
		NewVersion:  result.NewVersion,
		BuildOutput: result.BuildOutput,
		DurationMs:  result.DurationMs,
		Message:     msg,
	}, nil
}

// BuildComponent rebuilds a component (agent, tool, or plugin) from source.
func (s *DaemonServer) BuildComponent(ctx context.Context, req *BuildComponentRequest) (*BuildComponentResponse, error) {
	s.logger.Info("build component request received",
		"kind", req.Kind,
		"name", req.Name,
	)

	// Validate request
	if req.Kind == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "component kind is required")
	}
	if req.Name == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "component name is required")
	}

	// Validate kind is one of the supported types
	if req.Kind != "agent" && req.Kind != "tool" && req.Kind != "plugin" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "invalid component kind: %s (must be agent, tool, or plugin)", req.Kind)
	}

	// Call daemon implementation
	result, err := s.daemon.BuildComponent(ctx, req.Kind, req.Name)
	if err != nil {
		s.logger.Error("failed to build component", "error", err, "kind", req.Kind, "name", req.Name)

		// Map errors to appropriate gRPC codes
		if strings.Contains(err.Error(), "not found") {
			return nil, status_grpc.Errorf(codes.NotFound, "component '%s' not found", req.Name)
		}

		return nil, status_grpc.Errorf(codes.Internal, "failed to build component: %v", err)
	}

	s.logger.Info("component build completed",
		"kind", req.Kind,
		"name", req.Name,
		"success", result.Success,
	)

	msg := fmt.Sprintf("Component '%s' built successfully", req.Name)
	if !result.Success {
		msg = fmt.Sprintf("Component '%s' build failed", req.Name)
	}

	return &BuildComponentResponse{
		Success:    result.Success,
		Stdout:     result.Stdout,
		Stderr:     result.Stderr,
		DurationMs: result.DurationMs,
		Message:    msg,
	}, nil
}

// ShowComponent returns detailed information about a component (agent, tool, or plugin).
func (s *DaemonServer) ShowComponent(ctx context.Context, req *ShowComponentRequest) (*ShowComponentResponse, error) {
	s.logger.Debug("show component request received",
		"kind", req.Kind,
		"name", req.Name,
	)

	// Validate request
	if req.Kind == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "component kind is required")
	}
	if req.Name == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "component name is required")
	}

	// Validate kind is one of the supported types
	if req.Kind != "agent" && req.Kind != "tool" && req.Kind != "plugin" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "invalid component kind: %s (must be agent, tool, or plugin)", req.Kind)
	}

	// Call daemon implementation
	info, err := s.daemon.ShowComponent(ctx, req.Kind, req.Name)
	if err != nil {
		s.logger.Error("failed to show component", "error", err, "kind", req.Kind, "name", req.Name)

		// Map errors to appropriate gRPC codes
		if strings.Contains(err.Error(), "not found") {
			return nil, status_grpc.Errorf(codes.NotFound, "component '%s' not found", req.Name)
		}

		return nil, status_grpc.Errorf(codes.Internal, "failed to show component: %v", err)
	}

	s.logger.Debug("component info retrieved",
		"kind", req.Kind,
		"name", req.Name,
	)

	return &ShowComponentResponse{
		Success:   true,
		Name:      info.Name,
		Version:   info.Version,
		Kind:      info.Kind,
		Status:    info.Status,
		Source:    info.Source,
		RepoPath:  info.RepoPath,
		BinPath:   info.BinPath,
		Port:      int32(info.Port),
		Pid:       int32(info.PID),
		CreatedAt: info.CreatedAt.Unix(),
		UpdatedAt: info.UpdatedAt.Unix(),
	}, nil
}

// GetComponentLogs streams log entries for a component (agent, tool, or plugin).
func (s *DaemonServer) GetComponentLogs(req *GetComponentLogsRequest, stream grpc.ServerStreamingServer[LogEntry]) error {
	s.logger.Info("get component logs request received",
		"kind", req.Kind,
		"name", req.Name,
		"follow", req.Follow,
		"lines", req.Lines,
	)

	// Validate request
	if req.Kind == "" {
		return status_grpc.Errorf(codes.InvalidArgument, "component kind is required")
	}
	if req.Name == "" {
		return status_grpc.Errorf(codes.InvalidArgument, "component name is required")
	}

	// Validate kind is one of the supported types
	if req.Kind != "agent" && req.Kind != "tool" && req.Kind != "plugin" {
		return status_grpc.Errorf(codes.InvalidArgument, "invalid component kind: %s (must be agent, tool, or plugin)", req.Kind)
	}

	// Call daemon implementation
	logChan, err := s.daemon.GetComponentLogs(stream.Context(), req.Kind, req.Name, req.Follow, int(req.Lines))
	if err != nil {
		s.logger.Error("failed to get component logs", "error", err, "kind", req.Kind, "name", req.Name)

		// Map errors to appropriate gRPC codes
		if strings.Contains(err.Error(), "not found") {
			return status_grpc.Errorf(codes.NotFound, "component '%s' not found", req.Name)
		}

		return status_grpc.Errorf(codes.Internal, "failed to get component logs: %v", err)
	}

	// Stream log entries to client
	for {
		select {
		case <-stream.Context().Done():
			s.logger.Info("log stream cancelled", "kind", req.Kind, "name", req.Name)
			return stream.Context().Err()

		case entry, ok := <-logChan:
			if !ok {
				// Log channel closed
				s.logger.Info("log stream completed", "kind", req.Kind, "name", req.Name)
				return nil
			}

			// Convert to proto message
			protoEntry := &LogEntry{
				Timestamp: entry.Timestamp,
				Level:     entry.Level,
				Message:   entry.Message,
			}

			// Send to client
			if err := stream.Send(protoEntry); err != nil {
				s.logger.Error("failed to send log entry", "error", err)
				return status_grpc.Errorf(codes.Internal, "failed to send log entry: %v", err)
			}
		}
	}
}

// InstallMission installs a mission from a Git repository.
func (s *DaemonServer) InstallMission(ctx context.Context, req *InstallMissionRequest) (*InstallMissionResponse, error) {
	s.logger.Info("install mission request received",
		"url", req.Url,
		"branch", req.Branch,
		"tag", req.Tag,
		"force", req.Force,
	)

	// Validate request
	if req.Url == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "mission URL is required")
	}

	// Call daemon implementation
	result, err := s.daemon.InstallMission(ctx, req.Url, req.Branch, req.Tag, req.Force, req.Yes, req.TimeoutMs)
	if err != nil {
		s.logger.Error("failed to install mission", "error", err, "url", req.Url)

		// Map errors to appropriate gRPC codes
		if strings.Contains(err.Error(), "already exists") {
			return nil, status_grpc.Errorf(codes.AlreadyExists, "%v", err)
		}
		if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "clone failed") {
			return nil, status_grpc.Errorf(codes.NotFound, "%v", err)
		}
		if strings.Contains(err.Error(), "invalid") || strings.Contains(err.Error(), "validation") {
			return nil, status_grpc.Errorf(codes.InvalidArgument, "%v", err)
		}

		return nil, status_grpc.Errorf(codes.Internal, "failed to install mission: %v", err)
	}

	s.logger.Info("mission installed successfully",
		"name", result.Name,
		"version", result.Version,
	)

	// Convert dependencies to proto format
	protoDeps := make([]*InstalledDependency, len(result.Dependencies))
	for i, dep := range result.Dependencies {
		protoDeps[i] = &InstalledDependency{
			Type:             dep.Type,
			Name:             dep.Name,
			AlreadyInstalled: dep.AlreadyInstalled,
		}
	}

	return &InstallMissionResponse{
		Success:      true,
		Name:         result.Name,
		Version:      result.Version,
		Path:         result.Path,
		Dependencies: protoDeps,
		DurationMs:   result.DurationMs,
		Message:      fmt.Sprintf("Mission '%s' installed successfully", result.Name),
	}, nil
}

// UninstallMission removes an installed mission.
func (s *DaemonServer) UninstallMission(ctx context.Context, req *UninstallMissionRequest) (*UninstallMissionResponse, error) {
	s.logger.Info("uninstall mission request received",
		"name", req.Name,
		"force", req.Force,
	)

	// Validate request
	if req.Name == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "mission name is required")
	}

	// Call daemon implementation
	err := s.daemon.UninstallMission(ctx, req.Name, req.Force)
	if err != nil {
		s.logger.Error("failed to uninstall mission", "error", err, "name", req.Name)

		// Map errors to appropriate gRPC codes
		if strings.Contains(err.Error(), "not found") {
			return nil, status_grpc.Errorf(codes.NotFound, "%v", err)
		}

		return nil, status_grpc.Errorf(codes.Internal, "failed to uninstall mission: %v", err)
	}

	s.logger.Info("mission uninstalled successfully", "name", req.Name)

	return &UninstallMissionResponse{
		Success: true,
		Message: fmt.Sprintf("Mission '%s' uninstalled successfully", req.Name),
	}, nil
}

// ListMissionDefinitions returns all installed mission definitions.
func (s *DaemonServer) ListMissionDefinitions(ctx context.Context, req *ListMissionDefinitionsRequest) (*ListMissionDefinitionsResponse, error) {
	s.logger.Debug("list mission definitions request received",
		"limit", req.Limit,
		"offset", req.Offset,
	)

	// Convert limit/offset to int (proto uses int32)
	limit := int(req.Limit)
	offset := int(req.Offset)

	// Call daemon implementation
	definitions, total, err := s.daemon.ListMissionDefinitions(ctx, limit, offset)
	if err != nil {
		s.logger.Error("failed to list mission definitions", "error", err)
		return nil, status_grpc.Errorf(codes.Internal, "failed to list mission definitions: %v", err)
	}

	// Convert to proto format
	protoDefinitions := make([]*MissionDefinitionInfo, len(definitions))
	for i, def := range definitions {
		protoDefinitions[i] = &MissionDefinitionInfo{
			Name:        def.Name,
			Version:     def.Version,
			Description: def.Description,
			Source:      def.Source,
			InstalledAt: def.InstalledAt.Unix(),
			UpdatedAt:   def.UpdatedAt.Unix(),
			NodeCount:   int32(def.NodeCount),
		}
	}

	s.logger.Debug("listed mission definitions", "count", len(definitions), "total", total)

	return &ListMissionDefinitionsResponse{
		Missions: protoDefinitions,
		Total:    int32(total),
	}, nil
}

// UpdateMission updates an installed mission to the latest version.
func (s *DaemonServer) UpdateMission(ctx context.Context, req *UpdateMissionRequest) (*UpdateMissionResponse, error) {
	s.logger.Info("update mission request received", "name", req.Name)

	// Validate request
	if req.Name == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "mission name is required")
	}

	// Call daemon implementation
	result, err := s.daemon.UpdateMission(ctx, req.Name, req.TimeoutMs)
	if err != nil {
		s.logger.Error("failed to update mission", "error", err, "name", req.Name)

		// Map errors to appropriate gRPC codes
		if strings.Contains(err.Error(), "not found") {
			return nil, status_grpc.Errorf(codes.NotFound, "%v", err)
		}

		return nil, status_grpc.Errorf(codes.Internal, "failed to update mission: %v", err)
	}

	s.logger.Info("mission update completed",
		"name", req.Name,
		"updated", result.Updated,
		"old_version", result.OldVersion,
		"new_version", result.NewVersion,
	)

	message := fmt.Sprintf("Mission '%s' is already up to date (version %s)", req.Name, result.NewVersion)
	if result.Updated {
		message = fmt.Sprintf("Mission '%s' updated from %s to %s", req.Name, result.OldVersion, result.NewVersion)
	}

	return &UpdateMissionResponse{
		Success:    true,
		Updated:    result.Updated,
		OldVersion: result.OldVersion,
		NewVersion: result.NewVersion,
		DurationMs: result.DurationMs,
		Message:    message,
	}, nil
}
