package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpcmeta "google.golang.org/grpc/metadata"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zero-day-ai/gibson/internal/audit"
	"github.com/zero-day-ai/gibson/internal/auth"
	"github.com/zero-day-ai/gibson/internal/authz"
	"github.com/zero-day-ai/gibson/internal/component"
	"github.com/zero-day-ai/gibson/internal/finding"
	"github.com/zero-day-ai/gibson/internal/impersonation"
	"github.com/zero-day-ai/gibson/internal/keycloak"
	"github.com/zero-day-ai/gibson/internal/membership"
	"github.com/zero-day-ai/gibson/internal/mission"
	"github.com/zero-day-ai/gibson/internal/missiondraft"
	"github.com/zero-day-ai/gibson/internal/onboarding"
	"github.com/zero-day-ai/gibson/internal/provisioner"
	"github.com/zero-day-ai/gibson/internal/types"
	"github.com/zero-day-ai/gibson/internal/version"
	daemonpb "github.com/zero-day-ai/sdk/api/gen/gibson/daemon/v1"
)

// authzIface is the narrow subset of authz.Authorizer that the DaemonServer
// admin handlers use directly. Using an interface rather than the concrete type
// avoids importing the authz package in tests that don't care about it.
type authzIface interface {
	Check(ctx context.Context, user, relation, object string) (bool, error)
	Write(ctx context.Context, tuples []authz.Tuple) error
	Delete(ctx context.Context, tuples []authz.Tuple) error
	ListObjects(ctx context.Context, user, relation, objectType string) ([]string, error)
	ListUsers(ctx context.Context, objectType, object, relation string) ([]string, error)
}

// DaemonServer implements the DaemonServiceServer interface.
//
// This server exposes all daemon functionality via gRPC including mission
// execution, agent management, attack operations, and real-time event streaming.
// It acts as a facade that delegates to the daemon's internal services.
type DaemonServer struct {
	daemonpb.UnimplementedDaemonServiceServer
	UnimplementedDaemonAdminServiceServer

	// daemon is the daemon instance this server exposes
	daemon DaemonInterface

	// credentialHandler provides secure credential storage for per-tenant credentials
	credentialHandler *CredentialHandler

	// logger is the structured logger
	logger *slog.Logger

	// sessionCounter generates unique session IDs
	sessionCounter int64

	// quotaManager enforces per-tenant resource quotas on mission submission.
	// May be nil; when nil, quota checks are skipped.
	quotaManager MissionQuotaChecker

	// tenantService manages tenant CRUD operations backed by Redis.
	// May be nil; when nil, tenant management RPCs return codes.Unavailable.
	tenantService *component.TenantService

	// keycloak is the Keycloak Admin REST API client used for member queries.
	// May be nil; when nil, ListTenantMembers returns codes.Unavailable.
	keycloak *keycloak.Client

	// provisioner handles full tenant provisioning (namespace, RBAC, API key).
	// May be nil; wired via WithProvisioner() during daemon startup.
	provisioner interface {
		ProvisionTenant(ctx context.Context, tenantID, displayName, tier, ownerEmail, stripeCustomerID, stripeSubID string) (tenantJSON string, apiKey string, err error)
		GetProvisioningStatus(ctx context.Context, tenantID string) (status string, steps []ProvisioningStep, err error)
		DeprovisionTenant(ctx context.Context, tenantID string) error
	}

	// invitationStore manages team invitations.
	// May be nil; wired when the invitation service is available.
	// TODO: replace with concrete type once invitation package is introduced.
	invitationStore interface {
		Create(ctx context.Context, tenantID, email string, roles []string, message string, expiresInHours int32) (token, link string, err error)
		Accept(ctx context.Context, token, displayName string) (tenantID string, roles []string, err error)
		List(ctx context.Context, tenantID string, page, limit int32) (invitations []InvitationRecord, total int32, err error)
		Revoke(ctx context.Context, tenantID, token string) error
	}

	// apiKeyStore manages tenant API keys.
	// May be nil; wired when the API key service is available.
	// TODO: replace with concrete type once apikey package is introduced.
	apiKeyStore interface {
		Create(ctx context.Context, tenantID string, allowedKinds, allowedNames, capabilities []string, name, createdBy string) (keyID, rawKey string, err error)
		List(ctx context.Context, tenantID string) ([]APIKeyRecord, error)
		Revoke(ctx context.Context, keyID string) error
	}

	// onboardingStore manages tenant onboarding state.
	// May be nil; wired when the onboarding service is available.
	// TODO: replace with concrete type once onboarding package is introduced.
	onboardingStore interface {
		GetState(ctx context.Context, tenantID string) (currentStep string, completedSteps []string, setupTasks map[string]string, completedAt string, err error)
		UpdateState(ctx context.Context, tenantID, currentStep string, completedSteps []string, setupTasks map[string]string) error
	}

	// billingStore manages tenant billing records.
	// May be nil; wired when the billing service is available.
	// TODO: replace with concrete type once billing package is introduced.
	billingStore interface {
		GetBilling(ctx context.Context, tenantID string) (tier, stripeCustomerID string, billingAlert bool, usage BillingUsageRecord, err error)
		UpdateBilling(ctx context.Context, tenantID, tier, stripeCustomerID, stripeSubID string, billingAlert bool) (*component.TenantRecord, error)
	}

	// impersonationIssuer issues short-lived impersonation tokens.
	// May be nil; wired when the impersonation service is available.
	// TODO: replace with concrete type once impersonation package is introduced.
	impersonationIssuer interface {
		IssueToken(ctx context.Context, tenantID string) (token string, err error)
	}

	// membershipStore manages user-to-tenant membership records.
	// May be nil; when nil, membership RPCs return codes.Unavailable.
	membershipStore membership.MembershipStore

	// signupHandler orchestrates the atomic multi-step tenant signup flow.
	// May be nil; when nil, SignupTenant returns codes.Unavailable.
	// Wired via WithSignupHandler during daemon startup.
	// Added by authz-02-keycloak-organizations spec.
	signupHandler *provisioner.SignupHandler

	// inviteHandler manages member invitation creation, acceptance, and resend.
	// May be nil; when nil, InviteMember/ResendInvitation return codes.Unavailable.
	// Added by authz-04-dashboard-fga-migration spec.
	inviteHandler *provisioner.InviteHandler

	// grantHandler manages per-user component access grants via FGA.
	// May be nil; when nil, GrantComponentAccess/RevokeComponentAccess return codes.Unavailable.
	// Added by authz-04-dashboard-fga-migration spec.
	grantHandler *provisioner.GrantHandler

	// teamHandler manages team CRUD and crosstalk via FGA + Redis.
	// May be nil; when nil, team RPCs return codes.Unavailable.
	// Added by authz-04-dashboard-fga-migration spec.
	teamHandler *provisioner.TeamHandler

	// authorizer is the FGA Authorizer used by admin handlers that need direct FGA access.
	// May be nil; when nil, RPCs that require it return codes.Unavailable.
	// Added by authz-04-dashboard-fga-migration spec.
	authorizer authzIface

	// keycloakAdmin is the provisioner-level KeycloakAdmin client.
	// May be nil; when nil, RPCs that require it return codes.Unavailable.
	// Added by authz-04-dashboard-fga-migration spec.
	keycloakAdmin provisioner.KeycloakAdmin

	// auditLogger is the Redis-backed audit log reader/writer.
	// May be nil; when nil, ListAuditEvents falls back to Loki only (or returns Unavailable).
	// Added by authz-06-granular-permissions-teams spec.
	auditLogger *audit.AuditLogger

	// lokiQuerier is the Loki HTTP query client for audit events.
	// May be nil; when nil, ListAuditEvents falls back to the Redis audit stream.
	// Added by authz-06-granular-permissions-teams spec.
	lokiQuerier audit.LokiQuerier

	// missionDraftStore persists mission YAML drafts per tenant.
	// May be nil; when nil, SaveMissionDraft/ListMissionDrafts return codes.Unavailable.
	// Added by prod-unimplemented-apis spec.
	missionDraftStore missionDraftStoreIface

	// findingStore provides access to findings for export operations.
	// May be nil; when nil, ExportFindings returns codes.Unavailable.
	// Added by prod-unimplemented-apis spec.
	findingStore findingStoreIface

	// quotaStore persists and retrieves per-tenant quota configuration.
	// May be nil; when nil, GetTenantQuota/SetTenantQuota return codes.Unavailable.
	// Added by prod-feature-wiring spec.
	quotaStore quotaStoreIface

	// alertStore persists and retrieves per-user platform alerts.
	// May be nil; when nil, ListAlerts/MarkAlertRead return codes.Unavailable.
	// Added by prod-feature-wiring spec.
	alertStore alertStoreIface

	// conversationStore persists and retrieves chat conversation history.
	// May be nil; when nil, ListConversations/GetConversation return codes.Unavailable.
	// Added by prod-feature-wiring spec.
	conversationStore conversationStoreIface
}

// missionDraftStoreIface is the narrow interface the DaemonServer uses for
// mission draft persistence (Save and List). Using an interface allows tests
// to inject a mock without spinning up Redis.
type missionDraftStoreIface interface {
	Save(ctx context.Context, tenantID, name, yaml, draftID string) (string, error)
	List(ctx context.Context, tenantID string) ([]*missiondraft.MissionDraft, error)
}

// findingStoreIface is the narrow subset of finding.FindingStore used by ExportFindings.
// Using an interface avoids importing the finding package in tests that do not exercise it.
type findingStoreIface interface {
	// List retrieves findings scoped by mission and optional filter.
	// Pass a zero-value types.ID to list all findings for the filter.
	List(ctx context.Context, missionID types.ID, filter *finding.FindingFilter) ([]finding.EnhancedFinding, error)
}

// MissionQuotaChecker is the narrow interface the DaemonServer uses to enforce
// per-tenant quotas. It is satisfied by *component.QuotaManager.
type MissionQuotaChecker interface {
	// CheckMissionQuota returns a codes.ResourceExhausted error when the tenant
	// in ctx has met or exceeded its configured mission limit.
	CheckMissionQuota(ctx context.Context) error

	// CheckAgentQuota returns a codes.ResourceExhausted error when the tenant
	// in ctx has met or exceeded its configured agent limit.
	CheckAgentQuota(ctx context.Context) error

	// CheckMemoryQuota returns a codes.ResourceExhausted error when allocating
	// additionalMB would exceed the tenant's configured memory limit.
	CheckMemoryQuota(ctx context.Context, additionalMB int64) error

	// IncrementMissionCount increments the running mission counter for the
	// tenant in ctx. Called after successful mission submission.
	IncrementMissionCount(ctx context.Context) error
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

	// CreateMission creates a new mission with target and workflow configuration
	CreateMission(ctx context.Context, req CreateMissionData) (CreateMissionResultData, error)

	// RequestShutdown requests graceful shutdown of the daemon
	RequestShutdown(ctx context.Context, force bool, timeoutSeconds int32) error
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
	Capabilities *daemonpb.Capabilities
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
	TenantID     string
	Name         string
	Description  string
	WorkflowPath string
	WorkflowYAML string
	Status       string
	StartTime    time.Time
	EndTime      time.Time
	FindingCount int32
	Progress     float64
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
	Result    *daemonpb.OperationResult
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
	Result    *daemonpb.OperationResult
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
	EventType         string
	Timestamp         time.Time
	Source            string
	Data              string
	Metadata          map[string]interface{} // Additional metadata (e.g., trace_id, span_id, parent_span_id)
	MissionEvent      *MissionEventData
	AttackEvent       *AttackEventData
	AgentEvent        *AgentEventData
	FindingEvent      *FindingEventData
	ToolEvent         *ToolEventData
	LLMEvent          *LLMEventData
	OrchestratorEvent *OrchestratorEventData
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

// ToolEventData represents tool event data.
type ToolEventData struct {
	EventType       string
	Timestamp       time.Time
	ToolName        string
	AgentID         string
	AgentName       string
	MissionID       string
	Message         string
	Duration        float64 // seconds
	Progress        float64 // 0-1
	Error           string
	ErrorCode       string
	Warning         string
	WarningSeverity string
	InputSummary    string // max 200 chars
	OutputSummary   string // max 200 chars
	ResultsCount    int
}

// LLMEventData represents LLM event data.
type LLMEventData struct {
	EventType        string
	Timestamp        time.Time
	AgentID          string
	AgentName        string
	Model            string
	Slot             string
	MessageCount     int
	PromptTokens     int
	CompletionTokens int
	TotalTokens      int
	Duration         float64 // milliseconds
	Cached           bool
	Error            string
	ErrorCode        string
	WillRetry        bool
}

// OrchestratorEventData represents orchestrator event data.
type OrchestratorEventData struct {
	EventType       string
	Timestamp       time.Time
	MissionID       string
	Iteration       int
	Action          string
	TargetNodeID    string
	TargetAgentName string
	Confidence      float64
	Reasoning       string
	TokensUsed      int
	Latency         float64 // milliseconds
	ApprovalID      string
	Risk            string
	Timeout         int // seconds
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
	Successful      []daemonpb.InstallAllResultItem
	Skipped         []daemonpb.InstallAllResultItem
	Failed          []daemonpb.InstallAllFailedItem
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
	RunID         string
	MissionID     string
	RunNumber     int
	Status        string
	Progress      float64
	CreatedAt     int64
	StartedAt     int64
	CompletedAt   int64
	FindingsCount int
	Error         string
	PreviousRunID string // ID of the previous run (for linking run history)
	TraceID       string // OTel trace ID for Langfuse lookup
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

// CreateMissionData represents the data for creating a new mission.
type CreateMissionData struct {
	Name        string
	Description string

	// Target configuration (mutually exclusive)
	TargetID     string
	InlineTarget *InlineTargetData

	// Workflow configuration (mutually exclusive)
	WorkflowID     string
	InlineWorkflow *InlineWorkflowData

	// Optional configuration
	Metadata map[string]string
}

// InlineTargetData represents inline target configuration data.
type InlineTargetData struct {
	Seeds    []*TargetSeedData
	Profile  string
	Depth    int32
	Excluded []string
	Metadata map[string]string
}

// TargetSeedData represents a target seed.
type TargetSeedData struct {
	Value string
	Type  string
	Scope string
}

// InlineWorkflowData represents inline workflow configuration data.
type InlineWorkflowData struct {
	Name     string
	Nodes    []*WorkflowNodeData
	Edges    []*WorkflowEdgeData
	Metadata map[string]string
}

// WorkflowNodeData represents a workflow node configuration.
type WorkflowNodeData struct {
	ID        string
	Type      string
	Name      string
	DependsOn []string
	Config    map[string]any
}

// WorkflowEdgeData represents a workflow edge configuration.
type WorkflowEdgeData struct {
	From      string
	To        string
	Condition string
}

// CreateMissionResultData represents the result of creating a mission.
type CreateMissionResultData struct {
	MissionID   string
	TargetID    string
	WorkflowID  string
	Name        string
	Description string
	Status      string
	CreatedAt   time.Time
}

// ProvisioningStep describes a single step in the tenant provisioning pipeline.
// Used by the provisional provisioner interface until the concrete type is wired.
type ProvisioningStep struct {
	Name      string
	Status    string
	Error     string
	Timestamp string
}

// InvitationRecord is the internal representation of a pending or consumed
// invitation.  Used by the invitation store interface stub.
type InvitationRecord struct {
	Token     string
	Email     string
	Roles     []string
	Status    string
	InvitedBy string
	CreatedAt string
	ExpiresAt string
}

// APIKeyRecord is the internal representation of an API key without the secret
// value.  Used by the API key store interface stub.
type APIKeyRecord struct {
	KeyID        string
	TenantID     string
	CreatedAt    string
	LastUsedAt   string
	AllowedKinds []string
	AllowedNames []string
	Name         string
	Capabilities []string
	CreatedBy    string
}

// BillingUsageRecord holds current resource consumption metrics for a tenant.
// Used by the billing store interface stub.
type BillingUsageRecord struct {
	MissionsUsed     int32
	MissionsLimit    int32
	FindingsUsed     int32
	FindingsLimit    int32
	TeamMembers      int32
	TeamMembersLimit int32
	APIKeys          int32
	APIKeysLimit     int32
}

// NewDaemonServer creates a new gRPC server that exposes daemon functionality.
//
// Parameters:
//   - daemon: The daemon instance to expose via gRPC
//   - credentialHandler: Handler for encrypted credential storage (may be nil if credentials are not configured)
//   - logger: Structured logger for request logging
//
// Returns:
//   - *DaemonServer: A new gRPC server ready to be registered
func NewDaemonServer(daemon DaemonInterface, credentialHandler *CredentialHandler, logger *slog.Logger) *DaemonServer {
	if logger == nil {
		logger = slog.Default().With("component", "daemon-grpc")
	}

	return &DaemonServer{
		daemon:            daemon,
		credentialHandler: credentialHandler,
		logger:            logger.With("component", "daemon-grpc"),
		sessionCounter:    0,
	}
}

// WithQuotaManager attaches a MissionQuotaChecker to the server so that
// RunMission enforces per-tenant mission quotas.  Call this immediately
// after NewDaemonServer and before registering the server:
//
//	srv := api.NewDaemonServer(d, handler, logger)
//	srv.WithQuotaManager(quotaMgr)
//	api.RegisterDaemonServiceServer(grpcSrv, srv)
func (s *DaemonServer) WithQuotaManager(qm MissionQuotaChecker) *DaemonServer {
	s.quotaManager = qm
	return s
}

// WithTenantService attaches a TenantService so that tenant management RPCs
// (CreateTenant, GetTenant, ListTenants, UpdateTenant, DeleteTenant) are
// backed by durable Redis storage.  Call this immediately after NewDaemonServer
// and before registering the server.
func (s *DaemonServer) WithTenantService(ts *component.TenantService) *DaemonServer {
	s.tenantService = ts
	return s
}

// WithKeycloakClient attaches a Keycloak Admin REST API client so that
// ListTenantMembers can query live user data from Keycloak. Call this
// immediately after NewDaemonServer and before registering the server.
func (s *DaemonServer) WithKeycloakClient(kc *keycloak.Client) *DaemonServer {
	s.keycloak = kc
	return s
}

// WithProvisioner attaches a Provisioner so that ProvisionTenant,
// GetProvisioningStatus, and DeprovisionTenant RPCs are backed by the real
// provisioning pipeline.  Call this immediately after NewDaemonServer and
// before registering the server.
func (s *DaemonServer) WithProvisioner(p *provisioner.Provisioner) *DaemonServer {
	s.provisioner = &provisionerAdapter{p: p}
	return s
}

// WithBillingStore attaches a billing store backed by TenantService and
// QuotaManager so that GetTenantBilling and UpdateTenantBilling RPCs return
// real data.  Call this immediately after NewDaemonServer and before
// registering the server.
func (s *DaemonServer) WithBillingStore(ts *component.TenantService, qm *component.QuotaManager) *DaemonServer {
	s.billingStore = &billingStoreAdapter{tenants: ts, quotas: qm}
	return s
}

// WithAPIKeyStore wires the API key authenticator so that CreateAPIKey,
// ListAPIKeys, and RevokeAPIKey RPCs operate against Redis-backed storage.
// Call this immediately after NewDaemonServer and before registering the server.
func (s *DaemonServer) WithAPIKeyStore(a *auth.APIKeyAuthenticator) *DaemonServer {
	s.apiKeyStore = &apiKeyStoreAdapter{auth: a}
	return s
}

// WithOnboardingStore wires a Redis-backed onboarding state store so that
// GetOnboardingState and UpdateOnboardingState RPCs are backed by durable storage.
// Call this immediately after NewDaemonServer and before registering the server.
func (s *DaemonServer) WithOnboardingStore(store *onboarding.RedisOnboardingStore) *DaemonServer {
	s.onboardingStore = store
	return s
}

// WithImpersonationIssuer wires the HMAC-SHA256 JWT issuer so that
// ImpersonateTenant returns a real signed token instead of an empty string.
// Call this immediately after NewDaemonServer and before registering the server.
func (s *DaemonServer) WithImpersonationIssuer(issuer *impersonation.Issuer) *DaemonServer {
	s.impersonationIssuer = issuer
	return s
}

// WithMissionDraftStore wires a Redis-backed mission draft store so that
// SaveMissionDraft and ListMissionDrafts RPCs are backed by durable storage.
// Call this immediately after NewDaemonServer and before registering the server.
func (s *DaemonServer) WithMissionDraftStore(store missionDraftStoreIface) *DaemonServer {
	s.missionDraftStore = store
	return s
}

// WithFindingStore wires the finding store so that the ExportFindings RPC can
// query and serialize tenant-scoped findings. Call this immediately after
// NewDaemonServer and before registering the server.
// Added by prod-unimplemented-apis spec.
func (s *DaemonServer) WithFindingStore(store findingStoreIface) *DaemonServer {
	s.findingStore = store
	return s
}

// WithQuotaStore wires the Redis-backed quota store so that GetTenantQuota and
// SetTenantQuota RPCs are backed by durable storage.
// Added by prod-feature-wiring spec.
func (s *DaemonServer) WithQuotaStore(store quotaStoreIface) *DaemonServer {
	s.quotaStore = store
	return s
}

// WithAlertStore wires the Redis-backed alert store so that ListAlerts,
// MarkAlertRead, and MarkAllAlertsRead RPCs are backed by durable storage.
// Added by prod-feature-wiring spec.
func (s *DaemonServer) WithAlertStore(store alertStoreIface) *DaemonServer {
	s.alertStore = store
	return s
}

// WithConversationStore wires the Redis-backed conversation store so that
// ListConversations and GetConversation RPCs are backed by durable storage.
// Added by prod-feature-wiring spec.
func (s *DaemonServer) WithConversationStore(store conversationStoreIface) *DaemonServer {
	s.conversationStore = store
	return s
}

// WithMembershipStore wires the membership store so that the membership RPCs
// (AddTenantMember, RemoveTenantMember, UpdateMemberRole, ListUserTenants,
// TransferOwnership) are backed by durable Redis storage.
// Call this immediately after NewDaemonServer and before registering the server.
func (s *DaemonServer) WithMembershipStore(ms membership.MembershipStore) *DaemonServer {
	s.membershipStore = ms
	return s
}

// WithSignupHandler wires the SignupHandler so that the SignupTenant RPC
// delegates to the real signup orchestration pipeline.  Call this immediately
// after NewDaemonServer and before registering the server.
//
// When not called (or called with nil), SignupTenant returns codes.Unavailable.
// This allows the server to start before the Keycloak admin client is ready
// (e.g. in dev mode with authz disabled).
//
// Added by the authz-02-keycloak-organizations spec.
func (s *DaemonServer) WithSignupHandler(h *provisioner.SignupHandler) *DaemonServer {
	s.signupHandler = h
	return s
}

// WithInviteHandler wires the InviteHandler so that the InviteMember,
// ResendInvitation, and AcceptInvitation RPCs are backed by real logic.
// Added by the authz-04-dashboard-fga-migration spec.
func (s *DaemonServer) WithInviteHandler(h *provisioner.InviteHandler) *DaemonServer {
	s.inviteHandler = h
	return s
}

// WithGrantHandler wires the GrantHandler so that GrantComponentAccess,
// RevokeComponentAccess, and ListUserComponentGrants RPCs work.
// Added by the authz-04-dashboard-fga-migration spec.
func (s *DaemonServer) WithGrantHandler(h *provisioner.GrantHandler) *DaemonServer {
	s.grantHandler = h
	return s
}

// WithTeamHandler wires the TeamHandler so that team management RPCs work.
// Added by the authz-04-dashboard-fga-migration spec.
func (s *DaemonServer) WithTeamHandler(h *provisioner.TeamHandler) *DaemonServer {
	s.teamHandler = h
	return s
}

// WithAuthorizer wires an FGA Authorizer for admin handlers that need direct
// FGA access (e.g. GetMyPermissions, ListTenantMembers via FGA).
// Added by the authz-04-dashboard-fga-migration spec.
func (s *DaemonServer) WithAuthorizer(az authzIface) *DaemonServer {
	s.authorizer = az
	return s
}

// WithKeycloakAdmin wires the provisioner-level KeycloakAdmin client for admin
// RPCs (InviteMember, RemoveMember, etc.) that need to call Keycloak admin APIs.
// Added by the authz-04-dashboard-fga-migration spec.
func (s *DaemonServer) WithKeycloakAdmin(ka provisioner.KeycloakAdmin) *DaemonServer {
	s.keycloakAdmin = ka
	return s
}

// ---------------------------------------------------------------------------
// provisionerAdapter bridges *provisioner.Provisioner to the DaemonServer's
// provisioner interface which uses positional arguments and different return
// types.
// ---------------------------------------------------------------------------

type provisionerAdapter struct {
	p *provisioner.Provisioner
}

func (a *provisionerAdapter) ProvisionTenant(ctx context.Context, tenantID, displayName, tier, ownerEmail, stripeCustomerID, stripeSubID string) (string, string, error) {
	result, err := a.p.ProvisionTenant(ctx, provisioner.ProvisionRequest{
		TenantID:         tenantID,
		DisplayName:      displayName,
		Tier:             tier,
		OwnerEmail:       ownerEmail,
		StripeCustomerID: stripeCustomerID,
		StripeSubID:      stripeSubID,
	})
	if err != nil {
		return "", "", err
	}
	return result.TenantID, result.APIKey, nil
}

func (a *provisionerAdapter) GetProvisioningStatus(ctx context.Context, tenantID string) (string, []ProvisioningStep, error) {
	ps, err := a.p.GetProvisioningStatus(ctx, tenantID)
	if err != nil {
		return "", nil, err
	}
	steps := make([]ProvisioningStep, len(ps.Steps))
	for i, s := range ps.Steps {
		steps[i] = ProvisioningStep{
			Name:      s.Name,
			Status:    s.Status,
			Error:     s.Error,
			Timestamp: s.Timestamp.Format(time.RFC3339),
		}
	}
	return ps.Status, steps, nil
}

func (a *provisionerAdapter) DeprovisionTenant(ctx context.Context, tenantID string) error {
	return a.p.DeprovisionTenant(ctx, tenantID)
}

// ---------------------------------------------------------------------------
// billingStoreAdapter composes TenantService and QuotaManager to satisfy the
// billingStore interface.
// ---------------------------------------------------------------------------

type billingStoreAdapter struct {
	tenants *component.TenantService
	quotas  *component.QuotaManager
}

func (a *billingStoreAdapter) GetBilling(ctx context.Context, tenantID string) (string, string, bool, BillingUsageRecord, error) {
	record, err := a.tenants.GetTenant(ctx, tenantID)
	if err != nil {
		return "", "", false, BillingUsageRecord{}, err
	}

	var usage BillingUsageRecord
	if a.quotas != nil {
		quota, qErr := a.quotas.GetQuota(ctx, tenantID)
		if qErr == nil && quota != nil {
			usage.MissionsLimit = int32(quota.MaxMissions)
			usage.FindingsLimit = int32(quota.MaxFindings)
			// TeamMembersLimit and APIKeysLimit come from tenant config
		}
	}

	// Read limits from tenant config where quota doesn't track them
	if record.Config != nil {
		if v, ok := record.Config["max_api_keys"]; ok {
			if n, err := parseInt32(v); err == nil {
				usage.APIKeysLimit = n
			}
		}
	}

	return record.Tier, record.StripeCustomerID, record.BillingAlert, usage, nil
}

func (a *billingStoreAdapter) UpdateBilling(ctx context.Context, tenantID, tier, stripeCustomerID, stripeSubID string, billingAlert bool) (*component.TenantRecord, error) {
	updates := make(map[string]string)
	if tier != "" {
		updates["tier"] = tier
	}
	if stripeCustomerID != "" {
		updates["stripe_customer_id"] = stripeCustomerID
	}
	if stripeSubID != "" {
		updates["stripe_sub_id"] = stripeSubID
	}
	updates["billing_alert"] = fmt.Sprintf("%t", billingAlert)
	return a.tenants.UpdateTenant(ctx, tenantID, updates)
}

// ---------------------------------------------------------------------------
// apiKeyStoreAdapter bridges *auth.APIKeyAuthenticator to the apiKeyStore
// interface expected by DaemonServer.  It translates between the auth
// package's APIKeyRecord type and the server-local APIKeyRecord type, and
// maps the slightly different method signatures.
// ---------------------------------------------------------------------------

type apiKeyStoreAdapter struct {
	auth *auth.APIKeyAuthenticator
}

// Create generates a new API key via the auth package and returns the stable
// key ID plus the raw (unhashed) key material.  The raw key is shown once
// and never stored.
func (a *apiKeyStoreAdapter) Create(ctx context.Context, tenantID string, allowedKinds, allowedNames, capabilities []string, name, createdBy string) (keyID, rawKey string, err error) {
	raw, record, err := a.auth.CreateKey(ctx, tenantID, allowedKinds, allowedNames, capabilities, name, createdBy)
	if err != nil {
		return "", "", err
	}
	return record.KeyID, raw, nil
}

// List retrieves all API key records for a tenant, converting auth.APIKeyRecord
// to the server-local APIKeyRecord type.  Key hashes are never returned.
func (a *apiKeyStoreAdapter) List(ctx context.Context, tenantID string) ([]APIKeyRecord, error) {
	authRecords, err := a.auth.ListKeys(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	records := make([]APIKeyRecord, 0, len(authRecords))
	for _, r := range authRecords {
		records = append(records, APIKeyRecord{
			KeyID:        r.KeyID,
			TenantID:     r.TenantID,
			CreatedAt:    r.CreatedAt.Format(time.RFC3339),
			LastUsedAt:   r.LastUsedAt.Format(time.RFC3339),
			AllowedKinds: r.AllowedKinds,
			AllowedNames: r.AllowedNames,
			Name:         r.Name,
			Capabilities: r.Capabilities,
			CreatedBy:    r.CreatedBy,
		})
	}
	return records, nil
}

// Revoke marks the given key as revoked in Redis and removes its Casbin
// policies.  The revoked record is retained for audit purposes.
func (a *apiKeyStoreAdapter) Revoke(ctx context.Context, keyID string) error {
	return a.auth.RevokeKey(ctx, keyID)
}

// parseInt32 is a small helper for parsing int32 from string config values.
func parseInt32(s string) (int32, error) {
	var n int32
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err
}

// containsString reports whether needle is present in the haystack slice.
// Used for capability-based scope filtering on agent lists.
func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// Connect establishes a client connection to the daemon.
func (s *DaemonServer) Connect(ctx context.Context, req *daemonpb.ConnectRequest) (*daemonpb.ConnectResponse, error) {
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

	return &daemonpb.ConnectResponse{
		DaemonVersion: version.Version,
		SessionId:     sessionID,
		GrpcAddress:   status.GRPCAddress,
	}, nil
}

// Ping checks if the daemon is responsive.
func (s *DaemonServer) Ping(ctx context.Context, req *daemonpb.PingRequest) (*daemonpb.PingResponse, error) {
	return &daemonpb.PingResponse{
		Timestamp: time.Now().Unix(),
	}, nil
}

// Status returns the current daemon status.
func (s *DaemonServer) Status(ctx context.Context, req *daemonpb.StatusRequest) (*daemonpb.StatusResponse, error) {
	s.logger.Debug("status request received")

	status, err := s.daemon.Status()
	if err != nil {
		s.logger.Error("failed to get daemon status", "error", err)
		return nil, status_grpc.Errorf(codes.Internal, "failed to get daemon status: %v", err)
	}

	return &daemonpb.StatusResponse{
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
func (s *DaemonServer) RunMission(req *daemonpb.RunMissionRequest, stream grpc.ServerStreamingServer[daemonpb.RunMissionResponse]) error {
	s.logger.Info("mission run request received",
		"workflow_path", req.WorkflowPath,
		"workflow_yaml_size", len(req.WorkflowYaml),
		"mission_id", req.MissionId,
		"memory_continuity", req.MemoryContinuity,
	)

	// Enforce per-tenant quotas before any resource allocation.
	if s.quotaManager != nil {
		if err := s.quotaManager.CheckMissionQuota(stream.Context()); err != nil {
			s.logger.Warn("mission submission rejected: mission quota exceeded", "error", err)
			return err
		}
		if err := s.quotaManager.CheckAgentQuota(stream.Context()); err != nil {
			s.logger.Warn("mission submission rejected: agent quota exceeded", "error", err)
			return err
		}
		// Reserve a default memory budget per mission (10MB) for working + mission memory.
		if err := s.quotaManager.CheckMemoryQuota(stream.Context(), 10); err != nil {
			s.logger.Warn("mission submission rejected: memory quota exceeded", "error", err)
			return err
		}
	}

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

		// Validate YAML by parsing it using the mission definition parser
		if _, err := mission.ParseDefinitionFromBytes([]byte(req.WorkflowYaml)); err != nil {
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

	// Mission accepted: increment the tenant's running mission counter.
	if s.quotaManager != nil {
		if err := s.quotaManager.IncrementMissionCount(stream.Context()); err != nil {
			// Non-fatal: mission is already running. Log and continue — a
			// counter mismatch here is harmless given the floor-at-zero
			// semantics in DecrementMissionCount.
			s.logger.Warn("failed to increment mission quota counter", "error", err)
		}
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
			protoEvent := &daemonpb.RunMissionResponse{
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
func (s *DaemonServer) StopMission(ctx context.Context, req *daemonpb.StopMissionRequest) (*daemonpb.StopMissionResponse, error) {
	s.logger.Info("mission stop request received",
		"mission_id", req.MissionId,
		"force", req.Force,
	)

	err := s.daemon.StopMission(ctx, req.MissionId, req.Force)
	if err != nil {
		s.logger.Error("failed to stop mission", "error", err, "mission_id", req.MissionId)
		return &daemonpb.StopMissionResponse{
			Success: false,
			Message: fmt.Sprintf("failed to stop mission: %v", err),
		}, nil
	}

	return &daemonpb.StopMissionResponse{
		Success: true,
		Message: "Mission stop requested",
	}, nil
}

// ListMissions returns all missions (past and active).
//
// When authentication is enabled the tenant is extracted from the context and
// only missions belonging to that tenant are returned. When authentication is
// disabled (empty tenant) all missions are returned for backward compatibility.
func (s *DaemonServer) ListMissions(ctx context.Context, req *daemonpb.ListMissionsRequest) (*daemonpb.ListMissionsResponse, error) {
	tenant := auth.TenantFromContext(ctx)

	s.logger.Debug("mission list request received",
		"active_only", req.ActiveOnly,
		"status_filter", req.StatusFilter,
		"name_pattern", req.NamePattern,
		"limit", req.Limit,
		"offset", req.Offset,
		"tenant", tenant,
	)

	missions, total, err := s.daemon.ListMissions(ctx, req.ActiveOnly, req.StatusFilter, req.NamePattern, int(req.Limit), int(req.Offset))
	if err != nil {
		s.logger.Error("failed to list missions", "error", err)
		return nil, status_grpc.Errorf(codes.Internal, "failed to list missions: %v", err)
	}

	// Apply tenant filtering when auth is enabled.
	// An empty tenant means no tenant context is set; return all missions for backward compatibility.
	if tenant != "" {
		filtered := missions[:0]
		for _, m := range missions {
			if m.TenantID == tenant {
				filtered = append(filtered, m)
			}
		}
		// Adjust total to reflect the filtered count so pagination metadata stays accurate.
		total = len(filtered)
		missions = filtered
	}

	// Convert to proto messages
	protoMissions := make([]*daemonpb.MissionInfo, len(missions))
	for i, m := range missions {
		protoMissions[i] = &daemonpb.MissionInfo{
			Id:           m.ID,
			Name:         m.Name,
			Description:  m.Description,
			WorkflowPath: m.WorkflowPath,
			WorkflowYaml: m.WorkflowYAML,
			Status:       m.Status,
			StartTime:    m.StartTime.Unix(),
			EndTime:      m.EndTime.Unix(),
			FindingCount: m.FindingCount,
			Progress:     m.Progress,
		}
	}

	return &daemonpb.ListMissionsResponse{
		Missions: protoMissions,
		Total:    int32(total),
	}, nil
}

// ListAgents returns all registered agents from the etcd registry.
//
// Capability-based filtering is applied when an authenticated identity is present
// in the context. If the identity carries non-empty allowed_kinds or allowed_names
// claims (scoped API keys), only agents matching those constraints are returned.
// Identities with the wildcard capability "*" always receive the full list.
// When no identity is present (dev mode / unauthenticated path), no filtering is
// applied for backward compatibility.
func (s *DaemonServer) ListAgents(ctx context.Context, req *daemonpb.ListAgentsRequest) (*daemonpb.ListAgentsResponse, error) {
	s.logger.Debug("agent list request received", "kind", req.Kind)

	agents, err := s.daemon.ListAgents(ctx, req.Kind)
	if err != nil {
		s.logger.Error("failed to list agents", "error", err)
		return nil, status_grpc.Errorf(codes.Internal, "failed to list agents: %v", err)
	}

	// Apply capability-based scope filtering when an identity is present.
	// Capabilities are set by APIKeyAuthenticator for scoped API keys; the
	// wildcard "*" grants unrestricted access within the caller's tenant.
	if identity, ok := auth.GibsonIdentityFromContext(ctx); ok && !slices.Contains(identity.Capabilities, "*") {
		// Extract allowed_kinds and allowed_names from the identity claims.
		// These are set by APIKeyAuthenticator for scoped API keys.
		var allowedKinds, allowedNames []string
		if v, exists := identity.GetClaim("allowed_kinds"); exists {
			if kinds, ok := v.([]string); ok {
				allowedKinds = kinds
			}
		}
		if v, exists := identity.GetClaim("allowed_names"); exists {
			if names, ok := v.([]string); ok {
				allowedNames = names
			}
		}

		// Only filter when at least one scope constraint is present.
		if len(allowedKinds) > 0 || len(allowedNames) > 0 {
			filtered := agents[:0]
			for _, a := range agents {
				kindAllowed := len(allowedKinds) == 0 || containsString(allowedKinds, a.Kind)
				nameAllowed := len(allowedNames) == 0 || containsString(allowedNames, a.Name)
				if kindAllowed && nameAllowed {
					filtered = append(filtered, a)
				}
			}
			agents = filtered
			s.logger.Debug("agent list filtered by identity scope",
				"allowed_kinds", allowedKinds,
				"allowed_names", allowedNames,
				"result_count", len(agents),
			)
		}
	}

	// Convert to proto messages
	protoAgents := make([]*daemonpb.AgentInfo, len(agents))
	for i, a := range agents {
		protoAgents[i] = &daemonpb.AgentInfo{
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

	return &daemonpb.ListAgentsResponse{
		Agents: protoAgents,
	}, nil
}

// GetAgentStatus returns the current status of a specific agent.
func (s *DaemonServer) GetAgentStatus(ctx context.Context, req *daemonpb.GetAgentStatusRequest) (*daemonpb.GetAgentStatusResponse, error) {
	s.logger.Debug("agent status request received", "agent_id", req.AgentId)

	agentStatus, err := s.daemon.GetAgentStatus(ctx, req.AgentId)
	if err != nil {
		s.logger.Error("failed to get agent status", "error", err, "agent_id", req.AgentId)
		return nil, status_grpc.Errorf(codes.Internal, "failed to get agent status: %v", err)
	}

	return &daemonpb.GetAgentStatusResponse{
		Agent: &daemonpb.AgentInfo{
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
//
// Capability-based filtering is applied when an authenticated identity is present.
// The identity must hold the "tools:execute" capability (or the wildcard "*") to
// receive any tools. If neither capability is present, an empty list is returned.
// When no identity is present (dev mode / unauthenticated path), no filtering is
// applied for backward compatibility.
func (s *DaemonServer) ListTools(ctx context.Context, req *daemonpb.ListToolsRequest) (*daemonpb.ListToolsResponse, error) {
	s.logger.Debug("tool list request received")

	// Gate the entire tool list on the tools:execute capability when an identity
	// is present. Capabilities are set by APIKeyAuthenticator for scoped API
	// keys; "*" grants unrestricted access.
	if identity, ok := auth.GibsonIdentityFromContext(ctx); ok {
		if !slices.Contains(identity.Capabilities, "tools:execute") && !slices.Contains(identity.Capabilities, "*") {
			s.logger.Debug("tool list denied: identity lacks tools:execute capability",
				"subject", identity.Subject,
			)
			return &daemonpb.ListToolsResponse{Tools: []*daemonpb.ToolInfo{}}, nil
		}
	}

	tools, err := s.daemon.ListTools(ctx)
	if err != nil {
		s.logger.Error("failed to list tools", "error", err)
		return nil, status_grpc.Errorf(codes.Internal, "failed to list tools: %v", err)
	}

	// Convert to proto messages
	protoTools := make([]*daemonpb.ToolInfo, len(tools))
	for i, t := range tools {
		var protoCaps *daemonpb.Capabilities
		if t.Capabilities != nil {
			protoCaps = &daemonpb.Capabilities{
				HasRoot:         t.Capabilities.HasRoot,
				HasSudo:         t.Capabilities.HasSudo,
				CanRawSocket:    t.Capabilities.CanRawSocket,
				Features:        t.Capabilities.Features,
				BlockedArgs:     t.Capabilities.BlockedArgs,
				ArgAlternatives: t.Capabilities.ArgAlternatives,
			}
		}
		protoTools[i] = &daemonpb.ToolInfo{
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

	return &daemonpb.ListToolsResponse{
		Tools: protoTools,
	}, nil
}

// ListPlugins returns all registered plugins from the etcd registry.
//
// Capability-based filtering is applied when an authenticated identity is present.
// For each plugin, the identity must hold either the "plugin:{name}:read" capability
// or the wildcard "*" capability to see that plugin in the response. Plugins the
// identity is not authorised to see are silently omitted.
// When no identity is present (dev mode / unauthenticated path), no filtering is
// applied for backward compatibility.
func (s *DaemonServer) ListPlugins(ctx context.Context, req *daemonpb.ListPluginsRequest) (*daemonpb.ListPluginsResponse, error) {
	s.logger.Debug("plugin list request received")

	plugins, err := s.daemon.ListPlugins(ctx)
	if err != nil {
		s.logger.Error("failed to list plugins", "error", err)
		return nil, status_grpc.Errorf(codes.Internal, "failed to list plugins: %v", err)
	}

	// When an identity is present and does not hold the wildcard capability,
	// filter the plugin list to only those the identity is authorised to read.
	if identity, ok := auth.GibsonIdentityFromContext(ctx); ok && !slices.Contains(identity.Capabilities, "*") {
		filtered := plugins[:0]
		for _, p := range plugins {
			if slices.Contains(identity.Capabilities, "plugin:"+p.Name+":read") {
				filtered = append(filtered, p)
			}
		}
		plugins = filtered
		s.logger.Debug("plugin list filtered by identity capabilities",
			"subject", identity.Subject,
			"result_count", len(plugins),
		)
	}

	// Convert to proto messages
	protoPlugins := make([]*daemonpb.PluginInfo, len(plugins))
	for i, p := range plugins {
		protoPlugins[i] = &daemonpb.PluginInfo{
			Id:          p.ID,
			Name:        p.Name,
			Version:     p.Version,
			Endpoint:    p.Endpoint,
			Description: p.Description,
			Health:      p.Health,
			LastSeen:    p.LastSeen.Unix(),
		}
	}

	return &daemonpb.ListPluginsResponse{
		Plugins: protoPlugins,
	}, nil
}

// QueryPlugin executes a method on a plugin and returns the result.
func (s *DaemonServer) QueryPlugin(ctx context.Context, req *daemonpb.QueryPluginRequest) (*daemonpb.QueryPluginResponse, error) {
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
		return &daemonpb.QueryPluginResponse{
			Error:      err.Error(),
			DurationMs: duration.Milliseconds(),
		}, nil
	}

	// Convert result to TypedValue
	s.logger.Debug("plugin query completed", "plugin", req.Name, "method", req.Method, "duration_ms", duration.Milliseconds())
	return &daemonpb.QueryPluginResponse{
		Result:     anyToTypedValue(result),
		DurationMs: duration.Milliseconds(),
	}, nil
}

// Subscribe establishes an event stream for TUI real-time updates.
func (s *DaemonServer) Subscribe(req *daemonpb.SubscribeRequest, stream grpc.ServerStreamingServer[daemonpb.SubscribeResponse]) error {
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
			protoEvent := &daemonpb.SubscribeResponse{
				EventType: event.EventType,
				Timestamp: event.Timestamp.Unix(),
				Source:    event.Source,
				Data:      StringToTypedMap(event.Data),
			}

			// Add specific event type if present
			if event.MissionEvent != nil {
				protoEvent.Event = &daemonpb.SubscribeResponse_MissionEvent{
					MissionEvent: &daemonpb.MissionEvent{
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
				var finding *daemonpb.FindingInfo
				if event.AttackEvent.Finding != nil {
					finding = &daemonpb.FindingInfo{
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
				protoEvent.Event = &daemonpb.SubscribeResponse_AttackEvent{
					AttackEvent: &daemonpb.AttackEvent{
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
				protoEvent.Event = &daemonpb.SubscribeResponse_AgentEvent{
					AgentEvent: &daemonpb.AgentEvent{
						EventType: event.AgentEvent.EventType,
						Timestamp: event.AgentEvent.Timestamp.Unix(),
						AgentId:   event.AgentEvent.AgentID,
						AgentName: event.AgentEvent.AgentName,
						Message:   event.AgentEvent.Message,
						Data:      StringToTypedMap(event.AgentEvent.Data),
					},
				}
			} else if event.FindingEvent != nil {
				protoEvent.Event = &daemonpb.SubscribeResponse_FindingEvent{
					FindingEvent: &daemonpb.FindingEvent{
						EventType: event.FindingEvent.EventType,
						Timestamp: event.FindingEvent.Timestamp.Unix(),
						Finding: &daemonpb.FindingInfo{
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
			} else if event.ToolEvent != nil {
				protoEvent.Event = convertToToolEvent(event.ToolEvent)
			} else if event.LLMEvent != nil {
				protoEvent.Event = convertToLLMEvent(event.LLMEvent)
			} else if event.OrchestratorEvent != nil {
				protoEvent.Event = convertToOrchestratorEvent(event.OrchestratorEvent)
			}

			// Send event to client
			if err := stream.Send(protoEvent); err != nil {
				s.logger.Error("failed to send event", "error", err)
				return status_grpc.Errorf(codes.Internal, "failed to send event: %v", err)
			}
		}
	}
}

// convertToToolEvent converts internal ToolEventData to proto ToolEvent oneof wrapper.
func convertToToolEvent(data *ToolEventData) *daemonpb.SubscribeResponse_ToolEvent {
	if data == nil {
		return nil
	}

	return &daemonpb.SubscribeResponse_ToolEvent{
		ToolEvent: &daemonpb.ToolEvent{
			EventType:       data.EventType,
			Timestamp:       data.Timestamp.Unix(),
			ToolName:        data.ToolName,
			AgentId:         data.AgentID,
			AgentName:       data.AgentName,
			MissionId:       data.MissionID,
			Message:         data.Message,
			Duration:        data.Duration,
			Progress:        data.Progress,
			Error:           data.Error,
			ErrorCode:       data.ErrorCode,
			Warning:         data.Warning,
			WarningSeverity: data.WarningSeverity,
		},
	}
}

// convertToLLMEvent converts internal LLMEventData to proto LLMEvent oneof wrapper.
func convertToLLMEvent(data *LLMEventData) *daemonpb.SubscribeResponse_LlmEvent {
	if data == nil {
		return nil
	}

	return &daemonpb.SubscribeResponse_LlmEvent{
		LlmEvent: &daemonpb.LLMEvent{
			EventType:        data.EventType,
			Timestamp:        data.Timestamp.Unix(),
			AgentId:          data.AgentID,
			AgentName:        data.AgentName,
			Model:            data.Model,
			Slot:             data.Slot,
			MessageCount:     int32(data.MessageCount),
			PromptTokens:     int32(data.PromptTokens),
			CompletionTokens: int32(data.CompletionTokens),
			TotalTokens:      int32(data.TotalTokens),
			DurationMs:       data.Duration,
			Cached:           data.Cached,
			Error:            data.Error,
			ErrorCode:        data.ErrorCode,
			WillRetry:        data.WillRetry,
		},
	}
}

// convertToOrchestratorEvent converts internal OrchestratorEventData to proto OrchestratorEvent oneof wrapper.
func convertToOrchestratorEvent(data *OrchestratorEventData) *daemonpb.SubscribeResponse_OrchestratorEvent {
	if data == nil {
		return nil
	}

	return &daemonpb.SubscribeResponse_OrchestratorEvent{
		OrchestratorEvent: &daemonpb.OrchestratorEvent{
			EventType:       data.EventType,
			Timestamp:       data.Timestamp.Unix(),
			MissionId:       data.MissionID,
			Iteration:       int32(data.Iteration),
			Action:          data.Action,
			TargetNodeId:    data.TargetNodeID,
			TargetAgentName: data.TargetAgentName,
			Confidence:      data.Confidence,
			Reasoning:       data.Reasoning,
			TokensUsed:      int32(data.TokensUsed),
			LatencyMs:       data.Latency,
			ApprovalId:      data.ApprovalID,
			Risk:            data.Risk,
			TimeoutSeconds:  int32(data.Timeout),
		},
	}
}

// StartComponent starts a component (agent, tool, or plugin) by kind and name.
func (s *DaemonServer) StartComponent(ctx context.Context, req *daemonpb.StartComponentRequest) (*daemonpb.StartComponentResponse, error) {
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

	return &daemonpb.StartComponentResponse{
		Success: true,
		Pid:     int32(result.PID),
		Port:    int32(result.Port),
		Message: fmt.Sprintf("Component '%s' started successfully", req.Name),
		LogPath: result.LogPath,
	}, nil
}

// StopComponent stops a running component (agent, tool, or plugin) by kind and name.
func (s *DaemonServer) StopComponent(ctx context.Context, req *daemonpb.StopComponentRequest) (*daemonpb.StopComponentResponse, error) {
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

	return &daemonpb.StopComponentResponse{
		Success:      true,
		StoppedCount: int32(result.StoppedCount),
		TotalCount:   int32(result.TotalCount),
		Message:      fmt.Sprintf("Stopped %d/%d instances of component '%s'", result.StoppedCount, result.TotalCount, req.Name),
	}, nil
}

// PauseMission pauses a running mission at the next clean checkpoint boundary.
func (s *DaemonServer) PauseMission(ctx context.Context, req *daemonpb.PauseMissionRequest) (*daemonpb.PauseMissionResponse, error) {
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

	return &daemonpb.PauseMissionResponse{
		Success:      true,
		CheckpointId: "", // Will be populated when checkpoint system is fully integrated
		Message:      fmt.Sprintf("Mission %s paused successfully", req.MissionId),
	}, nil
}

// ResumeMission resumes a paused mission from its last checkpoint and streams execution events.
func (s *DaemonServer) ResumeMission(req *daemonpb.ResumeMissionRequest, stream grpc.ServerStreamingServer[daemonpb.ResumeMissionResponse]) error {
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
			protoEvent := &daemonpb.ResumeMissionResponse{
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
func (s *DaemonServer) GetMissionHistory(ctx context.Context, req *daemonpb.GetMissionHistoryRequest) (*daemonpb.GetMissionHistoryResponse, error) {
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
	protoRuns := make([]*daemonpb.MissionRun, len(runs))
	for i, run := range runs {
		protoRuns[i] = &daemonpb.MissionRun{
			MissionId:     run.MissionID,
			RunNumber:     int32(run.RunNumber),
			Status:        run.Status,
			CreatedAt:     run.CreatedAt,
			CompletedAt:   run.CompletedAt,
			FindingsCount: int32(run.FindingsCount),
			PreviousRunId: run.PreviousRunID,
			TraceId:       run.TraceID,
		}
	}

	s.logger.Debug("mission history retrieved", "name", req.Name, "count", len(runs), "total", total)

	return &daemonpb.GetMissionHistoryResponse{
		Runs:  protoRuns,
		Total: int32(total),
	}, nil
}

// GetMissionCheckpoints returns all checkpoints for a specific mission.
func (s *DaemonServer) GetMissionCheckpoints(ctx context.Context, req *daemonpb.GetMissionCheckpointsRequest) (*daemonpb.GetMissionCheckpointsResponse, error) {
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
	protoCheckpoints := make([]*daemonpb.CheckpointInfo, len(checkpoints))
	for i, cp := range checkpoints {
		protoCheckpoints[i] = &daemonpb.CheckpointInfo{
			CheckpointId:   cp.CheckpointID,
			CreatedAt:      cp.CreatedAt,
			CompletedNodes: int32(cp.CompletedNodes),
			TotalNodes:     int32(cp.TotalNodes),
			FindingsCount:  int32(cp.FindingsCount),
			Version:        int32(cp.Version),
		}
	}

	s.logger.Debug("mission checkpoints retrieved", "mission_id", req.MissionId, "count", len(checkpoints))

	return &daemonpb.GetMissionCheckpointsResponse{
		Checkpoints: protoCheckpoints,
	}, nil
}

// InstallAllComponent installs all components from a mono-repo.
func (s *DaemonServer) InstallAllComponent(ctx context.Context, req *daemonpb.InstallAllComponentRequest) (*daemonpb.InstallAllComponentResponse, error) {
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
	protoSuccessful := make([]*daemonpb.InstallAllResultItem, len(result.Successful))
	for i := range result.Successful {
		protoSuccessful[i] = &daemonpb.InstallAllResultItem{
			Name:    result.Successful[i].Name,
			Version: result.Successful[i].Version,
			Path:    result.Successful[i].Path,
		}
	}

	protoSkipped := make([]*daemonpb.InstallAllResultItem, len(result.Skipped))
	for i := range result.Skipped {
		protoSkipped[i] = &daemonpb.InstallAllResultItem{
			Name:    result.Skipped[i].Name,
			Version: result.Skipped[i].Version,
			Path:    result.Skipped[i].Path,
		}
	}

	protoFailed := make([]*daemonpb.InstallAllFailedItem, len(result.Failed))
	for i := range result.Failed {
		protoFailed[i] = &daemonpb.InstallAllFailedItem{
			Name:  result.Failed[i].Name,
			Path:  result.Failed[i].Path,
			Error: result.Failed[i].Error,
		}
	}

	return &daemonpb.InstallAllComponentResponse{
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
func (s *DaemonServer) UninstallComponent(ctx context.Context, req *daemonpb.UninstallComponentRequest) (*daemonpb.UninstallComponentResponse, error) {
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

	return &daemonpb.UninstallComponentResponse{
		Success: true,
		Message: fmt.Sprintf("Component '%s' uninstalled successfully", req.Name),
	}, nil
}

// UpdateComponent updates a component (agent, tool, or plugin) to the latest version.
func (s *DaemonServer) UpdateComponent(ctx context.Context, req *daemonpb.UpdateComponentRequest) (*daemonpb.UpdateComponentResponse, error) {
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

	return &daemonpb.UpdateComponentResponse{
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
func (s *DaemonServer) BuildComponent(ctx context.Context, req *daemonpb.BuildComponentRequest) (*daemonpb.BuildComponentResponse, error) {
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

	return &daemonpb.BuildComponentResponse{
		Success:    result.Success,
		Stdout:     result.Stdout,
		Stderr:     result.Stderr,
		DurationMs: result.DurationMs,
		Message:    msg,
	}, nil
}

// ShowComponent returns detailed information about a component (agent, tool, or plugin).
func (s *DaemonServer) ShowComponent(ctx context.Context, req *daemonpb.ShowComponentRequest) (*daemonpb.ShowComponentResponse, error) {
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

	return &daemonpb.ShowComponentResponse{
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
func (s *DaemonServer) GetComponentLogs(req *daemonpb.GetComponentLogsRequest, stream grpc.ServerStreamingServer[daemonpb.GetComponentLogsResponse]) error {
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
			protoEntry := &daemonpb.GetComponentLogsResponse{
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
func (s *DaemonServer) InstallMission(ctx context.Context, req *daemonpb.InstallMissionRequest) (*daemonpb.InstallMissionResponse, error) {
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
	protoDeps := make([]*daemonpb.InstalledDependency, len(result.Dependencies))
	for i, dep := range result.Dependencies {
		protoDeps[i] = &daemonpb.InstalledDependency{
			Type:             dep.Type,
			Name:             dep.Name,
			AlreadyInstalled: dep.AlreadyInstalled,
		}
	}

	return &daemonpb.InstallMissionResponse{
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
func (s *DaemonServer) UninstallMission(ctx context.Context, req *daemonpb.UninstallMissionRequest) (*daemonpb.UninstallMissionResponse, error) {
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

	return &daemonpb.UninstallMissionResponse{
		Success: true,
		Message: fmt.Sprintf("Mission '%s' uninstalled successfully", req.Name),
	}, nil
}

// ListMissionDefinitions returns all installed mission definitions.
func (s *DaemonServer) ListMissionDefinitions(ctx context.Context, req *daemonpb.ListMissionDefinitionsRequest) (*daemonpb.ListMissionDefinitionsResponse, error) {
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
	protoDefinitions := make([]*daemonpb.MissionDefinitionInfo, len(definitions))
	for i, def := range definitions {
		protoDefinitions[i] = &daemonpb.MissionDefinitionInfo{
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

	return &daemonpb.ListMissionDefinitionsResponse{
		Missions: protoDefinitions,
		Total:    int32(total),
	}, nil
}

// UpdateMission updates an installed mission to the latest version.
func (s *DaemonServer) UpdateMission(ctx context.Context, req *daemonpb.UpdateMissionRequest) (*daemonpb.UpdateMissionResponse, error) {
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

	return &daemonpb.UpdateMissionResponse{
		Success:    true,
		Updated:    result.Updated,
		OldVersion: result.OldVersion,
		NewVersion: result.NewVersion,
		DurationMs: result.DurationMs,
		Message:    message,
	}, nil
}

// CreateMission creates a new mission with target and workflow configuration.
func (s *DaemonServer) CreateMission(ctx context.Context, req *daemonpb.CreateMissionRequest) (*daemonpb.CreateMissionResponse, error) {
	s.logger.Info("create mission request received",
		"name", req.Name,
		"has_inline_target", req.GetInlineTarget() != nil,
		"has_inline_workflow", req.GetInlineWorkflow() != nil,
	)

	// Validate request - name is required
	if req.Name == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "mission name is required")
	}

	// Build CreateMissionData from proto request
	data := CreateMissionData{
		Name:        req.Name,
		Description: req.Description,
		Metadata:    req.Metadata,
	}

	// Handle target configuration (oneof)
	switch tc := req.GetTargetConfig().(type) {
	case *daemonpb.CreateMissionRequest_TargetId:
		if tc.TargetId == "" {
			return nil, status_grpc.Errorf(codes.InvalidArgument, "target_id cannot be empty")
		}
		data.TargetID = tc.TargetId
	case *daemonpb.CreateMissionRequest_InlineTarget:
		inlineTarget := tc.InlineTarget
		if inlineTarget == nil {
			return nil, status_grpc.Errorf(codes.InvalidArgument, "inline_target cannot be nil")
		}
		// Convert proto InlineTargetConfig to InlineTargetData
		seeds := make([]*TargetSeedData, len(inlineTarget.Seeds))
		for i, s := range inlineTarget.Seeds {
			seeds[i] = &TargetSeedData{
				Value: s.Value,
				Type:  s.Type,
				Scope: s.Scope,
			}
		}
		data.InlineTarget = &InlineTargetData{
			Seeds:    seeds,
			Profile:  inlineTarget.Profile,
			Depth:    inlineTarget.Depth,
			Excluded: inlineTarget.Excluded,
			Metadata: inlineTarget.Metadata,
		}
	default:
		return nil, status_grpc.Errorf(codes.InvalidArgument, "target configuration is required (target_id or inline_target)")
	}

	// Handle workflow configuration (oneof)
	switch wc := req.GetWorkflowConfig().(type) {
	case *daemonpb.CreateMissionRequest_WorkflowId:
		if wc.WorkflowId == "" {
			return nil, status_grpc.Errorf(codes.InvalidArgument, "workflow_id cannot be empty")
		}
		data.WorkflowID = wc.WorkflowId
	case *daemonpb.CreateMissionRequest_InlineWorkflow:
		inlineWorkflow := wc.InlineWorkflow
		if inlineWorkflow == nil {
			return nil, status_grpc.Errorf(codes.InvalidArgument, "inline_workflow cannot be nil")
		}
		// Convert proto InlineWorkflowConfig to InlineWorkflowData
		nodes := make([]*WorkflowNodeData, len(inlineWorkflow.Nodes))
		for i, n := range inlineWorkflow.Nodes {
			// Convert TypedMap config to map[string]any
			var config map[string]any
			if n.Config != nil {
				config = TypedMapToMap(n.Config)
			}
			nodes[i] = &WorkflowNodeData{
				ID:        n.Id,
				Type:      n.Type,
				Name:      n.Name,
				DependsOn: n.DependsOn,
				Config:    config,
			}
		}
		edges := make([]*WorkflowEdgeData, len(inlineWorkflow.Edges))
		for i, e := range inlineWorkflow.Edges {
			edges[i] = &WorkflowEdgeData{
				From:      e.From,
				To:        e.To,
				Condition: e.Condition,
			}
		}
		data.InlineWorkflow = &InlineWorkflowData{
			Name:     inlineWorkflow.Name,
			Nodes:    nodes,
			Edges:    edges,
			Metadata: inlineWorkflow.Metadata,
		}
	default:
		return nil, status_grpc.Errorf(codes.InvalidArgument, "workflow configuration is required (workflow_id or inline_workflow)")
	}

	// Call daemon implementation
	result, err := s.daemon.CreateMission(ctx, data)
	if err != nil {
		s.logger.Error("failed to create mission", "error", err, "name", req.Name)

		// Map errors to appropriate gRPC codes
		if strings.Contains(err.Error(), "not found") {
			return nil, status_grpc.Errorf(codes.NotFound, "%v", err)
		}
		if strings.Contains(err.Error(), "validation") || strings.Contains(err.Error(), "invalid") {
			return nil, status_grpc.Errorf(codes.InvalidArgument, "%v", err)
		}
		if strings.Contains(err.Error(), "already exists") {
			return nil, status_grpc.Errorf(codes.AlreadyExists, "%v", err)
		}

		return nil, status_grpc.Errorf(codes.Internal, "failed to create mission: %v", err)
	}

	s.logger.Info("mission created successfully",
		"mission_id", result.MissionID,
		"target_id", result.TargetID,
		"workflow_id", result.WorkflowID,
	)

	// Build proto Mission response
	protoMission := &daemonpb.Mission{
		Id:         result.MissionID,
		Name:       result.Name,
		Status:     daemonpb.MissionStatus_MISSION_STATUS_PENDING,
		TargetId:   result.TargetID,
		WorkflowId: result.WorkflowID,
	}

	return &daemonpb.CreateMissionResponse{
		Success: true,
		Mission: protoMission,
		Message: fmt.Sprintf("Mission '%s' created successfully", result.Name),
	}, nil
}

// Shutdown requests graceful shutdown of the daemon.
func (s *DaemonServer) Shutdown(ctx context.Context, req *ShutdownRequest) (*ShutdownResponse, error) {
	s.logger.Info("shutdown requested via gRPC",
		"force", req.Force,
		"timeout_seconds", req.TimeoutSeconds,
	)

	// Validate this is a local daemon (not remote via GIBSON_DAEMON_ADDRESS)
	// The CLI already prevents this, but we double-check here for safety
	if remoteAddr := os.Getenv("GIBSON_DAEMON_ADDRESS"); remoteAddr != "" {
		return &ShutdownResponse{
			Success: false,
			Message: "Cannot shutdown a remote daemon via this endpoint",
		}, nil
	}

	// Request shutdown from the daemon
	timeoutSeconds := req.TimeoutSeconds
	if timeoutSeconds <= 0 {
		timeoutSeconds = 30
	}

	// Start shutdown in a goroutine so we can return the response first
	go func() {
		// Give the response time to be sent
		time.Sleep(100 * time.Millisecond)

		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSeconds)*time.Second)
		defer cancel()

		if err := s.daemon.RequestShutdown(shutdownCtx, req.Force, timeoutSeconds); err != nil {
			s.logger.Error("shutdown failed", "error", err)
		}
	}()

	return &ShutdownResponse{
		Success: true,
		Message: "Shutdown request accepted, daemon will stop shortly",
	}, nil
}

// langfuseCredentialName returns the credential name used to store Langfuse
// project credentials for a given tenant.
func langfuseCredentialName(tenantID string) string {
	return fmt.Sprintf("langfuse_project:%s", tenantID)
}

// langfuseCredentialPayload is the JSON structure stored as the encrypted
// credential value for per-tenant Langfuse project credentials.
type langfuseCredentialPayload struct {
	PublicKey string `json:"public_key"`
	SecretKey string `json:"secret_key"`
	Host      string `json:"host"`
	ProjectID string `json:"project_id"`
}

// GetTenantLangfuseCredentials retrieves the Langfuse project credentials for a tenant.
func (s *DaemonServer) GetTenantLangfuseCredentials(ctx context.Context, req *GetTenantLangfuseCredentialsRequest) (*GetTenantLangfuseCredentialsResponse, error) {
	if req.TenantId == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "tenant_id is required")
	}

	if s.credentialHandler == nil {
		return nil, status_grpc.Errorf(codes.Unavailable, "credential handler not configured")
	}

	name := langfuseCredentialName(req.TenantId)

	_, decrypted, err := s.credentialHandler.GetDecrypted(ctx, name)
	if err != nil {
		s.logger.Debug("langfuse credentials not found", "tenant_id", req.TenantId, "error", err)
		return nil, status_grpc.Errorf(codes.NotFound, "langfuse credentials not found for tenant %q", req.TenantId)
	}

	var payload langfuseCredentialPayload
	if err := json.Unmarshal([]byte(decrypted), &payload); err != nil {
		s.logger.Error("failed to unmarshal langfuse credential payload", "tenant_id", req.TenantId, "error", err)
		return nil, status_grpc.Errorf(codes.Internal, "failed to decode langfuse credentials: %v", err)
	}

	return &GetTenantLangfuseCredentialsResponse{
		PublicKey: payload.PublicKey,
		SecretKey: payload.SecretKey,
		Host:      payload.Host,
		ProjectId: payload.ProjectID,
	}, nil
}

// SetTenantLangfuseCredentials stores or updates Langfuse project credentials for a tenant.
func (s *DaemonServer) SetTenantLangfuseCredentials(ctx context.Context, req *SetTenantLangfuseCredentialsRequest) (*SetTenantLangfuseCredentialsResponse, error) {
	if req.TenantId == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "tenant_id is required")
	}

	if s.credentialHandler == nil {
		return nil, status_grpc.Errorf(codes.Unavailable, "credential handler not configured")
	}

	payload := langfuseCredentialPayload{
		PublicKey: req.PublicKey,
		SecretKey: req.SecretKey,
		Host:      req.Host,
		ProjectID: req.ProjectId,
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		s.logger.Error("failed to marshal langfuse credential payload", "tenant_id", req.TenantId, "error", err)
		return nil, status_grpc.Errorf(codes.Internal, "failed to encode langfuse credentials: %v", err)
	}

	name := langfuseCredentialName(req.TenantId)

	// Attempt update if credentials already exist; fall back to create.
	existing, err := s.credentialHandler.GetByName(ctx, name)
	if err == nil {
		// Credential exists — update it.
		apiKey := string(payloadJSON)
		_, updateErr := s.credentialHandler.Update(ctx, CredentialUpdateRequest{
			ID:     existing.ID,
			APIKey: &apiKey,
		})
		if updateErr != nil {
			s.logger.Error("failed to update langfuse credentials", "tenant_id", req.TenantId, "error", updateErr)
			return nil, status_grpc.Errorf(codes.Internal, "failed to update langfuse credentials: %v", updateErr)
		}
	} else {
		// Credential does not exist — create it.
		_, createErr := s.credentialHandler.Create(ctx, CredentialCreateRequest{
			Name:        name,
			Type:        types.CredentialTypeLangfuseProject,
			Provider:    "langfuse",
			APIKey:      string(payloadJSON),
			Description: fmt.Sprintf("Langfuse project credentials for tenant %s", req.TenantId),
		})
		if createErr != nil {
			s.logger.Error("failed to create langfuse credentials", "tenant_id", req.TenantId, "error", createErr)
			return nil, status_grpc.Errorf(codes.Internal, "failed to store langfuse credentials: %v", createErr)
		}
	}

	s.logger.Info("langfuse credentials stored", "tenant_id", req.TenantId)
	return &SetTenantLangfuseCredentialsResponse{}, nil
}

// DeleteTenantLangfuseCredentials removes the Langfuse project credentials for a tenant.
func (s *DaemonServer) DeleteTenantLangfuseCredentials(ctx context.Context, req *DeleteTenantLangfuseCredentialsRequest) (*DeleteTenantLangfuseCredentialsResponse, error) {
	if req.TenantId == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "tenant_id is required")
	}

	if s.credentialHandler == nil {
		return nil, status_grpc.Errorf(codes.Unavailable, "credential handler not configured")
	}

	name := langfuseCredentialName(req.TenantId)

	existing, err := s.credentialHandler.GetByName(ctx, name)
	if err != nil {
		s.logger.Debug("langfuse credentials not found for deletion", "tenant_id", req.TenantId, "error", err)
		return nil, status_grpc.Errorf(codes.NotFound, "langfuse credentials not found for tenant %q", req.TenantId)
	}

	if err := s.credentialHandler.Delete(ctx, existing.ID); err != nil {
		s.logger.Error("failed to delete langfuse credentials", "tenant_id", req.TenantId, "error", err)
		return nil, status_grpc.Errorf(codes.Internal, "failed to delete langfuse credentials: %v", err)
	}

	s.logger.Info("langfuse credentials deleted", "tenant_id", req.TenantId)
	return &DeleteTenantLangfuseCredentialsResponse{}, nil
}

// ---------------------------------------------------------------------------
// Tenant management RPCs
//
// NOTE: The proto-generated request/response types referenced below
// (CreateTenantRequest, TenantInfo, MemberInfo, etc.) are defined in
// daemon.proto and will be present in daemon.pb.go after `make proto` is run.
// ---------------------------------------------------------------------------

// tenantRecordToProto converts a component.TenantRecord to the proto TenantInfo
// message.  member_count is not stored on TenantRecord; callers that need an
// accurate count should populate it separately.
func tenantRecordToProto(r *component.TenantRecord) *TenantInfo {
	return &TenantInfo{
		TenantId:         r.TenantID,
		DisplayName:      r.DisplayName,
		Status:           r.Status,
		Tier:             r.Tier,
		OwnerEmail:       r.OwnerEmail,
		StripeCustomerId: r.StripeCustomerID,
		BillingAlert:     r.BillingAlert,
		Config:           r.Config,
		CreatedAt:        r.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:        r.UpdatedAt.UTC().Format(time.RFC3339),
	}
}

// CreateTenant creates a new tenant record backed by Redis.
//
// Requires the "platform-operator" role (cross-tenant operation).
// Returns codes.Unavailable when no TenantService has been wired,
// codes.AlreadyExists when the tenant_id is already taken, and
// codes.InvalidArgument when the tenant_id fails format validation.
func (s *DaemonServer) CreateTenant(ctx context.Context, req *CreateTenantRequest) (*CreateTenantResponse, error) {
	// Authorization enforced by auth.RPCAuthzInterceptor via permissions.yaml.

	if s.tenantService == nil {
		return nil, status_grpc.Errorf(codes.Unavailable, "tenant service not configured")
	}

	if req.TenantId == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "tenant_id is required")
	}

	// Merge proto fields into the config map so TenantService persists them
	// and writes reverse-lookup indices (email, Stripe).
	cfg := req.Config
	if cfg == nil {
		cfg = make(map[string]string)
	}
	if req.OwnerEmail != "" {
		cfg["owner_email"] = req.OwnerEmail
	}
	if req.Tier != "" {
		cfg["tier"] = req.Tier
	}
	if _, ok := cfg["keycloak_realm_name"]; !ok {
		cfg["keycloak_realm_name"] = req.TenantId
	}

	record, err := s.tenantService.CreateTenant(ctx, req.TenantId, req.DisplayName, cfg)
	if err != nil {
		if errors.Is(err, component.ErrTenantAlreadyExists) {
			return nil, status_grpc.Errorf(codes.AlreadyExists, "tenant %q already exists", req.TenantId)
		}
		if errors.Is(err, component.ErrInvalidTenantID) {
			return nil, status_grpc.Errorf(codes.InvalidArgument, "%v", err)
		}
		s.logger.Error("failed to create tenant", "tenant_id", req.TenantId, "error", err)
		return nil, status_grpc.Errorf(codes.Internal, "failed to create tenant: %v", err)
	}

	s.logger.Info("tenant created via RPC",
		"tenant_id", req.TenantId,
		"display_name", req.DisplayName,
	)

	return &CreateTenantResponse{
		Tenant: tenantRecordToProto(record),
	}, nil
}

// GetTenant retrieves a single tenant by ID.
//
// Callers with "platform-operator" may retrieve any tenant.
// All other authenticated callers may only retrieve their own tenant.
// Returns codes.NotFound when the tenant does not exist.
func (s *DaemonServer) GetTenant(ctx context.Context, req *GetTenantRequest) (*GetTenantResponse, error) {
	if s.tenantService == nil {
		return nil, status_grpc.Errorf(codes.Unavailable, "tenant service not configured")
	}

	if req.TenantId == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "tenant_id is required")
	}

	record, err := s.tenantService.GetTenant(ctx, req.TenantId)
	if err != nil {
		if errors.Is(err, component.ErrTenantNotFound) {
			return nil, status_grpc.Errorf(codes.NotFound, "tenant %q not found", req.TenantId)
		}
		s.logger.Error("failed to get tenant", "tenant_id", req.TenantId, "error", err)
		return nil, status_grpc.Errorf(codes.Internal, "failed to get tenant: %v", err)
	}

	return &GetTenantResponse{
		Tenant: tenantRecordToProto(record),
	}, nil
}

// ListTenants returns tenants visible to the caller.
//
// Requires the "platform-operator" role to list all tenants.
// All other authenticated callers receive only their own tenant record.
func (s *DaemonServer) ListTenants(ctx context.Context, req *ListTenantsRequest) (*ListTenantsResponse, error) {
	if s.tenantService == nil {
		return nil, status_grpc.Errorf(codes.Unavailable, "tenant service not configured")
	}

	records, err := s.tenantService.ListTenants(ctx)
	if err != nil {
		s.logger.Error("failed to list tenants", "error", err)
		return nil, status_grpc.Errorf(codes.Internal, "failed to list tenants: %v", err)
	}

	tenants := make([]*TenantInfo, 0, len(records))
	for i := range records {
		tenants = append(tenants, tenantRecordToProto(&records[i]))
	}

	return &ListTenantsResponse{
		Tenants: tenants,
	}, nil
}

// UpdateTenant applies field-level updates to an existing tenant.
//
// Requires the "platform-operator" role (cross-tenant operation).
// Non-empty fields in the request replace the corresponding stored values.
// Config entries are merged into the existing config map.
// Returns codes.NotFound when the tenant does not exist.
func (s *DaemonServer) UpdateTenant(ctx context.Context, req *UpdateTenantRequest) (*UpdateTenantResponse, error) {
	if s.tenantService == nil {
		return nil, status_grpc.Errorf(codes.Unavailable, "tenant service not configured")
	}

	if req.TenantId == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "tenant_id is required")
	}

	// Build the updates map from proto request fields.
	// TenantService.UpdateTenant merges these into the stored record.
	updates := make(map[string]string)
	if req.DisplayName != "" {
		updates["display_name"] = req.DisplayName
	}
	if req.Status != "" {
		updates["status"] = req.Status
	}
	if req.Tier != "" {
		updates["tier"] = req.Tier
	}
	for k, v := range req.Config {
		updates[k] = v
	}

	record, err := s.tenantService.UpdateTenant(ctx, req.TenantId, updates)
	if err != nil {
		if errors.Is(err, component.ErrTenantNotFound) {
			return nil, status_grpc.Errorf(codes.NotFound, "tenant %q not found", req.TenantId)
		}
		s.logger.Error("failed to update tenant", "tenant_id", req.TenantId, "error", err)
		return nil, status_grpc.Errorf(codes.Internal, "failed to update tenant: %v", err)
	}

	s.logger.Info("tenant updated via RPC", "tenant_id", req.TenantId)

	return &UpdateTenantResponse{
		Tenant: tenantRecordToProto(record),
	}, nil
}

// DeleteTenant soft-deletes a tenant by marking its status as "deleted" and
// removing it from the active tenant index.
//
// Requires the "platform-operator" role (cross-tenant operation).
// The underlying Redis meta key is retained for audit history.
// Returns codes.NotFound when the tenant does not exist.
func (s *DaemonServer) DeleteTenant(ctx context.Context, req *DeleteTenantRequest) (*DeleteTenantResponse, error) {
	// Authorization enforced by auth.RPCAuthzInterceptor via permissions.yaml.

	if s.tenantService == nil {
		return nil, status_grpc.Errorf(codes.Unavailable, "tenant service not configured")
	}

	if req.TenantId == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "tenant_id is required")
	}

	if err := s.tenantService.DeleteTenant(ctx, req.TenantId); err != nil {
		if errors.Is(err, component.ErrTenantNotFound) {
			return nil, status_grpc.Errorf(codes.NotFound, "tenant %q not found", req.TenantId)
		}
		s.logger.Error("failed to delete tenant", "tenant_id", req.TenantId, "error", err)
		return nil, status_grpc.Errorf(codes.Internal, "failed to delete tenant: %v", err)
	}

	s.logger.Info("tenant soft-deleted via RPC", "tenant_id", req.TenantId)

	return &DeleteTenantResponse{}, nil
}

// ---------------------------------------------------------------------------
// Membership / Impersonation RPCs
// ---------------------------------------------------------------------------

// ListTenantMembers returns the set of users registered in the tenant's
// Keycloak realm, along with their assigned realm roles and last session info.
//
// Callers with "platform-operator" may query any tenant. Callers with "owner"
// or "admin" may query their own tenant. Returns codes.Unavailable when no
// Keycloak client has been wired.
func (s *DaemonServer) ListTenantMembers(ctx context.Context, req *ListTenantMembersRequest) (*ListTenantMembersResponse, error) {
	if s.keycloak == nil {
		return nil, status_grpc.Error(codes.Unavailable, "keycloak client not configured")
	}

	tenantID := req.GetTenantId()
	if tenantID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id required")
	}

	// Authorization enforced by the RPCAuthzInterceptor. Tenant isolation
	// (non-cross-tenant callers may only target their own tenant) is
	// verified here as parameter validation.
	identity, ok := auth.GibsonIdentityFromContext(ctx)
	if !ok {
		return nil, status_grpc.Error(codes.Unauthenticated, "not authenticated")
	}
	if !auth.IsCrossTenantCaller(identity.Roles) && auth.TenantFromContext(ctx) != tenantID {
		return nil, status_grpc.Error(codes.PermissionDenied, "access denied: wrong tenant")
	}

	// Determine realm name from tenant record; default to tenant ID.
	realmName := tenantID
	if s.tenantService != nil {
		record, err := s.tenantService.GetTenant(ctx, tenantID)
		if err == nil && record.KeycloakRealmName != "" {
			realmName = record.KeycloakRealmName
		}
	}

	// Query Keycloak for all users in the realm.
	users, err := s.keycloak.ListUsers(ctx, realmName, keycloak.ListUsersOpts{Max: 100})
	if err != nil {
		return nil, status_grpc.Errorf(codes.Internal, "querying keycloak users: %v", err)
	}

	// Map each Keycloak user to MemberInfo, enriching with roles and last session.
	members := make([]*MemberInfo, 0, len(users))
	for _, u := range users {
		roles, _ := s.keycloak.GetUserRealmRoles(ctx, realmName, u.ID)
		roleNames := make([]string, 0, len(roles))
		for _, r := range roles {
			roleNames = append(roleNames, r.Name)
		}

		sessions, _ := s.keycloak.GetUserSessions(ctx, realmName, u.ID)
		var lastLogin string
		if len(sessions) > 0 {
			lastLogin = time.Unix(sessions[0].LastAccess/1000, 0).UTC().Format(time.RFC3339)
		}

		members = append(members, &MemberInfo{
			Subject:    u.ID,
			Email:      u.Email,
			Name:       strings.TrimSpace(u.FirstName + " " + u.LastName),
			Roles:      roleNames,
			Groups:     []string{},
			LastLogin:  lastLogin,
			LoginCount: 0,
		})
	}

	return &ListTenantMembersResponse{
		Members: members,
	}, nil
}

// ImpersonateTenant issues a short-lived context token scoped to the target
// tenant for platform-operator use.
//
// Requires the "platform-operator" role (cross-tenant god-mode operation).
// The caller's identity is extracted from the request context and written to
// the structured audit log so every impersonation event is traceable.
//
// Token generation is not yet implemented; a TODO placeholder is returned
// until the token-issuance service is wired.
func (s *DaemonServer) ImpersonateTenant(ctx context.Context, req *ImpersonateTenantRequest) (*ImpersonateTenantResponse, error) {
	// Authorization enforced by auth.RPCAuthzInterceptor via permissions.yaml.
	// This RPC requires the tenants:impersonate permission (platform-operator only).

	if req.TenantId == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "tenant_id is required")
	}

	// Extract caller identity for the audit trail.
	identity, ok := auth.GibsonIdentityFromContext(ctx)
	if !ok {
		return nil, status_grpc.Errorf(codes.Unauthenticated, "not authenticated")
	}

	// Verify the target tenant exists when TenantService is available.
	if s.tenantService != nil {
		if _, err := s.tenantService.GetTenant(ctx, req.TenantId); err != nil {
			if errors.Is(err, component.ErrTenantNotFound) {
				return nil, status_grpc.Errorf(codes.NotFound, "tenant %q not found", req.TenantId)
			}
			s.logger.Error("failed to verify target tenant for impersonation",
				"tenant_id", req.TenantId,
				"error", err,
			)
			return nil, status_grpc.Errorf(codes.Internal, "failed to verify target tenant: %v", err)
		}
	}

	s.logger.Info("tenant impersonation started",
		"admin_subject", identity.Subject,
		"admin_email", identity.Email,
		"target_tenant", req.TenantId,
	)

	// Emit audit event for every impersonation attempt regardless of outcome.
	if s.auditLogger != nil {
		_ = s.auditLogger.Log(ctx, "tenants:impersonate", "tenant", req.TenantId, map[string]any{
			"admin_subject": identity.Subject,
			"admin_email":   identity.Email,
		})
	}

	// Issue a signed impersonation token if the issuer is wired.
	if s.impersonationIssuer == nil {
		return nil, status_grpc.Errorf(codes.Unimplemented, "impersonation service not configured")
	}

	token, err := s.impersonationIssuer.IssueToken(ctx, req.TenantId)
	if err != nil {
		s.logger.Error("failed to issue impersonation token",
			"target_tenant", req.TenantId,
			"error", err,
		)
		return nil, status_grpc.Errorf(codes.Internal, "failed to issue impersonation token: %v", err)
	}

	return &ImpersonateTenantResponse{
		Token: token,
	}, nil
}

// ---------------------------------------------------------------------------
// Provisioning RPCs
// ---------------------------------------------------------------------------

// ProvisionTenant triggers full tenant provisioning (namespace, RBAC, API key).
//
// Requires the "platform-operator" role (cross-tenant operation).
// Returns codes.Unimplemented until the provisioner service has been wired.
func (s *DaemonServer) ProvisionTenant(ctx context.Context, req *ProvisionTenantRequest) (*ProvisionTenantResponse, error) {
	// Authorization enforced by auth.RPCAuthzInterceptor via permissions.yaml.
	// This RPC requires the tenants:provision permission (platform-operator or
	// the dashboard's system-ops provisioner service account).

	if req.TenantId == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "tenant_id is required")
	}

	if s.provisioner == nil {
		return nil, status_grpc.Errorf(codes.Unimplemented, "provisioner not configured")
	}

	_, apiKey, err := s.provisioner.ProvisionTenant(
		ctx,
		req.TenantId,
		req.DisplayName,
		req.Tier,
		req.OwnerEmail,
		req.StripeCustomerId,
		req.StripeSubId,
	)
	if err != nil {
		s.logger.Error("failed to provision tenant", "tenant_id", req.TenantId, "error", err)
		return nil, status_grpc.Errorf(codes.Internal, "failed to provision tenant: %v", err)
	}

	// Role policies are loaded at daemon startup from permissions.yaml by
	// the declarative-rbac-framework loader; per-tenant bootstrap is no
	// longer needed. The tenant's `g` (membership) rules are written by
	// AddMember below when the owner is recorded in the membership store.

	// Create the owner membership record so the provisioning user is immediately
	// recognised as the tenant owner. AddMember is idempotent on retry via
	// ErrAlreadyMember — we log and continue rather than failing the RPC.
	if s.membershipStore != nil && req.OwnerEmail != "" {
		// Use the Keycloak user ID from gRPC metadata if provided; fall back to
		// email as user ID for backward compat.
		ownerUserID := req.OwnerEmail
		if md, ok := grpcmeta.FromIncomingContext(ctx); ok {
			if vals := md.Get("x-owner-user-id"); len(vals) > 0 && vals[0] != "" {
				ownerUserID = vals[0]
			}
		}
		if addErr := s.membershipStore.AddMember(ctx, req.TenantId, ownerUserID, req.OwnerEmail, "owner", "provisioner"); addErr != nil {
			if !errors.Is(addErr, membership.ErrAlreadyMember) {
				slog.Warn("failed to create owner membership",
					"tenant", req.TenantId,
					"email", req.OwnerEmail,
					"user_id", ownerUserID,
					"error", addErr,
				)
			}
		}
	}

	// Fetch the freshly-created tenant record for the response.
	var tenantInfo *TenantInfo
	if s.tenantService != nil {
		if record, fetchErr := s.tenantService.GetTenant(ctx, req.TenantId); fetchErr == nil {
			tenantInfo = tenantRecordToProto(record)
		}
	}

	s.logger.Info("tenant provisioned via RPC", "tenant_id", req.TenantId)
	return &ProvisionTenantResponse{Tenant: tenantInfo, ApiKey: apiKey}, nil
}

// GetProvisioningStatus queries the provisioning progress for a tenant.
//
// Returns codes.Unimplemented until the provisioner service has been wired.
func (s *DaemonServer) GetProvisioningStatus(ctx context.Context, req *GetProvisioningStatusRequest) (*GetProvisioningStatusResponse, error) {
	if req.TenantId == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "tenant_id is required")
	}

	if s.provisioner == nil {
		return nil, status_grpc.Errorf(codes.Unimplemented, "provisioner not configured")
	}

	provStatus, steps, err := s.provisioner.GetProvisioningStatus(ctx, req.TenantId)
	if err != nil {
		s.logger.Error("failed to get provisioning status", "tenant_id", req.TenantId, "error", err)
		return nil, status_grpc.Errorf(codes.Internal, "failed to get provisioning status: %v", err)
	}

	protoSteps := make([]*ProvisionStep, 0, len(steps))
	for _, step := range steps {
		protoSteps = append(protoSteps, &ProvisionStep{
			Name:      step.Name,
			Status:    step.Status,
			Error:     step.Error,
			Timestamp: step.Timestamp,
		})
	}

	return &GetProvisioningStatusResponse{
		TenantId: req.TenantId,
		Status:   provStatus,
		Steps:    protoSteps,
	}, nil
}

// DeprovisionTenant tears down all resources associated with a tenant.
//
// Requires the "platform-operator" role (cross-tenant operation).
// Returns codes.Unimplemented until the provisioner service has been wired.
func (s *DaemonServer) DeprovisionTenant(ctx context.Context, req *DeprovisionTenantRequest) (*DeprovisionTenantResponse, error) {
	// Authorization enforced by auth.RPCAuthzInterceptor via permissions.yaml.
	// This RPC requires the tenants:deprovision permission.

	if req.TenantId == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "tenant_id is required")
	}

	if s.provisioner == nil {
		return nil, status_grpc.Errorf(codes.Unimplemented, "provisioner not configured")
	}

	if err := s.provisioner.DeprovisionTenant(ctx, req.TenantId); err != nil {
		s.logger.Error("failed to deprovision tenant", "tenant_id", req.TenantId, "error", err)
		return nil, status_grpc.Errorf(codes.Internal, "failed to deprovision tenant: %v", err)
	}

	s.logger.Info("tenant deprovisioned via RPC", "tenant_id", req.TenantId)
	return &DeprovisionTenantResponse{}, nil
}

// ---------------------------------------------------------------------------
// Billing RPCs
// ---------------------------------------------------------------------------

// UpdateTenantBilling updates billing fields (tier, Stripe IDs, billing alert)
// on a tenant record.
//
// Requires "platform-operator" for cross-tenant access or "owner" for the
// caller's own tenant.  Returns codes.Unimplemented until the billing service
// has been wired.
func (s *DaemonServer) UpdateTenantBilling(ctx context.Context, req *UpdateTenantBillingRequest) (*UpdateTenantBillingResponse, error) {
	if req.TenantId == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "tenant_id is required")
	}

	// Authorization enforced by the RPCAuthzInterceptor. Tenant isolation
	// (non-cross-tenant callers may only target their own tenant) is
	// verified here as parameter validation.
	identity, ok := auth.GibsonIdentityFromContext(ctx)
	if !ok {
		return nil, status_grpc.Error(codes.Unauthenticated, "not authenticated")
	}
	if !auth.IsCrossTenantCaller(identity.Roles) && auth.TenantFromContext(ctx) != req.TenantId {
		return nil, status_grpc.Error(codes.PermissionDenied, "access denied: wrong tenant")
	}

	if s.billingStore == nil {
		return nil, status_grpc.Errorf(codes.Unimplemented, "billing service not configured")
	}

	record, err := s.billingStore.UpdateBilling(ctx, req.TenantId, req.Tier, req.StripeCustomerId, req.StripeSubId, req.BillingAlert)
	if err != nil {
		s.logger.Error("failed to update tenant billing", "tenant_id", req.TenantId, "error", err)
		return nil, status_grpc.Errorf(codes.Internal, "failed to update tenant billing: %v", err)
	}

	s.logger.Info("tenant billing updated via RPC", "tenant_id", req.TenantId)
	return &UpdateTenantBillingResponse{Tenant: tenantRecordToProto(record)}, nil
}

// GetTenantBilling returns billing details and current usage metrics for a
// tenant.
//
// Requires "platform-operator" for cross-tenant access or "owner" for the
// caller's own tenant.  Returns codes.Unimplemented until the billing service
// has been wired.
func (s *DaemonServer) GetTenantBilling(ctx context.Context, req *GetTenantBillingRequest) (*GetTenantBillingResponse, error) {
	if req.TenantId == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "tenant_id is required")
	}

	// Authorization enforced by the RPCAuthzInterceptor. Tenant isolation
	// (non-cross-tenant callers may only target their own tenant) is
	// verified here as parameter validation.
	identity, ok := auth.GibsonIdentityFromContext(ctx)
	if !ok {
		return nil, status_grpc.Error(codes.Unauthenticated, "not authenticated")
	}
	if !auth.IsCrossTenantCaller(identity.Roles) && auth.TenantFromContext(ctx) != req.TenantId {
		return nil, status_grpc.Error(codes.PermissionDenied, "access denied: wrong tenant")
	}

	if s.billingStore == nil {
		return nil, status_grpc.Errorf(codes.Unimplemented, "billing service not configured")
	}

	tier, stripeCustomerID, billingAlert, usage, err := s.billingStore.GetBilling(ctx, req.TenantId)
	if err != nil {
		s.logger.Error("failed to get tenant billing", "tenant_id", req.TenantId, "error", err)
		return nil, status_grpc.Errorf(codes.Internal, "failed to get tenant billing: %v", err)
	}

	return &GetTenantBillingResponse{
		Tier:             tier,
		StripeCustomerId: stripeCustomerID,
		BillingAlert:     billingAlert,
		Usage: &BillingUsage{
			MissionsUsed:     usage.MissionsUsed,
			MissionsLimit:    usage.MissionsLimit,
			FindingsUsed:     usage.FindingsUsed,
			FindingsLimit:    usage.FindingsLimit,
			TeamMembers:      usage.TeamMembers,
			TeamMembersLimit: usage.TeamMembersLimit,
			ApiKeys:          usage.APIKeys,
			ApiKeysLimit:     usage.APIKeysLimit,
		},
	}, nil
}

// GetTenantByStripeCustomerId resolves a Stripe customer ID to the tenant that
// owns it, using the reverse-mapping index maintained by TenantService.
func (s *DaemonServer) GetTenantByStripeCustomerId(ctx context.Context, req *GetTenantByStripeCustomerIdRequest) (*GetTenantByStripeCustomerIdResponse, error) {
	if s.tenantService == nil {
		return nil, status_grpc.Errorf(codes.Unavailable, "tenant service not configured")
	}
	if req.StripeCustomerId == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "stripe_customer_id is required")
	}
	record, err := s.tenantService.GetTenantByStripeCustomer(ctx, req.StripeCustomerId)
	if err != nil {
		if errors.Is(err, component.ErrTenantNotFound) {
			return nil, status_grpc.Errorf(codes.NotFound, "no tenant for stripe customer %q", req.StripeCustomerId)
		}
		s.logger.Error("failed to get tenant by stripe customer", "stripe_customer_id", req.StripeCustomerId, "error", err)
		return nil, status_grpc.Errorf(codes.Internal, "failed to get tenant by stripe customer: %v", err)
	}
	return &GetTenantByStripeCustomerIdResponse{
		Tenant: tenantRecordToProto(record),
	}, nil
}

// GetTenantByEmail is no longer supported in the single-realm Keycloak model.
// The email→tenant reverse mapping has been removed; tenant resolution now
// happens via the shared "gibson" realm using the tenant_id token claim.
func (s *DaemonServer) GetTenantByEmail(_ context.Context, _ *GetTenantByEmailRequest) (*GetTenantByEmailResponse, error) {
	return nil, status_grpc.Errorf(codes.Unimplemented, "GetTenantByEmail is not supported in single-realm mode")
}

// ---------------------------------------------------------------------------
// Onboarding RPCs
// ---------------------------------------------------------------------------

// GetOnboardingState returns the current onboarding state for a tenant.
//
// Returns codes.Unimplemented until the onboarding service has been wired.
func (s *DaemonServer) GetOnboardingState(ctx context.Context, req *GetOnboardingStateRequest) (*GetOnboardingStateResponse, error) {
	if req.TenantId == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "tenant_id is required")
	}

	// TODO: Wire to the onboarding service once the concrete type is available.
	if s.onboardingStore == nil {
		return nil, status_grpc.Errorf(codes.Unimplemented, "onboarding service not configured")
	}

	currentStep, completedSteps, setupTasks, completedAt, err := s.onboardingStore.GetState(ctx, req.TenantId)
	if err != nil {
		s.logger.Error("failed to get onboarding state", "tenant_id", req.TenantId, "error", err)
		return nil, status_grpc.Errorf(codes.Internal, "failed to get onboarding state: %v", err)
	}

	return &GetOnboardingStateResponse{
		CurrentStep:    currentStep,
		CompletedSteps: completedSteps,
		SetupTasks:     setupTasks,
		CompletedAt:    completedAt,
	}, nil
}

// UpdateOnboardingState advances or modifies the onboarding state for a tenant.
//
// Returns codes.Unimplemented until the onboarding service has been wired.
func (s *DaemonServer) UpdateOnboardingState(ctx context.Context, req *UpdateOnboardingStateRequest) (*UpdateOnboardingStateResponse, error) {
	if req.TenantId == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "tenant_id is required")
	}

	// TODO: Wire to the onboarding service once the concrete type is available.
	if s.onboardingStore == nil {
		return nil, status_grpc.Errorf(codes.Unimplemented, "onboarding service not configured")
	}

	if err := s.onboardingStore.UpdateState(ctx, req.TenantId, req.CurrentStep, req.CompletedSteps, req.SetupTasks); err != nil {
		s.logger.Error("failed to update onboarding state", "tenant_id", req.TenantId, "error", err)
		return nil, status_grpc.Errorf(codes.Internal, "failed to update onboarding state: %v", err)
	}

	s.logger.Info("onboarding state updated via RPC", "tenant_id", req.TenantId)
	return &UpdateOnboardingStateResponse{}, nil
}

// ---------------------------------------------------------------------------
// Invitation RPCs
// ---------------------------------------------------------------------------

// CreateInvitation issues a new team invitation for the caller's tenant.
//
// Requires "owner" or "admin" role within the caller's own tenant, or
// "platform-operator" for cross-tenant access.
// Returns codes.Unimplemented until the invitation service has been wired.
func (s *DaemonServer) CreateInvitation(ctx context.Context, req *CreateInvitationRequest) (*CreateInvitationResponse, error) {
	// Authorization enforced by auth.RPCAuthzInterceptor via permissions.yaml.

	if req.Email == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "email is required")
	}

	// TODO: Wire to the invitation service once the concrete type is available.
	if s.invitationStore == nil {
		return nil, status_grpc.Errorf(codes.Unimplemented, "invitation service not configured")
	}

	tenantID := auth.TenantFromContext(ctx)
	token, link, err := s.invitationStore.Create(ctx, tenantID, req.Email, req.Roles, req.Message, req.ExpiresInHours)
	if err != nil {
		s.logger.Error("failed to create invitation", "tenant_id", tenantID, "email", req.Email, "error", err)
		return nil, status_grpc.Errorf(codes.Internal, "failed to create invitation: %v", err)
	}

	s.logger.Info("invitation created via RPC", "tenant_id", tenantID, "email", req.Email)
	return &CreateInvitationResponse{Token: token, InvitationLink: link}, nil
}

// AcceptInvitation redeems an invitation token and adds the caller to the
// tenant.
//
// Returns codes.Unimplemented until the invitation service has been wired.
func (s *DaemonServer) AcceptInvitation(ctx context.Context, req *AcceptInvitationRequest) (*AcceptInvitationResponse, error) {
	if req.Token == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "token is required")
	}

	// TODO: Wire to the invitation service once the concrete type is available.
	if s.invitationStore == nil {
		return nil, status_grpc.Errorf(codes.Unimplemented, "invitation service not configured")
	}

	tenantID, roles, err := s.invitationStore.Accept(ctx, req.Token, req.DisplayName)
	if err != nil {
		s.logger.Error("failed to accept invitation", "error", err)
		return nil, status_grpc.Errorf(codes.Internal, "failed to accept invitation: %v", err)
	}

	s.logger.Info("invitation accepted via RPC", "tenant_id", tenantID)
	return &AcceptInvitationResponse{TenantId: tenantID, Roles: roles}, nil
}

// ListInvitations returns all invitations for the caller's tenant.
//
// Requires "owner" or "admin" role within the caller's own tenant, or
// "platform-operator" for cross-tenant access.
// Returns codes.Unimplemented until the invitation service has been wired.
func (s *DaemonServer) ListInvitations(ctx context.Context, req *ListInvitationsRequest) (*ListInvitationsResponse, error) {
	// Authorization enforced by auth.RPCAuthzInterceptor via permissions.yaml.

	// TODO: Wire to the invitation service once the concrete type is available.
	if s.invitationStore == nil {
		return nil, status_grpc.Errorf(codes.Unimplemented, "invitation service not configured")
	}

	tenantID := auth.TenantFromContext(ctx)
	records, total, err := s.invitationStore.List(ctx, tenantID, req.Page, req.Limit)
	if err != nil {
		s.logger.Error("failed to list invitations", "tenant_id", tenantID, "error", err)
		return nil, status_grpc.Errorf(codes.Internal, "failed to list invitations: %v", err)
	}

	infos := make([]*InvitationInfo, 0, len(records))
	for _, rec := range records {
		infos = append(infos, &InvitationInfo{
			Token:     rec.Token,
			Email:     rec.Email,
			Roles:     rec.Roles,
			Status:    rec.Status,
			InvitedBy: rec.InvitedBy,
			CreatedAt: rec.CreatedAt,
			ExpiresAt: rec.ExpiresAt,
		})
	}

	return &ListInvitationsResponse{Invitations: infos, Total: total}, nil
}

// RevokeInvitation cancels a pending invitation by token.
//
// Requires "owner" or "admin" role within the caller's own tenant, or
// "platform-operator" for cross-tenant access.
// Returns codes.Unimplemented until the invitation service has been wired.
func (s *DaemonServer) RevokeInvitation(ctx context.Context, req *RevokeInvitationRequest) (*RevokeInvitationResponse, error) {
	// Authorization enforced by auth.RPCAuthzInterceptor via permissions.yaml.

	if req.Token == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "token is required")
	}

	// TODO: Wire to the invitation service once the concrete type is available.
	if s.invitationStore == nil {
		return nil, status_grpc.Errorf(codes.Unimplemented, "invitation service not configured")
	}

	tenantID := auth.TenantFromContext(ctx)
	if err := s.invitationStore.Revoke(ctx, tenantID, req.Token); err != nil {
		s.logger.Error("failed to revoke invitation", "tenant_id", tenantID, "error", err)
		return nil, status_grpc.Errorf(codes.Internal, "failed to revoke invitation: %v", err)
	}

	s.logger.Info("invitation revoked via RPC", "tenant_id", tenantID)
	return &RevokeInvitationResponse{}, nil
}

// ---------------------------------------------------------------------------
// API Key RPCs
// ---------------------------------------------------------------------------

// CreateAPIKey issues a new API key for a tenant.
//
// Requires "owner" or "admin" role within the caller's own tenant, or
// "platform-operator" for cross-tenant access.
// Returns codes.Unimplemented until the API key service has been wired.
func (s *DaemonServer) CreateAPIKey(ctx context.Context, req *CreateAPIKeyRequest) (*CreateAPIKeyResponse, error) {
	// Authorization enforced by the RPCAuthzInterceptor. Tenant isolation
	// (non-cross-tenant callers may only target their own tenant) is
	// verified here as parameter validation.
	identity, ok := auth.GibsonIdentityFromContext(ctx)
	if !ok {
		return nil, status_grpc.Error(codes.Unauthenticated, "not authenticated")
	}

	if req.TenantId == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "tenant_id is required")
	}

	// Check caller's tenant matches target tenant (unless cross-tenant capable).
	if !auth.IsCrossTenantCaller(identity.Roles) && auth.TenantFromContext(ctx) != req.TenantId {
		return nil, status_grpc.Error(codes.PermissionDenied, "access denied: wrong tenant")
	}

	// TODO: Wire to the API key service once the concrete type is available.
	if s.apiKeyStore == nil {
		return nil, status_grpc.Errorf(codes.Unimplemented, "api key service not configured")
	}

	// Extract the caller's email for the audit trail. Fall back to the subject
	// when no email claim is present (e.g. service-account tokens).
	createdBy := ""
	if identity.Email != "" {
		createdBy = identity.Email
	} else {
		createdBy = identity.Subject
	}

	keyID, rawKey, err := s.apiKeyStore.Create(ctx, req.TenantId, req.AllowedKinds, req.AllowedNames, req.Capabilities, req.Name, createdBy)
	if err != nil {
		s.logger.Error("failed to create API key", "tenant_id", req.TenantId, "error", err)
		return nil, status_grpc.Errorf(codes.Internal, "failed to create API key: %v", err)
	}

	s.logger.Info("API key created via RPC", "tenant_id", req.TenantId, "key_id", keyID, "name", req.Name, "created_by", createdBy)
	return &CreateAPIKeyResponse{KeyId: keyID, RawKey: rawKey, TenantId: req.TenantId}, nil
}

// ListAPIKeys returns API key metadata for a tenant.  The raw key value is
// never returned — only the key ID and non-sensitive metadata.
//
// Requires "owner" or "admin" role within the caller's own tenant, or
// "platform-operator" for cross-tenant access.
// Returns codes.Unimplemented until the API key service has been wired.
func (s *DaemonServer) ListAPIKeys(ctx context.Context, req *ListAPIKeysRequest) (*ListAPIKeysResponse, error) {
	if req.TenantId == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "tenant_id is required")
	}

	// Authorization enforced by the RPCAuthzInterceptor. Tenant isolation
	// (non-cross-tenant callers may only target their own tenant) is
	// verified here as parameter validation.
	identity, ok := auth.GibsonIdentityFromContext(ctx)
	if !ok {
		return nil, status_grpc.Error(codes.Unauthenticated, "not authenticated")
	}
	if !auth.IsCrossTenantCaller(identity.Roles) && auth.TenantFromContext(ctx) != req.TenantId {
		return nil, status_grpc.Error(codes.PermissionDenied, "access denied: wrong tenant")
	}

	// TODO: Wire to the API key service once the concrete type is available.
	if s.apiKeyStore == nil {
		return nil, status_grpc.Errorf(codes.Unimplemented, "api key service not configured")
	}

	records, err := s.apiKeyStore.List(ctx, req.TenantId)
	if err != nil {
		s.logger.Error("failed to list API keys", "tenant_id", req.TenantId, "error", err)
		return nil, status_grpc.Errorf(codes.Internal, "failed to list API keys: %v", err)
	}

	keys := make([]*APIKeyInfo, 0, len(records))
	for _, rec := range records {
		keys = append(keys, &APIKeyInfo{
			KeyId:        rec.KeyID,
			TenantId:     rec.TenantID,
			CreatedAt:    rec.CreatedAt,
			LastUsedAt:   rec.LastUsedAt,
			AllowedKinds: rec.AllowedKinds,
			AllowedNames: rec.AllowedNames,
			Name:         rec.Name,
			Capabilities: rec.Capabilities,
			CreatedBy:    rec.CreatedBy,
		})
	}

	return &ListAPIKeysResponse{Keys: keys}, nil
}

// RevokeAPIKey permanently revokes an API key.
//
// Requires "owner" or "admin" role within the caller's tenant, or
// "platform-operator" for cross-tenant access.
// Returns codes.Unimplemented until the API key service has been wired.
func (s *DaemonServer) RevokeAPIKey(ctx context.Context, req *RevokeAPIKeyRequest) (*RevokeAPIKeyResponse, error) {
	// Authorization enforced by auth.RPCAuthzInterceptor via permissions.yaml.

	if req.KeyId == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "key_id is required")
	}

	// TODO: Wire to the API key service once the concrete type is available.
	if s.apiKeyStore == nil {
		return nil, status_grpc.Errorf(codes.Unimplemented, "api key service not configured")
	}

	if err := s.apiKeyStore.Revoke(ctx, req.KeyId); err != nil {
		s.logger.Error("failed to revoke API key", "key_id", req.KeyId, "error", err)
		return nil, status_grpc.Errorf(codes.Internal, "failed to revoke API key: %v", err)
	}

	s.logger.Info("API key revoked via RPC", "key_id", req.KeyId)
	return &RevokeAPIKeyResponse{}, nil
}

// ---------------------------------------------------------------------------
// Membership RPCs
// ---------------------------------------------------------------------------

// AddTenantMember adds a user to a tenant with the specified role.
//
// The caller must be a member of the tenant with at least the admin role and
// may only assign roles equal to or lower in privilege than their own.
func (s *DaemonServer) AddTenantMember(ctx context.Context, req *AddTenantMemberRequest) (*AddTenantMemberResponse, error) {
	if s.membershipStore == nil {
		return nil, status_grpc.Error(codes.Unavailable, "membership service not configured")
	}

	if req.TenantId == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id is required")
	}
	if req.UserId == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "user_id is required")
	}
	if req.Role == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "role is required")
	}

	// Get caller identity.
	identity, ok := auth.GibsonIdentityFromContext(ctx)
	if !ok {
		return nil, status_grpc.Error(codes.Unauthenticated, "authentication required")
	}

	// Allow bootstrap: when a tenant has zero members, the first AddMember
	// call (owner) is permitted without an existing membership check.  This
	// is the signup path — the dashboard provisions the tenant then adds the
	// first owner before anyone is a member yet.
	members, listErr := s.membershipStore.ListTenantMembers(ctx, req.TenantId)
	isBootstrap := listErr == nil && len(members) == 0 && req.Role == "owner"

	if !isBootstrap {
		// Verify the caller is a member of the tenant with at least admin role.
		callerMember, err := s.membershipStore.GetMember(ctx, req.TenantId, identity.Subject)
		if err != nil {
			return nil, status_grpc.Errorf(codes.PermissionDenied, "not a member of tenant %s", req.TenantId)
		}

		if membership.RoleLevel(callerMember.Role) > membership.RoleLevel("admin") {
			return nil, status_grpc.Error(codes.PermissionDenied, "admin role required to manage team")
		}

		// Enforce role hierarchy: callers cannot grant a role higher than their own.
		if !membership.CanAssignRole(callerMember.Role, req.Role) {
			return nil, status_grpc.Errorf(codes.PermissionDenied, "cannot assign role %s (your role: %s)", req.Role, callerMember.Role)
		}
	}

	if err := s.membershipStore.AddMember(ctx, req.TenantId, req.UserId, req.Email, req.Role, identity.Subject); err != nil {
		if errors.Is(err, membership.ErrAlreadyMember) {
			return nil, status_grpc.Error(codes.AlreadyExists, err.Error())
		}
		if errors.Is(err, membership.ErrInvalidRole) {
			return nil, status_grpc.Error(codes.InvalidArgument, err.Error())
		}
		return nil, status_grpc.Errorf(codes.Internal, "add member: %v", err)
	}

	m, _ := s.membershipStore.GetMember(ctx, req.TenantId, req.UserId)
	return &AddTenantMemberResponse{
		Membership: membershipToProto(m),
	}, nil
}

// RemoveTenantMember removes a user from a tenant.
//
// The caller must hold at least the admin role within the tenant.
// The tenant owner cannot be removed; ownership must first be transferred.
func (s *DaemonServer) RemoveTenantMember(ctx context.Context, req *RemoveTenantMemberRequest) (*RemoveTenantMemberResponse, error) {
	if s.membershipStore == nil {
		return nil, status_grpc.Error(codes.Unavailable, "membership service not configured")
	}

	if req.TenantId == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id is required")
	}
	if req.UserId == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "user_id is required")
	}

	// Get caller identity.
	identity, ok := auth.GibsonIdentityFromContext(ctx)
	if !ok {
		return nil, status_grpc.Error(codes.Unauthenticated, "authentication required")
	}

	// Verify the caller is a member of the tenant with at least admin role.
	callerMember, err := s.membershipStore.GetMember(ctx, req.TenantId, identity.Subject)
	if err != nil {
		return nil, status_grpc.Errorf(codes.PermissionDenied, "not a member of tenant %s", req.TenantId)
	}

	if membership.RoleLevel(callerMember.Role) > membership.RoleLevel("admin") {
		return nil, status_grpc.Error(codes.PermissionDenied, "admin role required to manage team")
	}

	if err := s.membershipStore.RemoveMember(ctx, req.TenantId, req.UserId); err != nil {
		if errors.Is(err, membership.ErrMemberNotFound) {
			return nil, status_grpc.Error(codes.NotFound, err.Error())
		}
		if errors.Is(err, membership.ErrCannotRemoveOwner) {
			return nil, status_grpc.Error(codes.FailedPrecondition, err.Error())
		}
		return nil, status_grpc.Errorf(codes.Internal, "remove member: %v", err)
	}

	return &RemoveTenantMemberResponse{}, nil
}

// UpdateMemberRole changes the role of an existing tenant member.
//
// The caller must hold at least the admin role and may only assign roles equal
// to or lower in privilege than their own.
func (s *DaemonServer) UpdateMemberRole(ctx context.Context, req *UpdateMemberRoleRequest) (*UpdateMemberRoleResponse, error) {
	if s.membershipStore == nil {
		return nil, status_grpc.Error(codes.Unavailable, "membership service not configured")
	}

	if req.TenantId == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id is required")
	}
	if req.UserId == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "user_id is required")
	}
	if req.NewRole == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "new_role is required")
	}

	// Get caller identity.
	identity, ok := auth.GibsonIdentityFromContext(ctx)
	if !ok {
		return nil, status_grpc.Error(codes.Unauthenticated, "authentication required")
	}

	// Verify the caller is a member of the tenant with at least admin role.
	callerMember, err := s.membershipStore.GetMember(ctx, req.TenantId, identity.Subject)
	if err != nil {
		return nil, status_grpc.Errorf(codes.PermissionDenied, "not a member of tenant %s", req.TenantId)
	}

	if membership.RoleLevel(callerMember.Role) > membership.RoleLevel("admin") {
		return nil, status_grpc.Error(codes.PermissionDenied, "admin role required to manage team")
	}

	// Enforce role hierarchy: callers cannot grant a role higher than their own.
	if !membership.CanAssignRole(callerMember.Role, req.NewRole) {
		return nil, status_grpc.Errorf(codes.PermissionDenied, "cannot assign role %s (your role: %s)", req.NewRole, callerMember.Role)
	}

	if err := s.membershipStore.UpdateRole(ctx, req.TenantId, req.UserId, req.NewRole, identity.Subject); err != nil {
		if errors.Is(err, membership.ErrMemberNotFound) {
			return nil, status_grpc.Error(codes.NotFound, err.Error())
		}
		if errors.Is(err, membership.ErrInvalidRole) {
			return nil, status_grpc.Error(codes.InvalidArgument, err.Error())
		}
		return nil, status_grpc.Errorf(codes.Internal, "update role: %v", err)
	}

	m, _ := s.membershipStore.GetMember(ctx, req.TenantId, req.UserId)
	return &UpdateMemberRoleResponse{
		Membership: membershipToProto(m),
	}, nil
}

// ListUserTenants returns all tenants the specified user belongs to.
//
// Users may list their own tenants (identity.Subject == req.UserId).
// Platform operators may query any user.
func (s *DaemonServer) ListUserTenants(ctx context.Context, req *ListUserTenantsRequest) (*ListUserTenantsResponse, error) {
	if s.membershipStore == nil {
		return nil, status_grpc.Error(codes.Unavailable, "membership service not configured")
	}

	if req.UserId == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "user_id is required")
	}

	// Authorization enforced by the RPCAuthzInterceptor. Users may only
	// query their OWN tenant memberships unless they are cross-tenant
	// capable (platform-operator); this is parameter validation.
	identity, ok := auth.GibsonIdentityFromContext(ctx)
	if !ok {
		return nil, status_grpc.Error(codes.Unauthenticated, "authentication required")
	}
	if identity.Subject != req.UserId && !auth.IsCrossTenantCaller(identity.Roles) {
		return nil, status_grpc.Error(codes.PermissionDenied, "cannot list tenants for another user")
	}

	memberships, err := s.membershipStore.ListUserTenants(ctx, req.UserId)
	if err != nil {
		return nil, status_grpc.Errorf(codes.Internal, "list user tenants: %v", err)
	}

	infos := make([]*MembershipInfo, 0, len(memberships))
	for i := range memberships {
		infos = append(infos, membershipToProto(&memberships[i]))
	}

	return &ListUserTenantsResponse{
		Memberships: infos,
	}, nil
}

// TransferOwnership transfers tenant ownership from the caller to another
// existing member of the tenant.
//
// Only the current tenant owner may invoke this RPC.
func (s *DaemonServer) TransferOwnership(ctx context.Context, req *TransferOwnershipRequest) (*TransferOwnershipResponse, error) {
	if s.membershipStore == nil {
		return nil, status_grpc.Error(codes.Unavailable, "membership service not configured")
	}

	if req.TenantId == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id is required")
	}
	if req.NewOwnerUserId == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "new_owner_user_id is required")
	}

	// Get caller identity.
	identity, ok := auth.GibsonIdentityFromContext(ctx)
	if !ok {
		return nil, status_grpc.Error(codes.Unauthenticated, "authentication required")
	}

	// Verify the caller is the current owner.
	callerMember, err := s.membershipStore.GetMember(ctx, req.TenantId, identity.Subject)
	if err != nil {
		return nil, status_grpc.Errorf(codes.PermissionDenied, "not a member of tenant %s", req.TenantId)
	}
	if callerMember.Role != "owner" {
		return nil, status_grpc.Error(codes.PermissionDenied, "only the tenant owner can transfer ownership")
	}

	if err := s.membershipStore.TransferOwnership(ctx, req.TenantId, identity.Subject, req.NewOwnerUserId, identity.Subject); err != nil {
		if errors.Is(err, membership.ErrMemberNotFound) {
			return nil, status_grpc.Error(codes.NotFound, err.Error())
		}
		if errors.Is(err, membership.ErrNotOwner) {
			return nil, status_grpc.Error(codes.PermissionDenied, err.Error())
		}
		return nil, status_grpc.Errorf(codes.Internal, "transfer ownership: %v", err)
	}

	return &TransferOwnershipResponse{}, nil
}

// membershipToProto converts a domain Membership record to the proto MembershipInfo type.
func membershipToProto(m *membership.Membership) *MembershipInfo {
	if m == nil {
		return nil
	}
	return &MembershipInfo{
		TenantId: m.TenantID,
		UserId:   m.UserID,
		Email:    m.Email,
		Role:     m.Role,
		AddedAt:  m.AddedAt.Format(time.RFC3339),
		AddedBy:  m.AddedBy,
	}
}

// ---------------------------------------------------------------------------
// SignupTenant — authz-02-keycloak-organizations spec
// ---------------------------------------------------------------------------

// SignupTenant orchestrates the full tenant signup flow via SignupHandler.
//
// It is a thin gRPC adapter that:
//  1. Guards against a nil signupHandler (returns codes.Unavailable).
//  2. Maps proto fields to provisioner.SignupRequest.
//  3. Calls SignupHandler.Signup and maps domain errors to gRPC status codes:
//     - provisioner.ErrInvalidSignupInput → codes.InvalidArgument
//     - provisioner.ErrEmailAlreadyExists → codes.AlreadyExists
//     - provisioner.ErrConflict           → codes.AlreadyExists
//     - any other error                   → codes.Internal
//  4. Maps the provisioner.SignupResponse to proto.
//
// The caller must present a gibson-system-ops service account JWT with the
// "provisioner" realm role.  Authorization enforcement (the
// required_permissions check) is handled by the authz interceptor introduced
// in authz-03; for the duration of authz-02 the existing auth interceptor
// provides basic identity verification only.
func (s *DaemonServer) SignupTenant(ctx context.Context, req *SignupTenantRequest) (*SignupTenantResponse, error) {
	if s.signupHandler == nil {
		return nil, status_grpc.Error(codes.Unavailable,
			"signup handler not configured; authz may be disabled or Keycloak admin credentials are missing")
	}

	domainReq := provisioner.SignupRequest{
		Email:       req.GetEmail(),
		Password:    req.GetPassword(),
		CompanyName: req.GetCompanyName(),
		Plan:        req.GetPlan(),
	}

	resp, err := s.signupHandler.Signup(ctx, domainReq)
	if err != nil {
		switch {
		case errors.Is(err, provisioner.ErrInvalidSignupInput):
			return nil, status_grpc.Error(codes.InvalidArgument, err.Error())
		case errors.Is(err, provisioner.ErrEmailAlreadyExists),
			errors.Is(err, provisioner.ErrConflict):
			return nil, status_grpc.Error(codes.AlreadyExists, err.Error())
		default:
			// Internal error — include a trace ID if one is available so the
			// caller can share it with support.
			traceID := extractTraceID(ctx)
			msg := fmt.Sprintf("signup failed (trace_id=%s): %s", traceID, err.Error())
			s.logger.ErrorContext(ctx, "SignupTenant internal error",
				slog.String("trace_id", traceID),
				slog.String("error", err.Error()),
			)
			return nil, status_grpc.Error(codes.Internal, msg)
		}
	}

	return &SignupTenantResponse{
		UserId:            resp.UserID,
		TenantId:          resp.TenantID,
		OrganizationAlias: resp.OrganizationAlias,
		RedirectUrl:       resp.RedirectURL,
	}, nil
}

// extractTraceID returns the OTel trace ID from the context as a hex string,
// or "unknown" when no valid span is present.
func extractTraceID(ctx context.Context) string {
	if span := traceSpanFromContext(ctx); span != "" {
		return span
	}
	return "unknown"
}

// ---------------------------------------------------------------------------
// Task 9: GetMyPermissions — returns the caller's role, admin flag,
// component grants, and team memberships for the current tenant.
// ---------------------------------------------------------------------------

// GetMyPermissions returns a compact permission summary for the authenticated
// caller within their current tenant.  It is callable by any authenticated user
// (no admin relation required).  All FGA queries run in parallel to minimise
// latency.
func (s *DaemonServer) GetMyPermissions(ctx context.Context, req *daemonpb.GetMyPermissionsRequest) (*daemonpb.GetMyPermissionsResponse, error) {
	tenantID := req.GetTenantId()
	if tenantID == "" {
		tenantID = auth.TenantFromContext(ctx)
	}
	if tenantID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id is required (or call with a tenant-scoped JWT)")
	}

	// Resolve the caller's user ID from the auth context.
	userID := ""
	if id, ok := auth.GibsonIdentityFromContext(ctx); ok {
		userID = id.Subject
	}
	if userID == "" {
		return nil, status_grpc.Error(codes.Unauthenticated, "user identity not found in context")
	}

	if s.authorizer == nil {
		// No authorizer wired — return a minimal response with member role.
		return &daemonpb.GetMyPermissionsResponse{
			TenantId: tenantID,
			Role:     "member",
			IsAdmin:  false,
		}, nil
	}

	// Run FGA queries in parallel:
	//   1. Check admin relation on tenant
	//   2. ListObjects to discover teams the user belongs to
	//   3. List component grants (if grantHandler is available)
	type queryResult struct {
		isAdmin         bool
		teamIDs         []string
		componentGrants []provisioner.ComponentGrant
		err             error
	}

	resultCh := make(chan queryResult, 1)
	go func() {
		var qr queryResult

		// 1. Admin check.
		isAdmin, err := s.authorizer.Check(ctx,
			fmt.Sprintf("user:%s", userID),
			"admin",
			fmt.Sprintf("tenant:%s", tenantID),
		)
		if err != nil {
			s.logger.WarnContext(ctx, "GetMyPermissions: admin check failed",
				slog.String("tenant_id", tenantID),
				slog.String("user_id", userID),
				slog.String("error", err.Error()),
			)
			// Non-fatal: proceed with isAdmin=false.
		}
		qr.isAdmin = isAdmin

		// 2. Team memberships via ListObjects.
		teamIDs, err := s.authorizer.ListObjects(ctx,
			fmt.Sprintf("user:%s", userID),
			"member",
			"team",
		)
		if err != nil {
			s.logger.WarnContext(ctx, "GetMyPermissions: list team objects failed",
				slog.String("tenant_id", tenantID),
				slog.String("user_id", userID),
				slog.String("error", err.Error()),
			)
		} else {
			qr.teamIDs = teamIDs
		}

		// 3. Component grants (best-effort).
		if s.grantHandler != nil {
			grants, err := s.grantHandler.List(ctx, tenantID, userID)
			if err != nil {
				s.logger.WarnContext(ctx, "GetMyPermissions: list component grants failed",
					slog.String("tenant_id", tenantID),
					slog.String("user_id", userID),
					slog.String("error", err.Error()),
				)
			} else {
				qr.componentGrants = grants
			}
		}

		resultCh <- qr
	}()

	qr := <-resultCh

	// Determine role string.
	role := "member"
	if qr.isAdmin {
		role = "admin"
	}

	// Aggregate component grants by component_ref.
	byRef := make(map[string]*daemonpb.PermissionComponentGrant)
	for _, g := range qr.componentGrants {
		if existing, ok := byRef[g.ComponentRef]; ok {
			existing.Actions = append(existing.Actions, g.Action)
		} else {
			byRef[g.ComponentRef] = &daemonpb.PermissionComponentGrant{
				ComponentRef: g.ComponentRef,
				Actions:      []string{g.Action},
			}
		}
	}
	pgrants := make([]*daemonpb.PermissionComponentGrant, 0, len(byRef))
	for _, pg := range byRef {
		pgrants = append(pgrants, pg)
	}

	// Build team memberships — team_name is a best-effort lookup from teamHandler.
	teamMemberships := make([]*daemonpb.PermissionTeamMembership, 0, len(qr.teamIDs))
	for _, rawTeamID := range qr.teamIDs {
		// FGA returns "team:{id}" — strip the prefix.
		teamID := strings.TrimPrefix(rawTeamID, "team:")
		if teamID == "" || teamID == rawTeamID {
			continue
		}

		// Look up team name via teamHandler (best-effort).
		teamName := teamID
		if s.teamHandler != nil {
			if recs, err := s.teamHandler.List(ctx, tenantID); err == nil {
				for _, r := range recs {
					if r.TeamID == teamID {
						teamName = r.Name
						break
					}
				}
			}
		}

		// Check if user is also team admin.
		isTeamAdmin := false
		if adminCheck, err := s.authorizer.Check(ctx,
			fmt.Sprintf("user:%s", userID),
			"admin",
			fmt.Sprintf("team:%s", teamID),
		); err == nil {
			isTeamAdmin = adminCheck
		}

		teamMemberships = append(teamMemberships, &daemonpb.PermissionTeamMembership{
			TeamId:   teamID,
			TeamName: teamName,
			IsAdmin:  isTeamAdmin,
		})
	}

	return &daemonpb.GetMyPermissionsResponse{
		TenantId:        tenantID,
		Role:            role,
		IsAdmin:         qr.isAdmin,
		ComponentGrants: pgrants,
		TeamMemberships: teamMemberships,
	}, nil
}

// traceSpanFromContext extracts the trace ID string using the grpc metadata
// or OTel context.  We keep this local to avoid importing the full OTel trace
// package just for this one helper.
func traceSpanFromContext(ctx context.Context) string {
	if md, ok := grpcmeta.FromIncomingContext(ctx); ok {
		if vals := md.Get("traceparent"); len(vals) > 0 {
			// W3C traceparent format: 00-<trace-id>-<span-id>-<flags>
			parts := strings.SplitN(vals[0], "-", 4)
			if len(parts) >= 2 {
				return parts[1]
			}
		}
	}
	return ""
}
