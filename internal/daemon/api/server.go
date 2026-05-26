package api

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpcmeta "google.golang.org/grpc/metadata"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/audit"
	"github.com/zeroroot-ai/gibson/internal/authz"
	"github.com/zeroroot-ai/gibson/internal/budget"
	"github.com/zeroroot-ai/gibson/internal/capabilitygrant"
	userv1 "github.com/zeroroot-ai/gibson/internal/daemon/api/gibson/user/v1"
	"github.com/zeroroot-ai/gibson/internal/datapool"
	"github.com/zeroroot-ai/gibson/internal/finding"
	"github.com/zeroroot-ai/gibson/internal/idp"
	"github.com/zeroroot-ai/gibson/internal/impersonation"
	"github.com/zeroroot-ai/gibson/internal/llm"
	"github.com/zeroroot-ai/gibson/internal/manifest"
	"github.com/zeroroot-ai/gibson/internal/missiondraft"
	"github.com/zeroroot-ai/gibson/internal/onboarding"
	"github.com/zeroroot-ai/gibson/internal/types"
	"github.com/zeroroot-ai/gibson/pkg/version"
	modelaccesspb "github.com/zeroroot-ai/platform-sdk/gen/gibson/authz/v1"
	daemonoperatorv1 "github.com/zeroroot-ai/platform-sdk/gen/gibson/daemon/operator/v1"
	daemonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
	sdktenantv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// authzIface is the narrow subset of authz.Authorizer that the DaemonServer
// admin handlers use directly. Using an interface rather than the concrete type
// avoids importing the authz package in tests that don't care about it.
type authzIface interface {
	Check(ctx context.Context, user, relation, object string) (bool, error)
	BatchCheck(ctx context.Context, checks []authz.CheckRequest) ([]bool, error)
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
	sdktenantv1.UnimplementedTenantServiceServer
	daemonoperatorv1.UnimplementedDaemonOperatorServiceServer
	userv1.UnimplementedUserServiceServer
	modelaccesspb.UnimplementedModelAccessServiceServer

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

	// cgMinter / cgVerifier back the RenewCapabilityGrant RPC.
	// Wired via WithCGRenewal; nil-checked at handler entry.
	cgMinter   *capabilitygrant.Minter
	cgVerifier CGJWTVerifier

	// onboardingStore manages tenant onboarding state.
	// May be nil; wired when the onboarding service is available.
	// TODO: replace with concrete type once onboarding package is introduced.
	onboardingStore interface {
		GetState(ctx context.Context, tenantID string) (currentStep string, completedSteps []string, setupTasks map[string]string, completedAt string, err error)
		UpdateState(ctx context.Context, tenantID, currentStep string, completedSteps []string, setupTasks map[string]string) error
	}

	// impersonationIssuer issues short-lived impersonation tokens.
	// May be nil; wired when the impersonation service is available.
	// TODO: replace with concrete type once impersonation package is introduced.
	impersonationIssuer interface {
		IssueToken(ctx context.Context, tenantID string) (token string, err error)
	}

	// authorizer is the FGA Authorizer used by admin handlers that need direct FGA access.
	// May be nil; when nil, RPCs that require it return codes.Unavailable.
	authorizer authzIface

	// tenantNameResolver looks up a tenant's friendly display name. Wired by
	// the daemon bootstrap to read the operator-published Redis cache via
	// `core/gibson/internal/state.GetTenantName`. May be nil; when nil, the
	// ListMyMemberships handler falls back to the tenant ID as the name.
	// Returning ("", false, nil) is a cache miss — also handled as fallback.
	tenantNameResolver func(ctx context.Context, tenantID string) (string, bool, error)

	// platformDB is the shared-dashboard Postgres pool used by the
	// entitlements handlers (UpsertTenantQuota in particular). Wired via
	// WithPlatformDB by the daemon; nil in dev/kind when the Postgres
	// connection couldn't be established.
	platformDB *sql.DB

	// auditLogger is the Redis-backed audit log reader/writer.
	// May be nil; when nil, ListAuditEvents falls back to Loki only (or returns Unavailable).
	auditLogger *audit.AuditLogger

	// lokiQuerier is the Loki HTTP query client for audit events.
	// May be nil; when nil, ListAuditEvents falls back to the Redis audit stream.
	lokiQuerier audit.LokiQuerier

	// missionDraftStore persists mission YAML drafts per tenant.
	// May be nil; when nil, SaveMissionDraft/ListMissionDrafts return codes.Unavailable.
	missionDraftStore missionDraftStoreIface

	// findingStore provides access to findings for export operations.
	// May be nil; when nil, ExportFindings returns codes.Unavailable.
	// Added by prod-unimplemented-apis spec.
	findingStore findingStoreIface

	// poolGetter returns the live per-tenant data-plane pool.
	// Used by ExportFindings (Neo4j Cypher path).
	// May be nil; when nil those RPCs return codes.Unavailable.
	// Wired by the daemon via WithPoolGetter. Spec: dashboard-neo4j-crud-removal.
	poolGetter func() datapool.Pool

	// quotaStore + tenantUsage fields removed by spec
	// plans-and-quotas-simplification: quota limits are read from Postgres
	// directly by GetTenantQuota; live counters via the QuotaManager.

	// alertStore persists and retrieves per-user platform alerts.
	// May be nil; when nil, ListAlerts/MarkAlertRead return codes.Unavailable.
	// Added by prod-feature-wiring spec.
	alertStore alertStoreIface

	// conversationStore persists and retrieves chat conversation history.
	// May be nil; when nil, ListConversations/GetConversation return codes.Unavailable.
	// Added by prod-feature-wiring spec.
	conversationStore conversationStoreIface

	// capabilityGrantService handles the Agent Auth Protocol gRPC RPCs.
	// May be nil; when nil, Agent Auth RPCs return codes.Unavailable.
	// Added by agent-auth-fga-integration spec.
	capabilityGrantService *capabilitygrant.CapabilityGrantService

	// manifestBuilder builds signed capability manifests for GetCapabilityManifest.
	// May be nil; when nil, GetCapabilityManifest returns codes.Unavailable.
	// Added by capability-manifest-rpc spec.
	manifestBuilder manifest.Builder

	// manifestWatchHub multiplexes a single Redis psubscribe across all
	// connected WatchManifestInvalidations streams. May be nil; when nil,
	// that RPC returns codes.Unavailable.
	manifestWatchHub *manifest.WatchHub

	// providerConfig is the encrypted provider-config store (spec 25).
	// May be nil; when nil, all provider CRUD RPCs return codes.FailedPrecondition
	// with a message pointing at security.key_provider.
	providerConfig providerConfigStoreIface

	// execLimiter enforces per-(tenant, RPC) request rates for ExecuteLLM,
	// StreamLLM, and TestProvider. May be nil; when nil rate limiting is skipped.
	// Added by spec 25-daemon-driven-provider-config task 4.
	execLimiter execLimiterIface

	// providerFactory constructs an llm.LLMProvider from a resolved ProviderConfig.
	// Defaults to the package-level providerFactoryFunc; overridden in tests via
	// WithProviderFactory. Must never be nil after NewDaemonServer.
	// Added by spec 25-daemon-driven-provider-config task 4.
	providerFactory func(cfg llm.ProviderConfig) (llm.LLMProvider, error)

	// budgetEnforcer enforces per-user/team/tenant token and spend
	// budgets around ExecuteLLM / StreamLLM. May be nil; when nil budget
	// enforcement is skipped (absent-budget = unlimited, so this
	// degrades to today's behavior).
	// Spec: llm-user-attribution-governance (Requirement 3).
	budgetEnforcer budgetEnforcerIface

	// modelGateInvalidator is called from Grant/Revoke so that the
	// next slot resolution picks up the new grant state within
	// milliseconds (bypassing the filter's 30s TTL). May be nil; when
	// nil, grant/revoke still persist but callers may see up to 30s of
	// stale enforcement.
	// Spec: llm-user-attribution-governance (Requirement 4.6).
	modelGateInvalidator modelGateInvalidator

	// auditQuery backs ListModelResolutionEvents. May be nil; when nil
	// the RPC returns an empty response rather than Unimplemented.
	// Spec: llm-user-attribution-governance (Requirement 4.9).
	auditQuery auditQueryIface

	// idpAdminClient is the vendor-neutral IdP admin interface used by
	// TenantAdminService agent-identity RPCs. May be nil; when nil the
	// agent-identity RPCs return codes.Unavailable.
	// Spec: agent-service-credentials.
	idpAdminClient idp.AdminClient

	// tenantAdminAuditWriter is the Postgres-backed audit event writer for
	// TenantAdminService operations. May be nil; when nil audit events are
	// silently dropped (not a fatal error — the operation still succeeds).
	// Spec: agent-service-credentials.
	tenantAdminAuditWriter auditWriterIface

	// gibsonPublicURL is the public Envoy URL returned in CreateAgentIdentity
	// responses as the gibson_url and in the enroll_command field.
	// Populated from GIBSON_PUBLIC_URL env var at server construction time.
	gibsonPublicURL string
}

// auditWriterIface is the narrow surface TenantAdminService uses from
// audit.Writer. Using an interface allows tests to inject a no-op.
type auditWriterIface interface {
	Log(event audit.Event)
}

// budgetEnforcerIface is the narrow surface ExecuteLLM / StreamLLM use
// from internal/budget.Enforcer. Interfaced here so tests can inject a
// mock without spinning up Redis. Spec: llm-user-attribution-governance.
type budgetEnforcerIface interface {
	Check(ctx context.Context, estimatedTokens int64) (*budget.Status, error)
	Record(ctx context.Context, actualTokens int64, actualCostUSDCents int64) error
}

// modelGateInvalidator is the narrow cache-invalidation hook the
// ModelAccessService handlers call after Grant / Revoke so the next
// call reflects the new state within milliseconds rather than waiting
// for the modelgate 30s TTL. Implemented by *modelgate.fgaFilter.
type modelGateInvalidator interface {
	InvalidateCache()
}

// auditQueryIface is the narrow read surface ListModelResolutionEvents
// uses from audit.Query. Pluggable so tests can return deterministic
// data without spinning up Postgres.
type auditQueryIface interface {
	List(ctx context.Context, tenantID string, filters audit.Filters, limit, offset int) ([]audit.PgEntry, int, error)
}

// missionDraftStoreIface is the narrow interface the DaemonServer uses for
// mission draft persistence. Using an interface allows tests to inject a
// mock without spinning up Redis.
type missionDraftStoreIface interface {
	Save(ctx context.Context, tenantID, name, yaml, draftID string) (string, error)
	List(ctx context.Context, tenantID string) ([]*missiondraft.MissionDraft, error)
	Get(ctx context.Context, tenantID, draftID string) (*missiondraft.MissionDraft, error)
	Delete(ctx context.Context, tenantID, draftID string) error
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
//
// Memory enforcement (CheckMemoryQuota) was removed by spec
// plans-and-quotas-simplification — only concurrent_missions and
// concurrent_agents are enforced going forward.
type MissionQuotaChecker interface {
	// CheckMissionQuota returns a codes.ResourceExhausted error when the tenant
	// in ctx has met or exceeded its configured concurrent_missions limit.
	CheckMissionQuota(ctx context.Context) error

	// CheckAgentQuota returns a codes.ResourceExhausted error when the tenant
	// in ctx has met or exceeded its configured concurrent_agents limit
	// (counted only while bound to an in-flight task — idle agents do not
	// count).
	CheckAgentQuota(ctx context.Context) error

	// IncrementMissionCount increments the active-mission counter for the
	// tenant in ctx. Called when a mission transitions queued → running.
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

	// RunMission starts a mission by reference and returns an event channel.
	// The mission definition must already be registered via CreateMissionDefinition
	// and the target must already be registered — inline construction is no longer
	// supported.
	RunMission(ctx context.Context, missionDefinitionID string, targetID string, variables map[string]string, memoryContinuity string) (<-chan MissionEventData, error)

	// StopMission stops a running mission
	StopMission(ctx context.Context, missionID string, force bool) error

	// ListMissions returns mission list
	ListMissions(ctx context.Context, activeOnly bool, statusFilter, namePattern string, limit, offset int) ([]MissionData, int, error)

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

	// GetMissionCheckpointPayload returns the rich, per-super-step
	// payload for a single checkpoint — the decrypted working memory,
	// mission memory, DAG steps, findings, and parallel-group state.
	// Implementations that lack the per-super-step store fall back to
	// the legacy mission.MissionCheckpoint metadata view. The returned
	// CheckpointData's heavy fields may be nil/empty on the fallback
	// path; the mission handlers degrade gracefully in that case.
	//
	// Spec: mission-checkpointing R14.1-R14.3.
	GetMissionCheckpointPayload(ctx context.Context, missionID, checkpointID string) (*CheckpointData, error)

	// RewindMission rewinds a mission's state to the named target
	// checkpoint, cancelling any in-flight tools per their declared
	// idempotency runtime, dropping any super-steps newer than the
	// target, and writing a CHECKPOINT_SOURCE_MANUAL marker checkpoint.
	// Returns the ID of the marker checkpoint on success.
	//
	// Spec: mission-checkpointing R16.4 (rewind core).
	RewindMission(ctx context.Context, missionID, targetCheckpointID string) (markerCheckpointID string, err error)

	// BuildComponent rebuilds a component from source
	BuildComponent(ctx context.Context, kind string, name string) (BuildComponentResult, error)

	// ShowComponent returns detailed information about a component
	ShowComponent(ctx context.Context, kind string, name string) (ComponentInfoInternal, error)

	// GetComponentLogs streams log entries for a component
	GetComponentLogs(ctx context.Context, kind string, name string, follow bool, lines int) (<-chan LogEntryData, error)

	// ListMissionDefinitions returns all installed mission definitions
	ListMissionDefinitions(ctx context.Context, limit int, offset int) ([]MissionDefinitionData, int, error)

	// GetMissionDefinition returns the full structured proto for a single installed
	// mission definition by name. Returns nil, ErrNotFound when the name is not registered.
	GetMissionDefinition(ctx context.Context, name string) (*missionpb.MissionDefinition, error)

	// CreateMission creates a new mission by reference (target_id + mission_definition_id).
	// Inline target / inline mission are not supported.
	CreateMission(ctx context.Context, req CreateMissionData) (CreateMissionResultData, error)

	// CreateMissionDefinition registers a structured mission definition.
	CreateMissionDefinition(ctx context.Context, req CreateMissionDefinitionData) (CreateMissionDefinitionResultData, error)

	// RequestShutdown requests graceful shutdown of the daemon
	RequestShutdown(ctx context.Context, force bool, timeoutSeconds int32) error

	// RefreshToolCatalog signals the catalog refresher to immediately
	// poll runner images. Returns (queued, message, error): queued is
	// true if the signal was accepted by this replica's refresher;
	// false if the refresher is not running on this replica.
	RefreshToolCatalog(ctx context.Context) (queued bool, message string, err error)
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
	ID                  string
	TenantID            string
	Name                string
	Description         string
	MissionDefinitionID string
	TargetID            string
	Status              string
	StartTime           time.Time
	EndTime             time.Time
	FindingCount        int32
	Progress            float64
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
	Payload   map[string]interface{} // Additional payload data (mission_name, duration, status, etc.)
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
//
// The heavy fields below (WorkingMemory, MissionMemory, DagSteps,
// FindingSnapshots, ParallelGroups, InFlightIdempotency, SizeBytes,
// Source) are populated by the per-super-step payload exposure path
// (Spec 4 Phase 2A — `ThreadedCheckpointer.OnSuperStepComplete`). The
// legacy `daemonImpl.GetMissionCheckpoints` returns only the metadata
// fields; the richer fields are zero in that case. The mission
// handlers' `GetCheckpoint` and `DiffCheckpoints` opt into the rich
// payload via `GetMissionCheckpointPayload` (see DaemonInterface).
//
// Spec: mission-checkpointing R13.1, R14.1, R15.1.
type CheckpointData struct {
	CheckpointID   string
	CreatedAt      int64
	CompletedNodes int
	TotalNodes     int
	FindingsCount  int
	Version        int

	// SizeBytes is the on-wire byte size of the persisted checkpoint
	// (post-encryption + compression). Zero on the metadata-only path.
	SizeBytes int64

	// Source maps to daemonpb.CheckpointSource. Empty string falls back
	// to CHECKPOINT_SOURCE_SUPER_STEP at proto-shape time.
	// Valid: super_step / approval_gate / graceful_shutdown /
	// parallel_group / manual.
	Source string

	// ParallelGroupID, when non-empty, indicates this checkpoint was
	// captured at a parallel-group barrier.
	ParallelGroupID string

	// InFlightIdempotency surfaces the idempotency mode of any tool
	// whose call was mid-flight at checkpoint time. Empty when no tool
	// was in flight. Valid:
	//   "AT_MOST_ONCE" / "AT_LEAST_ONCE" / "EXACTLY_ONCE"
	InFlightIdempotency string

	// InFlightNodeID is the node ID of the in-flight tool at checkpoint
	// time, or empty if none was in flight.
	InFlightNodeID string

	// ResumptionToken is the EXACTLY_ONCE handshake token written by the
	// tool at its last side-effecting step. Empty for AT_MOST_ONCE /
	// AT_LEAST_ONCE.
	ResumptionToken string

	// WorkingMemory is the decrypted opaque bytes from per-super-step
	// storage. Nil on the metadata-only path.
	WorkingMemory []byte

	// MissionMemory is the decrypted opaque bytes from per-super-step
	// storage. Nil on the metadata-only path.
	MissionMemory []byte

	// DagSteps captures one snapshot row per node at checkpoint time.
	// Nil on the metadata-only path.
	DagSteps []DagStepData

	// FindingSnapshots captures the per-finding slice of the checkpoint.
	// Nil on the metadata-only path.
	FindingSnapshots []FindingSnapshotData

	// ParallelGroups maps group ID → state at checkpoint time. Nil on
	// the metadata-only path.
	ParallelGroups map[string]ParallelGroupStateData
}

// DagStepData is a single DAG node's snapshot at checkpoint time. The
// inputs and outputs are opaque, agent-defined byte payloads.
type DagStepData struct {
	NodeID         string
	State          string
	StartedAtUnix  int64
	FinishedAtUnix int64
	Inputs         []byte
	Outputs        []byte
	RetryCount     int32
	Error          string
}

// FindingSnapshotData is the per-finding row at checkpoint time.
// Payload is the taxonomy-canonical Finding bytes.
type FindingSnapshotData struct {
	FindingID string
	Severity  string
	Title     string
	NodeID    string
	Payload   []byte
}

// ParallelGroupStateData captures the state of a parallel-group barrier.
type ParallelGroupStateData struct {
	GroupID          string
	Expected         int32
	Completed        int32
	CompletedNodeIDs []string
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

// CreateMissionData represents the data for creating a new mission.
// Inline target / inline mission / YAML paths were removed under spec
// mission-api-only-cleanup — missions now reference a registered target and
// mission definition by ID only.
type CreateMissionData struct {
	Name                string
	Description         string
	TargetID            string
	MissionDefinitionID string
	Variables           map[string]string
	MemoryContinuity    string
	Metadata            map[string]string
}

// CreateMissionResultData represents the result of creating a mission.
type CreateMissionResultData struct {
	MissionID           string
	TargetID            string
	MissionDefinitionID string
	Name                string
	Description         string
	Status              string
	CreatedAt           time.Time
}

// CreateMissionDefinitionData represents the data for registering a mission
// definition with the daemon. The Definition is a fully-formed value; it is
// validated and persisted by the handler.
type CreateMissionDefinitionData struct {
	Definition *missionpb.MissionDefinition
}

// CreateMissionDefinitionResultData represents the result of registering a
// mission definition.
type CreateMissionDefinitionResultData struct {
	MissionDefinitionID string
	Info                MissionDefinitionData
}

// ProvisioningStep describes a single step in the tenant provisioning pipeline.
// Used by the provisional provisioner interface until the concrete type is wired.
type ProvisioningStep struct {
	Name      string
	Status    string
	Error     string
	Timestamp string
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
		providerFactory:   providerFactoryFunc,
		gibsonPublicURL:   os.Getenv("GIBSON_PUBLIC_URL"),
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

// WithCapabilityGrantService wires the CapabilityGrantService so that the Agent Auth
// Protocol RPCs are backed by Postgres storage and FGA authorization.
// Added by agent-auth-fga-integration spec.
func (s *DaemonServer) WithCapabilityGrantService(svc *capabilitygrant.CapabilityGrantService) *DaemonServer {
	s.capabilityGrantService = svc
	return s
}

// WithAuthorizer wires an FGA Authorizer for admin handlers that need direct
// FGA access (e.g. GetMyPermissions).
func (s *DaemonServer) WithAuthorizer(az authzIface) *DaemonServer {
	s.authorizer = az
	return s
}

// WithTenantNameResolver wires the tenant display-name lookup used by the
// ListMyMemberships handler. The daemon bootstrap supplies a closure that
// reads the operator-published cache (`tenant:name:<id>`) via
// `core/gibson/internal/state.GetTenantName`. When unset, ListMyMemberships
// returns the tenant ID as the name (still functional, just less friendly).
func (s *DaemonServer) WithTenantNameResolver(fn func(ctx context.Context, tenantID string) (string, bool, error)) *DaemonServer {
	s.tenantNameResolver = fn
	return s
}

// WithPlatformDB wires the shared-dashboard Postgres pool used by the
// entitlements handlers (UpsertTenantQuota writes the tenant_quotas row
// there). May be nil; handlers that require it return Unavailable.
func (s *DaemonServer) WithPlatformDB(db *sql.DB) *DaemonServer {
	s.platformDB = db
	return s
}

// WithPoolGetter wires the per-tenant data-plane pool getter.
// Required by ExportFindings (Neo4j DashboardQueries path) and
// GetMissionSourceYAML. When nil those RPCs return codes.Unavailable.
// Spec: dashboard-neo4j-crud-removal.
func (s *DaemonServer) WithPoolGetter(getter func() datapool.Pool) *DaemonServer {
	s.poolGetter = getter
	return s
}

// WithProviderConfigStore wires the encrypted provider-config store for the
// spec-25 CRUD and execution RPCs. When nil, provider CRUD RPCs return
// codes.FailedPrecondition pointing at security.key_provider.
// Added by spec 25-daemon-driven-provider-config.
func (s *DaemonServer) WithProviderConfigStore(store providerConfigStoreIface) *DaemonServer {
	s.providerConfig = store
	return s
}

// WithIdPAdminClient wires the vendor-neutral IdP admin client into the server.
// When set, TenantAdminService agent-identity RPCs (CreateAgentIdentity,
// ListAgentIdentities, RevokeAgentIdentity) are available. When nil, those
// RPCs return codes.Unavailable with a clear message directing the operator
// to set GIBSON_IDP_PROVIDER and related env vars.
// Spec: agent-service-credentials.
func (s *DaemonServer) WithIdPAdminClient(c idp.AdminClient) *DaemonServer {
	s.idpAdminClient = c
	return s
}

// WithTenantAdminAuditWriter wires an audit writer for TenantAdminService
// operations. When nil, audit events are silently dropped but operations
// still succeed (non-fatal degradation). Spec: agent-service-credentials.
func (s *DaemonServer) WithTenantAdminAuditWriter(w auditWriterIface) *DaemonServer {
	s.tenantAdminAuditWriter = w
	return s
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

// preserveStatus returns the error unchanged if it already carries a gRPC
// status code (e.g. codes.FailedPrecondition from datapool.MapPoolError),
// otherwise wraps it as codes.Internal with the given message prefix.
//
// This prevents double-wrapping: daemon layer methods (list_missions.go,
// grpc.go) call datapool.MapPoolError and return a FailedPrecondition status;
// without this helper the server.go handlers would re-wrap that status as
// codes.Internal, causing the dashboard to receive a 500 instead of a 412.
// Spec: per-tenant-data-plane-completion Req 8.1–8.3.
func preserveStatus(err error, internalMsg string) error {
	if _, ok := status_grpc.FromError(err); ok {
		// err already has a gRPC status code — preserve it.
		return err
	}
	return status_grpc.Errorf(codes.Internal, "%s: %v", internalMsg, err)
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

// RunMission starts a mission by reference and streams execution events.
// Both mission_definition_id and target_id are required; inline construction
// and YAML paths were removed under spec mission-api-only-cleanup.
func (s *DaemonServer) RunMission(req *daemonpb.RunMissionRequest, stream grpc.ServerStreamingServer[daemonpb.RunMissionResponse]) error {
	s.logger.Info("mission run request received",
		"mission_definition_id", req.MissionDefinitionId,
		"target_id", req.TargetId,
		"memory_continuity", req.MemoryContinuity,
	)

	if req.MissionDefinitionId == "" {
		return status_grpc.Errorf(codes.InvalidArgument, "mission_definition_id is required")
	}
	if req.TargetId == "" {
		return status_grpc.Errorf(codes.InvalidArgument, "target_id is required")
	}

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
		// Memory-quota enforcement was removed by spec
		// plans-and-quotas-simplification (it was unenforced and the Redis
		// key family was dead). Future memory checks ship in their own spec.
	}

	// Start mission and get event channel
	eventChan, err := s.daemon.RunMission(stream.Context(), req.MissionDefinitionId, req.TargetId, req.Variables, req.MemoryContinuity)
	if err != nil {
		s.logger.Error("failed to start mission", "error", err)
		return preserveStatus(err, "failed to start mission")
	}

	// Spec plans-and-quotas-simplification: the concurrent_missions counter
	// is now incremented by the missionManager at queued → running dispatch
	// (mission_manager.go) and decremented at terminal-state transitions.
	// Submission alone no longer counts toward the quota.

	// Stream events to client
	for {
		select {
		case <-stream.Context().Done():
			s.logger.Info("mission stream cancelled",
				"mission_definition_id", req.MissionDefinitionId,
				"target_id", req.TargetId,
			)
			return stream.Context().Err()

		case event, ok := <-eventChan:
			if !ok {
				// Event channel closed, mission completed
				s.logger.Info("mission completed",
					"mission_definition_id", req.MissionDefinitionId,
					"target_id", req.TargetId,
				)
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
	tenant := auth.TenantStringFromContext(ctx)

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
		return nil, preserveStatus(err, "failed to list missions")
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
			Id:                  m.ID,
			Name:                m.Name,
			Description:         m.Description,
			MissionDefinitionId: m.MissionDefinitionID,
			TargetId:            m.TargetID,
			Status:              m.Status,
			StartTime:           m.StartTime.Unix(),
			EndTime:             m.EndTime.Unix(),
			FindingCount:        m.FindingCount,
			Progress:            m.Progress,
		}
	}

	return &daemonpb.ListMissionsResponse{
		Missions: protoMissions,
		Total:    int32(total),
	}, nil
}

// ListAgents returns all registered agents from the component registry.
//
// Authorization is enforced by the FGA interceptor at the Envoy layer.
// The daemon trusts signed identity headers and returns the full agent list
// for the caller's tenant; fine-grained capability filtering has moved to
// ext_authz.
func (s *DaemonServer) ListAgents(ctx context.Context, req *daemonpb.ListAgentsRequest) (*daemonpb.ListAgentsResponse, error) {
	s.logger.Debug("agent list request received", "kind", req.Kind)

	agents, err := s.daemon.ListAgents(ctx, req.Kind)
	if err != nil {
		s.logger.Error("failed to list agents", "error", err)
		return nil, status_grpc.Errorf(codes.Internal, "failed to list agents: %v", err)
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

// ListTools returns all registered tools from the component registry.
//
// Authorization is enforced by the FGA interceptor at the Envoy layer.
// Capability-based filtering has moved to ext_authz; the daemon returns
// the full tool list for the caller's tenant.
func (s *DaemonServer) ListTools(ctx context.Context, req *daemonpb.ListToolsRequest) (*daemonpb.ListToolsResponse, error) {
	s.logger.Debug("tool list request received")

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

// ListPlugins returns all registered plugins from the component registry.
//
// Authorization is enforced by the FGA interceptor at the Envoy layer.
// Capability-based filtering has moved to ext_authz; the daemon returns
// the full plugin list for the caller's tenant.
func (s *DaemonServer) ListPlugins(ctx context.Context, req *daemonpb.ListPluginsRequest) (*daemonpb.ListPluginsResponse, error) {
	s.logger.Debug("plugin list request received")

	plugins, err := s.daemon.ListPlugins(ctx)
	if err != nil {
		s.logger.Error("failed to list plugins", "error", err)
		return nil, status_grpc.Errorf(codes.Internal, "failed to list plugins: %v", err)
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
//
// target_checkpoint_id (proto field 3) optionally requests rewind-and-resume:
// when non-empty, the daemon discards work past the named checkpoint and
// resumes from that point. When empty, behaviour is the legacy resume-from-
// latest path. Spec: mission-checkpointing R16.
func (s *DaemonServer) ResumeMission(req *daemonpb.ResumeMissionRequest, stream grpc.ServerStreamingServer[daemonpb.ResumeMissionResponse]) error {
	s.logger.Info("mission resume request received",
		"mission_id", req.MissionId,
		"checkpoint_id", req.CheckpointId,
		"target_checkpoint_id", req.TargetCheckpointId,
	)

	// Validate mission ID
	if req.MissionId == "" {
		return status_grpc.Errorf(codes.InvalidArgument, "mission ID is required")
	}

	// Rewind path: when target_checkpoint_id is set, this is a rewind-and-
	// resume request, which requires admin (not viewer) per R16.3.
	if req.TargetCheckpointId != "" {
		if err := s.requireMissionAdminForRewind(stream.Context(), req.MissionId); err != nil {
			return err
		}
		// Resolve the latest checkpoint as `from_checkpoint_id` BEFORE
		// the rewind mutates state. R16.6 audit envelope wants both
		// from_id and to_id.
		fromCheckpointID := s.resolveLatestCheckpointID(stream.Context(), req.MissionId)

		// Drive the orchestrator-side rewind core: validate the target,
		// dispatch in-flight tools per their idempotency contract,
		// write the marker checkpoint. The daemon's RewindMission
		// returns the marker checkpoint ID on success.
		markerID, rewindErr := s.daemon.RewindMission(stream.Context(), req.MissionId, req.TargetCheckpointId)
		if rewindErr != nil {
			s.logger.Warn("mission rewind failed",
				"mission_id", req.MissionId,
				"target_checkpoint_id", req.TargetCheckpointId,
				"error", rewindErr,
			)
			if strings.Contains(rewindErr.Error(), "not found") {
				return status_grpc.Errorf(codes.NotFound,
					"target checkpoint %s not found for mission %s",
					req.TargetCheckpointId, req.MissionId)
			}
			return preserveStatus(rewindErr, "rewind failed")
		}
		s.logger.Info("mission rewind completed",
			"mission_id", req.MissionId,
			"target_checkpoint_id", req.TargetCheckpointId,
			"marker_checkpoint_id", markerID,
			"from_checkpoint_id", fromCheckpointID,
		)
		// Audit emission per R16.6.
		s.emitRewindCompletedAudit(stream.Context(), req.MissionId, fromCheckpointID, req.TargetCheckpointId)

		// Apply the orchestrator-side idempotency dispatch decision for
		// any in-flight tool captured at the target checkpoint. The
		// dispatcher emits per-tool audit hints; failures (EXACTLY_ONCE
		// without resumption_token) abort the rewind early.
		if err := s.applyRewindIdempotency(stream.Context(), req.MissionId, req.TargetCheckpointId); err != nil {
			return err
		}
	}

	// Build CheckpointMetadata up-front from the latest available
	// checkpoint (or the targeted one) so we can attach it to the first
	// streamed response event. R9.2 + R9.3.
	checkpointMetadata := s.buildResumeCheckpointMetadata(stream.Context(), req.MissionId, req.TargetCheckpointId)

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
	firstEvent := true
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

			// Attach checkpoint_metadata on the first emitted event so the
			// dashboard's "Resumed from <checkpoint>" badge can render
			// without a follow-up RPC. R9.2.
			if firstEvent {
				protoEvent.CheckpointMetadata = checkpointMetadata
				firstEvent = false
			}

			// Send event to client
			if err := stream.Send(protoEvent); err != nil {
				s.logger.Error("failed to send mission event", "error", err)
				return status_grpc.Errorf(codes.Internal, "failed to send event: %v", err)
			}
		}
	}
}

// buildResumeCheckpointMetadata constructs the CheckpointMetadata block
// attached to the first event of a ResumeMission response. Returns nil
// when there is no checkpoint to surface (from-scratch resume or
// metadata lookup error). Spec: mission-checkpointing R9.2.
func (s *DaemonServer) buildResumeCheckpointMetadata(ctx context.Context, missionID, targetCheckpointID string) *daemonpb.CheckpointMetadata {
	checkpoints, err := s.daemon.GetMissionCheckpoints(ctx, missionID)
	if err != nil || len(checkpoints) == 0 {
		return nil
	}

	// Prefer the explicitly targeted checkpoint; otherwise fall back to
	// the first (most recent) entry returned by the backend.
	chosen := checkpoints[0]
	if targetCheckpointID != "" {
		for _, cp := range checkpoints {
			if cp.CheckpointID == targetCheckpointID {
				chosen = cp
				break
			}
		}
	}

	cadence := "super_step"
	if targetCheckpointID != "" {
		cadence = "manual_rewind"
	}
	return &daemonpb.CheckpointMetadata{
		CheckpointId:       chosen.CheckpointID,
		SavedAtUnixSeconds: chosen.CreatedAt,
		SuperStepNumber:    int32(chosen.Version),
		CadenceReason:      cadence,
	}
}

// requireMissionAdminForRewind enforces mission-scoped admin FGA via
// `mission#admin`, which cascades from `tenant#admin` per the OpenFGA
// model relation `define admin: [user] or admin from belongs_to` (see
// internal/authz/model.fga `type mission`). Tenant admins can rewind any
// mission in their tenant; per-mission admins (e.g. shared with a
// specific user) layer on top via `(user:<sub>, admin, mission:<id>)`.
// When the FGA Authorizer is not wired (kind dev), the per-tenant Pool's
// tenant-id scoping is the implicit guard.
//
// Spec: mission-checkpointing R16.3, R17.8.
func (s *DaemonServer) requireMissionAdminForRewind(ctx context.Context, missionID string) error {
	id, idErr := auth.IdentityFromContext(ctx)
	if idErr != nil {
		return status_grpc.Error(codes.Unauthenticated, "no identity in context")
	}
	tenantID := auth.TenantStringFromContext(ctx)
	if tenantID == "" {
		return status_grpc.Error(codes.PermissionDenied, "caller has no tenant")
	}

	if s.authorizer == nil {
		s.logger.Debug("ResumeMission rewind: no authorizer wired, falling back to tenant-scope guard",
			"mission_id", missionID,
			"tenant_id", tenantID,
		)
		return nil
	}

	// Mission-scoped admin check. The model relation cascades from
	// tenant#admin; per-mission admin shares layer on top.
	ok, err := s.authorizer.Check(ctx,
		"user:"+id.Subject,
		"admin",
		"mission:"+missionID,
	)
	if err != nil {
		s.logger.Warn("ResumeMission rewind: authz check failed",
			"mission_id", missionID,
			"tenant_id", tenantID,
			"error", err,
		)
		return status_grpc.Errorf(codes.Internal, "authz check failed: %v", err)
	}
	if !ok {
		return status_grpc.Errorf(codes.PermissionDenied,
			"rewind requires admin on mission %s", missionID)
	}
	return nil
}

// emitRewindCompletedAudit emits the mission.rewind.completed audit
// event (R16.6) after the rewind path validates and the orchestrator
// has applied the idempotency contract. Carries both from_id (the
// checkpoint the daemon was tracking pre-rewind) and to_id (the user-
// chosen target).
func (s *DaemonServer) emitRewindCompletedAudit(ctx context.Context, missionID, fromCheckpointID, toCheckpointID string) {
	tenantID := auth.TenantStringFromContext(ctx)
	subject := ""
	if id, err := auth.IdentityFromContext(ctx); err == nil {
		subject = id.Subject
	}

	s.logger.Info("audit: mission.rewind.completed",
		"event_kind", "mission.rewind.completed",
		"tenant_id", tenantID,
		"mission_id", missionID,
		"from_checkpoint_id", fromCheckpointID,
		"to_checkpoint_id", toCheckpointID,
		"caller_subject", subject,
	)

	if s.tenantAdminAuditWriter != nil {
		meta := fmt.Sprintf(
			`{"mission_id":%q,"from_checkpoint_id":%q,"to_checkpoint_id":%q}`,
			missionID, fromCheckpointID, toCheckpointID,
		)
		s.tenantAdminAuditWriter.Log(audit.Event{
			TenantID:   tenantID,
			ActorID:    subject,
			ActorType:  "user",
			Action:     "mission.rewind.completed",
			TargetType: "mission",
			TargetID:   missionID,
			Metadata:   []byte(meta),
		})
	}
}

// resolveLatestCheckpointID returns the most-recent checkpoint ID for
// the given mission, or empty string when the lookup fails or the
// mission has no checkpoints. Used as `from_checkpoint_id` in the
// rewind audit envelope.
func (s *DaemonServer) resolveLatestCheckpointID(ctx context.Context, missionID string) string {
	checkpoints, err := s.daemon.GetMissionCheckpoints(ctx, missionID)
	if err != nil || len(checkpoints) == 0 {
		return ""
	}
	return checkpoints[0].CheckpointID
}

// applyRewindIdempotency / serverRewindEmitter live in mission_handlers.go
// to keep the orchestrator import out of server.go's already-busy
// import block. Spec: mission-checkpointing R6.3-R6.6, R16.4.

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
		return nil, preserveStatus(err, "failed to get mission history")
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

		return nil, preserveStatus(err, "failed to get mission checkpoints")
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
		return nil, preserveStatus(err, "failed to list mission definitions")
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

// CreateMission creates a new mission by reference. Inline target / inline
// mission / YAML paths were removed under spec mission-api-only-cleanup — the
// mission definition and target must already be registered via
// CreateMissionDefinition and the target API.
func (s *DaemonServer) CreateMission(ctx context.Context, req *daemonpb.CreateMissionRequest) (*daemonpb.CreateMissionResponse, error) {
	s.logger.Info("create mission request received",
		"name", req.Name,
		"target_id", req.TargetId,
		"mission_definition_id", req.MissionDefinitionId,
	)

	if req.Name == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "mission name is required")
	}
	if req.TargetId == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "target_id is required")
	}
	if req.MissionDefinitionId == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "mission_definition_id is required")
	}

	data := CreateMissionData{
		Name:                req.Name,
		Description:         req.Description,
		TargetID:            req.TargetId,
		MissionDefinitionID: req.MissionDefinitionId,
		Variables:           req.Variables,
		MemoryContinuity:    req.MemoryContinuity,
		Metadata:            req.Metadata,
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

		return nil, preserveStatus(err, "failed to create mission")
	}

	s.logger.Info("mission created successfully",
		"mission_id", result.MissionID,
		"target_id", result.TargetID,
		"mission_definition_id", result.MissionDefinitionID,
	)

	// Write the FGA `mission:<id> belongs_to tenant:<tenant>` tuple so the
	// cascading viewer/admin relations declared in model.fga resolve for
	// every tenant member/admin without per-user grants. This is the only
	// tuple the daemon writes on mission creation; per-user "share with"
	// grants land separately when that UI ships.
	//
	// This write is REQUIRED: without the belongs_to tuple, the FGA model
	// relation `define viewer: [user] or admin or member from belongs_to`
	// cannot resolve for tenant members — leaving the mission permanently
	// inaccessible to all ListCheckpoints / GetCheckpoint callers.
	//
	// Spec: mission-checkpointing R13/R14/R15/R16, model.fga `type mission`.
	if s.authorizer != nil {
		tenantID := auth.TenantStringFromContext(ctx)
		if tenantID == "" {
			return nil, status_grpc.Error(codes.Internal, "CreateMission: no tenant in context — cannot write FGA belongs_to tuple")
		}
		tuple := authz.Tuple{
			User:     "tenant:" + tenantID,
			Relation: "belongs_to",
			Object:   "mission:" + result.MissionID,
		}
		if writeErr := s.authorizer.Write(ctx, []authz.Tuple{tuple}); writeErr != nil {
			return nil, status_grpc.Errorf(codes.Internal,
				"CreateMission: failed to write FGA belongs_to tuple for mission %s: %v",
				result.MissionID, writeErr,
			)
		}
		s.logger.Debug("CreateMission: mission belongs_to tuple written",
			"mission_id", result.MissionID,
			"tenant_id", tenantID,
		)
	}

	// Build proto Mission response
	protoMission := &daemonpb.Mission{
		Id:       result.MissionID,
		Name:     result.Name,
		Status:   daemonpb.MissionStatus_MISSION_STATUS_PENDING,
		TargetId: result.TargetID,
	}

	return &daemonpb.CreateMissionResponse{
		Success: true,
		Mission: protoMission,
		Message: fmt.Sprintf("Mission '%s' created successfully", result.Name),
	}, nil
}

// CreateMissionDefinition registers a structured mission definition with the
// daemon. The definition is validated via mission.Validate and persisted to the
// definition store; no YAML parsing, git cloning, or dependency resolution runs.
func (s *DaemonServer) CreateMissionDefinition(ctx context.Context, req *daemonpb.CreateMissionDefinitionRequest) (*daemonpb.CreateMissionDefinitionResponse, error) {
	if req == nil || req.Definition == nil {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "definition is required")
	}

	def := req.Definition
	if def == nil {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "invalid mission definition: definition is nil")
	}

	// Minimal validation at the wire boundary. Full structural validation
	// happens at the protovalidate gRPC interceptor; this guard catches the
	// summary envelope's required fields the runtime needs immediately.
	if def.GetName() == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "definition name is required")
	}

	result, err := s.daemon.CreateMissionDefinition(ctx, CreateMissionDefinitionData{Definition: def})
	if err != nil {
		s.logger.Error("failed to create mission definition", "error", err, "name", def.GetName())
		if strings.Contains(err.Error(), "already exists") {
			return nil, status_grpc.Errorf(codes.AlreadyExists, "%v", err)
		}
		return nil, preserveStatus(err, "failed to create mission definition")
	}

	s.logger.Info("mission definition created",
		"mission_definition_id", result.MissionDefinitionID,
		"name", result.Info.Name,
	)

	return &daemonpb.CreateMissionDefinitionResponse{
		MissionDefinitionId: result.MissionDefinitionID,
		Info: &daemonpb.MissionDefinitionInfo{
			Name:        result.Info.Name,
			Version:     result.Info.Version,
			Description: result.Info.Description,
			Source:      result.Info.Source,
			InstalledAt: result.Info.InstalledAt.Unix(),
			UpdatedAt:   result.Info.UpdatedAt.Unix(),
			NodeCount:   int32(result.Info.NodeCount),
		},
	}, nil
}

// Shutdown, ImpersonateTenant, and RefreshToolCatalog have been relocated
// to platform_operator_shutdown.go, platform_operator_impersonate.go, and
// platform_operator_refresh_tool_catalog.go as PlatformOperatorService handlers.
// The langfuseCredentialName helper and langfuseCredentialPayload type remain
// here for use by the new Langfuse handler files.

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

// GetTenantLangfuseCredentials, SetTenantLangfuseCredentials, and
// DeleteTenantLangfuseCredentials have been relocated to
// tenant_admin_langfuse_get.go, tenant_admin_langfuse_set.go, and
// tenant_admin_langfuse_delete.go as TenantAdminService handlers.

// ---------------------------------------------------------------------------
// Tenant management RPCs
//
// CreateTenant, GetTenant, ListTenants, UpdateTenant, DeleteTenant have been
// removed. Tenant lifecycle is now the sole responsibility of the standalone
// gibson-tenant-operator (see core/tenant-operator/).
// ---------------------------------------------------------------------------

// RefreshToolCatalog, ImpersonateTenant, GetOnboardingState, and
// UpdateOnboardingState have been relocated to PlatformOperatorService and
// TenantAdminService handler files respectively.

// ---------------------------------------------------------------------------
// API Key RPCs — deleted.
// CreateAPIKey, ListAPIKeys, RevokeAPIKey have been removed from
// The gsk_ API key system has been removed.
// See: agent-service-credentials spec Requirement 10.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// InitiateSignup has been removed. Signup is now owned by the
// gibson-tenant-operator saga (Tenant CRD reconciler).

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Task 9: GetMyPermissions — returns the caller's role, admin flag,
// component grants, and team memberships for the current tenant.
// ---------------------------------------------------------------------------

// GetMyPermissions returns a compact permission summary for the authenticated
// caller within their current tenant.  It is callable by any authenticated user
// (no admin relation required).
//
// Role closure parity: the FGA model defines admin = [user] or owner, so
// checking the "admin" relation alone returns true for owners too — but the
// role string in the response would be "admin", hiding the fact that the
// caller holds the higher "owner" relation.  The dashboard's permission
// resolution layer (satisfiesRelation) maps role strings to privilege tiers;
// if "owner" is not returned when the caller is an owner, the dashboard cannot
// grant the owner the additional owner-only actions (e.g. transfer ownership).
//
// Fix: use BatchCheck for both "owner" and "admin" relations (the same
// 2-check pattern used by ListMyMemberships / pickHighestRole) so the returned
// role correctly reflects the caller's highest held relation.
//
// Spec: gibson#289 — gibson.owner RBAC permission closure parity.
func (s *DaemonServer) GetMyPermissions(ctx context.Context, req *daemonpb.GetMyPermissionsRequest) (*daemonpb.GetMyPermissionsResponse, error) {
	tenantID := req.GetTenantId()
	if tenantID == "" {
		tenantID = auth.TenantStringFromContext(ctx)
	}
	if tenantID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id is required (or call with a tenant-scoped JWT)")
	}

	// Resolve the caller's user ID from the auth context.
	callerID, err := auth.IdentityFromContext(ctx)
	if err != nil {
		return nil, status_grpc.Error(codes.Unauthenticated, "user identity not found in context")
	}
	userID := callerID.Subject
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

	// Check both "owner" and "admin" relations via a single BatchCheck call.
	// This mirrors the ListMyMemberships / pickHighestRole pattern and ensures
	// "owner" is returned for users who hold the owner tuple, not "admin"
	// (which the FGA computed union would also grant them via admin = [user] or owner).
	//
	// checks[0] = owner check, checks[1] = admin check.
	objStr := fmt.Sprintf("tenant:%s", tenantID)
	userStr := fmt.Sprintf("user:%s", userID)
	checks := []authz.CheckRequest{
		{User: userStr, Relation: "owner", Object: objStr},
		{User: userStr, Relation: "admin", Object: objStr},
	}
	results, err := s.authorizer.BatchCheck(ctx, checks)
	if err != nil {
		s.logger.WarnContext(ctx, "GetMyPermissions: BatchCheck failed; defaulting to member",
			slog.String("tenant_id", tenantID),
			slog.String("user_id", userID),
			slog.String("error", err.Error()),
		)
		// Non-fatal: degrade to member.
		results = []bool{false, false}
	}

	isOwner := len(results) > 0 && results[0]
	isAdmin := len(results) > 1 && results[1]

	// pickHighestRole: owner > admin > member.
	// IsAdmin is true whenever the caller holds admin-or-above privilege
	// (owners satisfy FGA "admin" checks via the computed union).
	role := pickHighestRole(isOwner, isAdmin)
	effectiveAdmin := isOwner || isAdmin

	// Component grants and team memberships were previously sourced from the
	// provisioner package; those features now live in the tenant-operator
	// control plane. Returning empty slices keeps the proto response valid.
	return &daemonpb.GetMyPermissionsResponse{
		TenantId:        tenantID,
		Role:            role,
		IsAdmin:         effectiveAdmin,
		ComponentGrants: nil,
		TeamMemberships: nil,
	}, nil
}

// ListMyMemberships returns every tenant the authenticated caller is a
// `member` of, with the caller's role (admin/member) per tenant. Identity
// comes from the request context; no tenant_id parameter — this RPC
// discovers the caller's tenants. Used by the dashboard at sign-in time
// to populate the tenant picker / set the active-tenant cookie.
//
// Authz semantics: registered as `unauthenticated: true` in the ext-authz
// RPC registry — caller identity is required (validated by Envoy
// jwt_authn + ext-authz) but no per-tenant FGA gate is performed (the
// response IS the tenant list).
func (s *DaemonServer) ListMyMemberships(ctx context.Context, _ *daemonpb.ListMyMembershipsRequest) (*daemonpb.ListMyMembershipsResponse, error) {
	callerID, err := auth.IdentityFromContext(ctx)
	if err != nil || callerID.Subject == "" {
		return nil, status_grpc.Error(codes.Unauthenticated, "user identity not found in context")
	}
	userID := callerID.Subject

	if s.authorizer == nil {
		// No authorizer wired — best we can do is return an empty list and
		// let the dashboard route the user to onboarding. Logged so the
		// degraded mode is visible.
		s.logger.WarnContext(ctx, "ListMyMemberships: authorizer not wired; returning empty memberships",
			slog.String("user_id", userID),
		)
		return &daemonpb.ListMyMembershipsResponse{Memberships: nil}, nil
	}

	tenantIDs, err := s.authorizer.ListObjects(ctx, "user:"+userID, "member", "tenant")
	if err != nil {
		s.logger.WarnContext(ctx, "ListMyMemberships: ListObjects failed",
			slog.String("user_id", userID),
			slog.String("error", err.Error()),
		)
		return nil, status_grpc.Error(codes.Internal, "failed to list memberships")
	}
	if len(tenantIDs) == 0 {
		return &daemonpb.ListMyMembershipsResponse{Memberships: nil}, nil
	}

	// Batch-evaluate owner AND admin relations across all tenants in a single
	// FGA call. For N tenants we push 2*N checks: checks[2*i] = owner check
	// for tenant i, checks[2*i+1] = admin check for tenant i.
	//
	// `tenantIDs` from `ListObjects` already includes the `tenant:` prefix
	// (OpenFGA wire convention) — we MUST strip it before re-prefixing,
	// otherwise the constructed Object becomes `tenant:tenant:<id>`, which
	// FGA rejects as `invalid 'object' field format` and the entire
	// BatchCheck errors out, degrading every caller's role to "member".
	// (Pre-existing long-standing bug, exposed by tenant-role-taxonomy
	// when the role string finally became visible in the dashboard.)
	//
	// Spec: tenant-role-taxonomy Req 2.1–2.3.
	checks := make([]authz.CheckRequest, 0, 2*len(tenantIDs))
	for _, tid := range tenantIDs {
		bareTID := strings.TrimPrefix(tid, "tenant:")
		objStr := "tenant:" + bareTID
		checks = append(checks,
			authz.CheckRequest{User: "user:" + userID, Relation: "owner", Object: objStr},
			authz.CheckRequest{User: "user:" + userID, Relation: "admin", Object: objStr},
		)
	}
	results, err := s.authorizer.BatchCheck(ctx, checks)
	if err != nil {
		// Non-fatal: degrade to "everyone is member"; log for observability.
		// Req 2.4: fail-closed-to-member on BatchCheck error.
		s.logger.WarnContext(ctx, "ListMyMemberships: BatchCheck failed; defaulting all roles to member",
			slog.String("user_id", userID),
			slog.String("error", err.Error()),
		)
		results = make([]bool, 2*len(tenantIDs))
	}

	memberships := make([]*daemonpb.Membership, 0, len(tenantIDs))
	for i, tid := range tenantIDs {
		isOwner := 2*i < len(results) && results[2*i]
		isAdmin := 2*i+1 < len(results) && results[2*i+1]
		role := pickHighestRole(isOwner, isAdmin)

		// OpenFGA ListObjects returns object strings of the form
		// "tenant:<id>". The wire contract for daemonpb.Membership.TenantId
		// is the bare id — downstream consumers (dashboard's
		// gibson_active_tenant cookie, x-gibson-tenant header, FGA's own
		// resolveObject which re-adds the type prefix) expect the unprefixed
		// form. Strip "tenant:" defensively; pass through anything that
		// doesn't have the prefix.
		bareID := strings.TrimPrefix(tid, "tenant:")
		// Friendly name lookup is best-effort; on miss/timeout fall back to ID.
		name := bareID
		if s.tenantNameResolver != nil {
			if resolved, ok, _ := s.tenantNameResolver(ctx, bareID); ok && resolved != "" {
				name = resolved
			}
		}

		s.logger.InfoContext(ctx, "ListMyMemberships: resolved role",
			slog.String("user_id", userID),
			slog.String("tenant_id", bareID),
			slog.String("role", role),
		)

		memberships = append(memberships, &daemonpb.Membership{
			TenantId:   bareID,
			TenantName: name,
			Role:       role,
		})
	}

	// Sort by display name ASC so the dashboard picker is stable across requests.
	sortMembershipsByName(memberships)

	return &daemonpb.ListMyMembershipsResponse{Memberships: memberships}, nil
}

// sortMembershipsByName sorts a slice of Memberships in-place by TenantName ASC.
// Equal names tie-break on TenantId for determinism.
func sortMembershipsByName(ms []*daemonpb.Membership) {
	sort.Slice(ms, func(i, j int) bool {
		if ms[i].GetTenantName() != ms[j].GetTenantName() {
			return ms[i].GetTenantName() < ms[j].GetTenantName()
		}
		return ms[i].GetTenantId() < ms[j].GetTenantId()
	})
}

// pickHighestRole returns the highest role the user holds for a tenant, given
// the results of owner and admin BatchCheck calls.
//
// Role precedence (highest to lowest): owner > admin > member.
// A user who holds owner inherits admin and member by FGA computed union, but
// the daemon's BatchCheck observes the raw tuple-level result: if the owner
// tuple exists, isOwner is true (and isAdmin may also be true due to the
// computed union). We always return the highest explicit signal.
//
// Spec: tenant-role-taxonomy Req 2.1, 2.2, 2.3.
func pickHighestRole(isOwner, isAdmin bool) string {
	if isOwner {
		return "owner"
	}
	if isAdmin {
		return "admin"
	}
	return "member"
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
