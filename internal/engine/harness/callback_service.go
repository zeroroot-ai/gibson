// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/emitbounds"
	findingpkg "github.com/zeroroot-ai/gibson/internal/engine/finding"
	"github.com/zeroroot-ai/gibson/internal/engine/graphrag/ingest"
	"github.com/zeroroot-ai/gibson/internal/engine/harness/middleware"
	"github.com/zeroroot-ai/gibson/internal/engine/harness/sandboxed"
	"github.com/zeroroot-ai/gibson/internal/engine/metatool"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/infra/queue"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
	"github.com/zeroroot-ai/gibson/internal/platform/pagetoken"
	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
	"github.com/zeroroot-ai/sdk/auth"
	sdkgraphrag "github.com/zeroroot-ai/sdk/graphrag"
	"github.com/zeroroot-ai/sdk/protoresolver"
	"go.opentelemetry.io/otel/attribute"
	otelcodes "go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// CredentialStore provides access to stored credentials.
// This interface is implemented by the daemon's credential manager
// to provide secure credential retrieval with decryption.
type CredentialStore interface {
	// GetCredential retrieves a credential by name, decrypting it if necessary.
	// Returns the credential with its secret value populated.
	GetCredential(ctx context.Context, name string) (*types.Credential, string, error)
}

// EventBusPublisher is an interface for publishing daemon-wide events.
// This allows the callback service to publish tool and LLM events
// to the daemon's event bus for graph processing.
type EventBusPublisher interface {
	Publish(ctx context.Context, event interface{}) error
}

// DiscoveryProcessor processes proto DiscoveryResult from tool responses.
// This interface is implemented by the graphrag/processor package to
// extract, convert, and store discovered entities to Neo4j.
type DiscoveryProcessor interface {
	// Process extracts discovered nodes from a proto DiscoveryResult and stores them in the graph.
	// Takes graphragpb.DiscoveryResult (proto-first approach) for processing.
	Process(ctx context.Context, execCtx ingest.ExecContext, discovery *graphragpb.DiscoveryResult) (interface{}, error)
}

// HarnessCallbackService implements the gRPC HarnessCallbackService server.
// It receives harness operation requests from remote agents via gRPC and
// delegates them to the appropriate registered harness instance.
//
// The service uses mission-based harness lookup via CallbackHarnessRegistry,
// requiring explicit mission_id and agent_name in the callback context.
// This enforces clean separation and supports concurrent execution of the
// same agent in different missions.
//
// When an agent running in standalone mode makes a harness call, the SDK's
// CallbackClient sends a gRPC request with context information (mission ID
// and agent name), which is used to look up the correct harness instance.
//
// To register this service with a gRPC server:
//
//	service := harness.NewHarnessCallbackServiceWithRegistry(logger, registry)
//	harnesspb.RegisterHarnessCallbackServiceServer(grpcServer, service)
//
// Before executing an agent task, register its harness:
//
//	registry.RegisterHarnessForMission(missionID, agentName, harness)
//	defer registry.UnregisterHarnessForMission(missionID, agentName)
type HarnessCallbackService struct {
	harnesspb.UnimplementedHarnessCallbackServiceServer

	// registry provides mission-based harness lookup for external agents (new mode)
	registry *CallbackHarnessRegistry

	// credentialStore provides access to stored credentials
	credentialStore CredentialStore

	// eventBus publishes tool and LLM events for graph processing
	eventBus EventBusPublisher

	// observationSink receives typed agent observations (ADR-0107); the daemon
	// wires it to the per-tenant brain. nil means observation ingest is disabled.
	observationSink ObservationSink

	// observeCounts bounds how many observations one task may emit through
	// the Observe RPC (emitbounds.MaxObservationsPerTask, ADR-0112 "Write
	// contract"). Observe has no per-task object to hang a counter on — the
	// handler never resolves a harness — so this path uses the keyed,
	// bounded pool. Lazily created by observeCounter.
	observeCountsOnce sync.Once
	observeCounts     *emitbounds.TaskCounter

	// toolValidator checks whether a discovery tool's response carried the
	// DiscoveryResult the catalog says it emits (gibson#625). Built on first
	// use by validator(), because this service has several construction paths.
	validatorOnce sync.Once
	toolValidator *ToolValidator

	// worldViewSource projects the mission-Scope-limited World slice the
	// WorldView RPC returns (ADR-0112 read half, gibson#1377); the daemon wires
	// it to the per-tenant brain. nil means the WorldView read is disabled and
	// returns an empty slice, symmetric to observationSink's no-op default.
	worldViewSource WorldViewSource

	// modelGateway and agentGateway are the public gateways that ResolveModel
	// and ResolveAgent return.
	modelGateway GatewayInfo
	agentGateway GatewayInfo
	// outsideAgents returns the outside agent store. ResolveAgent resolves a name
	// that the tenant registered as an outside agent.
	outsideAgents OutsideAgentStoreSource

	// toolCallSink receives completed tool calls observed on the callback
	// CallToolProto path (ADR-0120, gibson#271); the daemon wires it to the
	// per-tenant World's AgentToolCall capture — the flight recorder's tool-I/O
	// half. nil means capture is disabled.
	toolCallSink ToolCallSink

	// beliefSubstrate backs the PlaceBet RPC (ADR-0122, ADR-0129,
	// gibson#273/#278): a placed bet is persisted as belief on its
	// hypothesis's claim-node. nil means PlaceBet returns Unavailable — the
	// market view is not wired on this daemon. See callback_place_bet.go.
	beliefSubstrate brain.BeliefSubstrate

	// proofSettlement backs the SubmitProof RPC (ADR-0131,
	// gibson#389): resolving an enabled Domain Pack's CEL predicate binding
	// and settling a bet true once it fires against submitted evidence. nil
	// means SubmitProof returns Unavailable, the same staged-wiring default
	// beliefSubstrate uses. See callback_submit_proof.go.
	proofSettlement brain.ProofSettlementEngine

	// toolApproval is the approval queue that invoke_tool uses for a tool that
	// the manifest of its connector marks (gibson#1474). nil means that a
	// call of a marked tool is refused.
	toolApproval metatool.ApprovalGate

	// ontologyDiscovery backs the ProposeOntologyExtension RPC (ADR-0124,
	// ADR-0133, gibson#391): folding an agent-proposed Taxonomy
	// node label or relationship type through the ValidIdentifier safety gate
	// and PromotionGate.Observe's recurrence counting. nil means
	// ProposeOntologyExtension returns Unavailable, the same staged-wiring
	// default proofSettlement uses. See callback_propose_ontology_extension.go.
	ontologyDiscovery brain.OntologyDiscoveryEngine

	// spanProcessors receives spans exported from remote agents for tracing integration
	spanProcessors []sdktrace.SpanProcessor

	// taskGrantVerifier resolves the verifier that binds a request to the
	// task grant it carries (gibson#1605). Read per request; see
	// WithTaskGrantVerifier.
	taskGrantVerifier func() TaskGrantVerifier

	// forkLedger records the forks of each source grant (ADR-0169, D74).
	// The callback interceptors refuse the grant of a forked source outside
	// the source sandbox, and ClaimFork serves each fork its dispatch.
	forkLedger ForkLedger

	// forkGrants mints the grant of a claimed fork (D80).
	forkGrants ForkGrantMinter

	// sandboxIdentity verifies the sandbox identity token of a caller with
	// setec (setec#235). The fork checks take the sandbox of the caller from
	// it, never from a header that the process writes.
	sandboxIdentity SandboxIdentityVerifier

	// jobs is the job store the member-facing callbacks read and write
	// (ADR-0119, gibson#1711). Nil means this daemon serves no banks, and
	// every member callback says so rather than failing obscurely.
	jobs JobSurface

	// jobDriver is the JobService implementation behind OpenJob, SendInput
	// and CloseJob, the callbacks that a dispatched agent uses to drive a
	// bank (callback_job_driver.go).
	jobDriver JobDriver

	// turnGrants mints the per-turn grant each delivered input carries.
	turnGrants TurnGrantMinter

	// memberEvents carries the job lines onto a member's console stream.
	memberEvents MemberEventSink

	// memberControl is the in-memory queue of sign-in control inputs a
	// member's inbox delivers ahead of its jobs (gibson#1715).
	memberControl *MemberControl

	// memberInboxes holds the tenant/member keys with a live SubscribeInput
	// stream, so a second subscriber for the same member is refused.
	memberInboxes sync.Map // map[string]struct{}

	// members resolves which member a callback is coming from, from the
	// mission run on its verified context.
	members MemberLookup

	// tracerProvider for creating real spans from proxy span data
	tracerProvider *sdktrace.TracerProvider

	// metadataInjector adds mission context metadata to graph nodes before storage
	metadataInjector MetadataInjector

	// discoveryProcessor processes DiscoveryResult from tool responses and stores to Neo4j
	discoveryProcessor DiscoveryProcessor

	// queueManager provides access to the Redis work queue for parallel tool execution
	queueManager *QueueManager

	// missionManager provides full mission lifecycle operations (create, run, wait, cancel, etc.).
	// Declared as MissionOperator so the six mission callback stubs can delegate without a cast.
	missionManager MissionOperator

	// authzStore provides per-run authz state lookup (run_id → user_id, tenant_id).
	// Typed as RunAuthzLookup to avoid a circular import (mission→eval→harness).
	// One-code-path slice deploy#195: required for any callback service that
	// will actually serve Authorize calls — the daemon wires this in setup.
	// Tests that build the service directly without it MUST NOT exercise
	// Authorize.
	authzStore RunAuthzLookup

	// connectorAudit records each connector call of invoke_tool. Nil refuses a
	// connector call.
	connectorAudit *audit.AuditLogger
	// connectorGrants names the grant of a connector call in its record. Nil
	// records no grant.
	connectorGrants metatool.GrantLookup

	// missionBlockedTools reads the deny list of a mission from its stored
	// definition. Nil refuses a connector call.
	missionBlockedTools MissionBlockedToolsSource

	// skillLoadSink receives each successful load of an Agent Skill. nil means
	// the load is not recorded on the Timeline.
	skillLoadSink SkillLoadSink

	// agentSkills returns the Agent Skill store. It is nil when no store is wired.
	agentSkills AgentSkillStoreSource

	// componentAuthorizer is the FGA-backed authorizer for component authz decisions.
	// One-code-path slice deploy#195: required for any callback service that
	// will actually serve Authorize calls. The daemon wires this in setup
	// after FGA has been reached.
	componentAuthorizer authz.Authorizer

	// componentRegistry is the tenant-scoped component registry the SearchTools
	// RPC enumerates to build the connector catalog. Wired by the daemon; when
	// nil, SearchTools returns Unavailable.
	componentRegistry component.ComponentRegistry

	// connectors is the one MCP client of the daemon (ADR-0065). search_tools
	// lists the tools of the connectors of a tenant through it, and
	// invoke_tool calls an mcp:<connector>:<tool> id through it. Nil lists no
	// connector tool, and an mcp: call fails closed.
	connectors ConnectorClient

	// componentAuthzMetrics emits counters for every component Authorize decision.
	// When nil, metrics are not emitted (no-op).
	componentAuthzMetrics ComponentAuthzMetrics

	// sessionContextStore persists the per-(tenant, session_id) opaque
	// context blob served by Put/Get/DeleteSessionContext (gibson#1184). The
	// daemon wires it to the per-tenant dataplane Postgres
	// (callback_session_context.go); nil means the session-context RPCs
	// return Unavailable.
	sessionContextStore SessionContextStore

	// resolver provides dynamic proto type resolution using FileDescriptorSets
	resolver protoresolver.ProtoResolver

	// agentOwnerLookup resolves a target agent name to its owning user ID for
	// sub-agent ExecutorUser attribution (spec:
	// llm-user-attribution-governance Requirement 1.5). When nil the
	// DelegateToAgent handler simply does not populate ExecutorUser —
	// EnrichSpan omits the attribute rather than failing the call. The
	// indirection keeps the callback service free of a direct dependency on
	// the component registry.
	agentOwnerLookup AgentOwnerLookup

	// mu protects spanProcessors for concurrent access
	mu sync.RWMutex

	// sessionSandboxes pins a component's session to one long-lived setec
	// sandbox so successive DevboxExec commands share a /workspace
	// (gibson#1183). nil means session execution is not wired on this daemon,
	// and DevboxExec fails Unavailable with that reason rather than silently
	// launching a throwaway VM per command.
	sessionSandboxes *sandboxed.SessionRegistry

	// logger for service-level logging
	logger *slog.Logger
}

// AgentOwnerLookup resolves an agent component name (as registered in the
// daemon's component registry) to the user ID that owns it. Used by
// DelegateToAgent to populate ExecutorUser on the sub-agent's execution
// context so downstream LLM spans carry executor_user_id alongside the
// mission-stable initiator_user_id.
//
// Implementations should return ("", nil) when the owner is not resolvable
// (unknown agent, tenant-shared system agent, etc.) — DelegateToAgent
// treats this as graceful degradation and simply does not set the key.
// Returning a non-nil error aborts the delegation.
type AgentOwnerLookup func(ctx context.Context, agentName string) (userID string, err error)

// CallbackServiceOption configures the callback service.
type CallbackServiceOption func(*HarnessCallbackService)

// WithSpanProcessors adds span processors to receive tracing spans from remote agents.
func WithSpanProcessors(processors ...sdktrace.SpanProcessor) CallbackServiceOption {
	return func(s *HarnessCallbackService) {
		s.spanProcessors = append(s.spanProcessors, processors...)
	}
}

// WithTracerProvider sets the TracerProvider for creating real spans from proxy span data.
// When set, proxy spans from remote agents are re-created as real spans and passed through
// the TracerProvider's span processors (e.g., the OTLP exporter).
func WithTracerProvider(tp *sdktrace.TracerProvider) CallbackServiceOption {
	return func(s *HarnessCallbackService) {
		s.tracerProvider = tp
	}
}

// WithCredentialStore sets the credential store for secure credential retrieval.
// When set, agents can retrieve stored credentials by name via the GetCredential RPC.
// WithSessionSandboxes wires the session-sandbox registry DevboxExec routes
// through (gibson#1183). Left unset, DevboxExec answers Unavailable naming the
// reason — which is the honest answer on a daemon with no setec, and is not the
// same thing as silently running the command somewhere else.
func WithSessionSandboxes(reg *sandboxed.SessionRegistry) CallbackServiceOption {
	return func(s *HarnessCallbackService) {
		s.sessionSandboxes = reg
	}
}

func WithCredentialStore(store CredentialStore) CallbackServiceOption {
	return func(s *HarnessCallbackService) {
		s.credentialStore = store
	}
}

// WithEventBus sets the event bus for publishing tool and LLM events, which
// the execution graph engine consumes. It is required: each constructor
// panics without it (gibson#681).
func WithEventBus(eventBus EventBusPublisher) CallbackServiceOption {
	return func(s *HarnessCallbackService) {
		s.eventBus = eventBus
	}
}

// observeCounter returns the per-task observation counter for the Observe RPC,
// creating it on first use so a zero-value service stays usable in tests.
func (s *HarnessCallbackService) observeCounter() *emitbounds.TaskCounter {
	s.observeCountsOnce.Do(func() {
		s.observeCounts = emitbounds.NewTaskCounter()
	})
	return s.observeCounts
}

// observeTaskKey names the task an observation is charged against. The task of
// the verified grant decides it, as it decides the harness (callerTask), so an
// emitter cannot spread its observations over many body task ids to dodge the
// cap. A request with no grant names its task in ContextInfo. When no task is
// named, the agent run — the (mission, agent) pair the harness registry itself
// is keyed by — is the task. An emitter that supplies neither is charged
// against one shared bucket, which is the strict reading and the right way to
// fail.
func observeTaskKey(ctx context.Context, info *harnesspb.ContextInfo) string {
	if id := callerTask(ctx, info); id != "" {
		return id
	}
	return info.GetMissionId() + "/" + info.GetAgentName()
}

// ObservationAttribution is the server-resolved provenance of an emitted
// observation (ADR-0112). Every field is read off the mission record the daemon
// created — reached through the harness registered for the mission, whose tenant
// getHarness has already checked against the caller's authenticated tenant.
//
// None of it is readable from the payload. ObserveRequest carries no tenant and
// no scope field, so an agent cannot express "the host at some other network's
// address": cross-scope creation is unrepresentable rather than rejected. The
// sink takes this struct instead of digging the values out of the request
// precisely so that no future sink can reach for a payload-supplied scope.
type ObservationAttribution struct {
	// Tenant owns the World the observation lands in. It is the mission
	// record's tenant, never the caller's assertion and never a process-wide
	// default.
	Tenant string

	// ScopeID is the mission's target — the network the observation was made
	// on. Host identity is the (ScopeID, Address) coordinate (ADR-0102), so two
	// hosts answering at the same address on two scanned networks stay distinct
	// entities only because this is populated and per-target.
	ScopeID string

	// MissionID is the mission the write is attributable to. The bar is not
	// "a user was present" — agents outlive the session — but "every write is
	// attributable to a mission a user launched".
	MissionID string

	// RunID is the mission run the write is attributable to (gibson#339's
	// transcript-linking need), server-resolved off the mission record the
	// same way MissionID is — never read from the request payload, which is
	// client-supplied and unattributed. Empty when the mission record has no
	// run recorded yet, the same "no signal yet" reading Host.MissionID's
	// absence already gets.
	RunID string
}

// ObservationSink consumes a typed observation emitted by an agent (ADR-0107).
// The daemon wires this to translate the observation into a brain Timeline event
// and submit it to the per-tenant World; harness stays decoupled from the brain.
//
// attr carries the server-resolved tenant and scope; the sink must route on it
// and must not derive either from req.
type ObservationSink func(ctx context.Context, attr ObservationAttribution, req *harnesspb.ObserveRequest) error

// WithObservationSink sets the sink the Observe RPC forwards observations to.
// When unset, Observe is a no-op (the brain ingest is simply not wired).
func WithObservationSink(sink ObservationSink) CallbackServiceOption {
	return func(s *HarnessCallbackService) {
		s.observationSink = sink
	}
}

// WithBeliefSubstrate wires the belief substrate the PlaceBet RPC persists
// staked bets to (ADR-0122, ADR-0129). When unset, PlaceBet returns
// Unavailable.
func WithBeliefSubstrate(substrate brain.BeliefSubstrate) CallbackServiceOption {
	return func(s *HarnessCallbackService) {
		s.beliefSubstrate = substrate
	}
}

// WithProofSettlement wires the tenant-scoped engine the SubmitProof RPC
// resolves pack predicates and settles bets against (ADR-0131,
// gibson#389). When unset, SubmitProof returns Unavailable.
func WithProofSettlement(engine brain.ProofSettlementEngine) CallbackServiceOption {
	return func(s *HarnessCallbackService) {
		s.proofSettlement = engine
	}
}

// WithToolApproval wires the approval queue that invoke_tool uses for a tool
// that the manifest of its connector marks (gibson#1474).
func WithToolApproval(g metatool.ApprovalGate) CallbackServiceOption {
	return func(s *HarnessCallbackService) {
		s.toolApproval = g
	}
}

// WithOntologyDiscovery wires the tenant-scoped engine the
// ProposeOntologyExtension RPC folds an agent-proposed Taxonomy node label or
// relationship type through (ADR-0124, ADR-0133, gibson#391).
// When unset, ProposeOntologyExtension returns Unavailable.
func WithOntologyDiscovery(engine brain.OntologyDiscoveryEngine) CallbackServiceOption {
	return func(s *HarnessCallbackService) {
		s.ontologyDiscovery = engine
	}
}

// ToolCallRecord captures a completed tool call observed on the callback
// CallToolProto path — the tool-I/O half of the flight recorder (ADR-0120,
// gibson#271), It mirrors the
// daemon's brain.AgentToolCallObserved but lives here so the harness package
// stays decoupled from the brain package,
type ToolCallRecord struct {
	// ToolCallID is the call's stable World/graph identity — the
	// ContextInfo.ToolExecutionId the calling agent's SDK already stamps for
	// provenance (the same id discovery ingest attaches PRODUCED edges to), so
	// a tool call and the graph nodes it produced share one key.
	ToolCallID string
	// MissionID attributes the call to its mission's frame, mirroring
	// the mission frame.
	MissionID string
	// RunID is the mission run (or agent run) that made this call.
	RunID string
	// MissionRunID is the mission run that issued the call, and only that. RunID
	// falls back to the agent run, so it cannot tell one run of a mission from
	// the next (gibson#1217). Empty when the context carries no mission run.
	MissionRunID string
	// ToolName is the tool that was called.
	ToolName string
	// Arguments + Result are the full JSON the agent sent and the tool
	// returned — captured in full, always (never optional).
	Arguments string
	Result    string
	// Err is set instead of Result when the tool call failed.
	Err string
	// GrantID is the capability grant that allowed a connector call. It is
	// empty for a native tool and for a call with no grant row.
	GrantID string
	// RecordedAtUnixNano stamps when the daemon observed this call, so a
	// tenant's retention policy can be swept deterministically later.
	RecordedAtUnixNano int64
}

// ToolCallSink consumes a completed tool call observed on the callback
// CallToolProto path. The daemon wires this to the per-tenant World; tenant is
// the call's tenant (already validated equal to the mission tenant by
// getHarness). When unset, callback tool-call capture is a no-op.
type ToolCallSink func(ctx context.Context, tenant string, call ToolCallRecord)

// WithToolCallSink sets the sink CallToolProto forwards completed tool calls
// to for World capture (ADR-0120, gibson#271). When unset, capture is disabled.
func WithToolCallSink(sink ToolCallSink) CallbackServiceOption {
	return func(s *HarnessCallbackService) {
		s.toolCallSink = sink
	}
}

// WithDiscoveryProcessor sets the DiscoveryProcessor for automatic graph storage.
// When set, the callback service will extract DiscoveryResult from tool responses
// and automatically persist discovered entities to Neo4j.
func WithDiscoveryProcessor(processor DiscoveryProcessor) CallbackServiceOption {
	return func(s *HarnessCallbackService) {
		s.discoveryProcessor = processor
	}
}

// WithQueueManager sets the QueueManager for Redis-based work queue operations.
// When set, the callback service can queue tool work and stream results back to agents.
func WithQueueManager(queueMgr *QueueManager) CallbackServiceOption {
	return func(s *HarnessCallbackService) {
		s.queueManager = queueMgr
	}
}

// WithMissionManager sets the MissionOperator for agent-driven mission lifecycle operations.
// When set, agents can create, run, wait for, list, cancel, and get results of missions
// through the corresponding harness callback RPCs.
func WithMissionManager(missionMgr MissionOperator) CallbackServiceOption {
	return func(s *HarnessCallbackService) {
		s.missionManager = missionMgr
	}
}

// WithProtoResolver sets the ProtoResolver for dynamic proto type resolution.
// When set, the callback service uses this resolver for CallToolProto requests.
// If not set, a default resolver with standard configuration will be created.
func WithProtoResolver(resolver protoresolver.ProtoResolver) CallbackServiceOption {
	return func(s *HarnessCallbackService) {
		s.resolver = resolver
	}
}

// WithAgentOwnerLookup wires an AgentOwnerLookup so DelegateToAgent can
// populate ExecutorUser on the sub-agent dispatch context. When not
// configured, the handler skips ExecutorUser propagation and EnrichSpan
// omits the executor_user_id span attribute (graceful degradation).
// Typical implementations close over the daemon's ComponentRegistry.
func WithAgentOwnerLookup(fn AgentOwnerLookup) CallbackServiceOption {
	return func(s *HarnessCallbackService) {
		s.agentOwnerLookup = fn
	}
}

// NewHarnessCallbackService creates a new callback service instance with
// task-based harness lookup (legacy mode).
func NewHarnessCallbackService(logger *slog.Logger, opts ...CallbackServiceOption) *HarnessCallbackService {
	if logger == nil {
		logger = slog.Default()
	}

	s := &HarnessCallbackService{
		logger:           logger.With("component", "harness_callback_service"),
		metadataInjector: NewMetadataInjector(),
		// The member seams are never nil. A daemon that serves no banks
		// answers ErrNoBankSurface on each, and the callbacks fail closed.
		jobs:          noBankSurface{},
		jobDriver:     noBankSurface{},
		members:       noBankSurface{},
		turnGrants:    noBankSurface{},
		memberEvents:  noBankSurface{},
		memberControl: NewMemberControl(),
		// The Agent Skill seams are never nil. A daemon that serves no Agent Skill
		// offers none, and a load with no sink fails.
		agentSkills:   noAgentSkillStore,
		skillLoadSink: noSkillLoadSink,
	}

	for _, opt := range opts {
		opt(s)
	}

	// Create default resolver if none was provided
	if s.resolver == nil {
		s.resolver = protoresolver.NewDefaultProtoResolver(protoresolver.DefaultConfig())
	}

	requireEventBus(s)
	return s
}

// NewHarnessCallbackServiceWithRegistry creates a new callback service instance
// with mission-based harness lookup via the provided registry.
//
// This is the preferred constructor for external agents, as it supports
// concurrent execution of the same agent in different missions.
//
// Parameters:
//   - logger: Structured logger for service events
//   - registry: The harness registry for mission-based lookups
//   - opts: Optional configuration options (e.g., WithSpanProcessors)
//
// Returns:
//   - *HarnessCallbackService: A new service instance ready to be registered
func NewHarnessCallbackServiceWithRegistry(logger *slog.Logger, registry *CallbackHarnessRegistry, opts ...CallbackServiceOption) *HarnessCallbackService {
	if logger == nil {
		logger = slog.Default()
	}

	s := &HarnessCallbackService{
		registry:         registry,
		logger:           logger.With("component", "harness_callback_service"),
		metadataInjector: NewMetadataInjector(),
		jobs:             noBankSurface{},
		jobDriver:        noBankSurface{},
		members:          noBankSurface{},
		turnGrants:       noBankSurface{},
		memberEvents:     noBankSurface{},
		memberControl:    NewMemberControl(),
		agentSkills:      noAgentSkillStore,
		skillLoadSink:    noSkillLoadSink,
	}

	for _, opt := range opts {
		opt(s)
	}

	// Create default resolver if none was provided
	if s.resolver == nil {
		s.resolver = protoresolver.NewDefaultProtoResolver(protoresolver.DefaultConfig())
	}

	requireEventBus(s)
	return s
}

// getHarness retrieves the harness for a request based on the context information.
//
// This method requires explicit mission ID and agent name for harness lookup via registry.
// The legacy string parsing and task-based lookup have been removed to enforce the use
// of the explicit mission_id field in ContextInfo.
//
// Parameters:
//   - ctx: Request context
//   - contextInfo: Context information from the gRPC request
//
// Returns:
//   - AgentHarness: The harness instance to use for this request
//   - error: Non-nil if no harness is found or if context info is invalid
func (s *HarnessCallbackService) getHarness(ctx context.Context, contextInfo *harnesspb.ContextInfo) (AgentHarness, error) {
	if contextInfo == nil {
		return nil, status.Error(codes.InvalidArgument, "missing context info in request")
	}

	// Require explicit mission ID and agent name
	if contextInfo.MissionId == "" {
		return nil, status.Error(codes.InvalidArgument, "missing mission_id in context info - ensure agent SDK is v0.7.0+")
	}

	if contextInfo.AgentName == "" {
		return nil, status.Error(codes.InvalidArgument, "missing agent_name in context info")
	}

	// The mission ID is the same for every run of a record, so a callback
	// must name its run (gibson#1235).
	if callerRun(ctx, contextInfo) == "" {
		return nil, status.Error(codes.InvalidArgument, "missing mission_run_id in context info - ensure agent SDK is v0.208.0+")
	}

	// Registry must be configured for mission-based lookup
	if s.registry == nil {
		return nil, status.Error(codes.Internal, "callback registry not configured")
	}

	// Perform registry lookup with explicit mission ID, agent name and run ID.
	// The mission ID is the same for every run of a record, so an agent of
	// run 1 that still runs must not find the harness of run 2. Its evidence
	// would take the run of run 2 (gibson#1217).
	harness, err := s.registry.Lookup(contextInfo.MissionId, contextInfo.AgentName, callerRun(ctx, contextInfo), callerTask(ctx, contextInfo))
	if err != nil {
		if errors.Is(err, ErrCallbackTaskMismatch) {
			s.logger.Warn("callback of another task refused",
				"mission_id", contextInfo.MissionId,
				"agent_name", contextInfo.AgentName,
				"callback_run_id", contextInfo.MissionRunId,
				"callback_task_id", contextInfo.TaskId,
				"error", err,
			)
			return nil, status.Errorf(codes.FailedPrecondition, "callback refused: %v", err)
		}
		if errors.Is(err, ErrCallbackRunMismatch) {
			s.logger.Warn("callback of another run refused",
				"mission_id", contextInfo.MissionId,
				"agent_name", contextInfo.AgentName,
				"callback_run_id", contextInfo.MissionRunId,
				"error", err,
			)
			return nil, status.Errorf(codes.FailedPrecondition, "callback refused: %v", err)
		}
		s.logger.Error("harness lookup failed",
			"mission_id", contextInfo.MissionId,
			"agent_name", contextInfo.AgentName,
			"task_id", contextInfo.TaskId,
			"error", err,
		)
		return nil, status.Errorf(codes.NotFound, "no active harness for mission %s, agent %s: %v",
			contextInfo.MissionId, contextInfo.AgentName, err)
	}

	s.logger.Debug("harness lookup succeeded",
		"mission_id", contextInfo.MissionId,
		"agent_name", contextInfo.AgentName,
		"task_id", contextInfo.TaskId,
	)

	// Tenant isolation: prevent cross-tenant harness access. Per
	// unified-identity-and-authorization Requirement 8.6, the legacy
	// dev-mode bypass (allowing through when either side was empty)
	// is removed. Identity must always have a tenant by the time it
	// reaches a handler — if it does not, the request is rejected.
	// Mission tenant must always be set — if it is not, the mission
	// was created under broken state and we refuse to operate on it.
	contextTenant := auth.TenantStringFromContext(ctx)
	missionTenant := harness.Mission().TenantID
	if contextTenant == "" || contextTenant == auth.SystemTenantString {
		s.logger.Warn("harness lookup with missing tenant in context",
			slog.String("mission_id", contextInfo.MissionId),
			slog.String("agent_name", contextInfo.AgentName),
		)
		return nil, status.Error(codes.PermissionDenied, "no tenant in context")
	}
	if missionTenant == "" {
		s.logger.Warn("harness lookup against mission with empty tenant",
			slog.String("context_tenant", contextTenant),
			slog.String("mission_id", contextInfo.MissionId),
		)
		return nil, status.Error(codes.PermissionDenied, "mission has no tenant")
	}
	if contextTenant != missionTenant {
		s.logger.Warn("tenant mismatch on harness lookup",
			slog.String("context_tenant", contextTenant),
			slog.String("mission_tenant", missionTenant),
			slog.String("mission_id", contextInfo.MissionId),
			slog.String("agent_name", contextInfo.AgentName),
		)
		return nil, status.Error(codes.PermissionDenied, "tenant mismatch")
	}

	return harness, nil
}

// ============================================================================
// LLM Operations
// ============================================================================

// validator is the discovery-compliance validator, built once.
//
// Lazily rather than in the constructor: HarnessCallbackService has several
// construction paths and a field set in one of them is a nil dereference in the
// others. It holds only a logger, so building it on first use costs nothing.
func (s *HarnessCallbackService) validator() *ToolValidator {
	s.validatorOnce.Do(func() {
		s.toolValidator = NewToolValidator(s.logger)
	})
	return s.toolValidator
}

// newToolCallID returns the id of one tool call. It is the ToolExecutionId that
// the SDK of the calling agent stamps for provenance. When the caller left it
// empty, the id is a fresh one, so the call is still recorded.
func newToolCallID(contextInfo *harnesspb.ContextInfo) string {
	if id := contextInfo.GetToolExecutionId(); id != "" {
		return id
	}
	return uuid.NewString()
}

// captureToolCall folds a completed CallToolProto invocation into the
// per-tenant World via the wired toolCallSink (ADR-0120, gibson#271) — the
// tool-I/O half of the flight recorder, alongside captureLLMCall's transcript
// half. Best-effort: a missing sink, context, or tenant is a silent no-op, the
// same contract as captureLLMCall, so capture can never break a tool call.
//
// toolCallID is the id of the call. The caller mints it one time, with
// newToolCallID, at the start of the call. The record, the reply and the
// discovery processor all use that one id.
//
// It returns the id that the record holds, or an empty string when nothing was
// recorded. The tool call reply carries this id as tool_call_id, so a finding
// can cite the call.
func (s *HarnessCallbackService) captureToolCall(ctx context.Context, contextInfo *harnesspb.ContextInfo, toolCallID, toolName, argumentsJSON, resultJSON, callErr string) string {
	return s.captureGrantedToolCall(ctx, contextInfo, toolCallID, toolName, argumentsJSON, resultJSON, callErr, "")
}

// captureGrantedToolCall is captureToolCall for a connector call, with the
// capability grant that allowed it.
func (s *HarnessCallbackService) captureGrantedToolCall(
	ctx context.Context, contextInfo *harnesspb.ContextInfo,
	toolCallID, toolName, argumentsJSON, resultJSON, callErr, grantID string,
) string {
	if s.toolCallSink == nil || contextInfo == nil {
		return ""
	}
	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" {
		return ""
	}
	runID := contextInfo.GetMissionRunId()
	if runID == "" {
		runID = contextInfo.GetAgentRunId()
	}
	s.toolCallSink(ctx, tenant, ToolCallRecord{
		ToolCallID:         toolCallID,
		MissionID:          contextInfo.GetMissionId(),
		MissionRunID:       contextInfo.GetMissionRunId(),
		RunID:              runID,
		ToolName:           toolName,
		Arguments:          argumentsJSON,
		Result:             resultJSON,
		Err:                callErr,
		GrantID:            grantID,
		RecordedAtUnixNano: time.Now().UnixNano(),
	})
	return toolCallID
}

// ============================================================================
// Tool Operations
// ============================================================================

// CallToolProto implements the proto-based tool execution RPC.
// This is the canonical way to execute tools from external agents.
func (s *HarnessCallbackService) CallToolProto(ctx context.Context, req *harnesspb.CallToolProtoRequest) (*harnesspb.CallToolProtoResponse, error) {
	// Meta-tools (search_tools / invoke_tool) are synthetic: they are not
	// registered tools, so intercept before the registry dispatch and resolve
	// them against the connector catalog (ADR-0065).
	if isMetaTool(req.GetName()) {
		return s.callMetaTool(ctx, req)
	}

	harness, err := s.getHarness(ctx, req.Context)
	if err != nil {
		return nil, err
	}

	// Mission-level blocked_tools denial (MissionConstraints.blocked_tools),
	// matched against the raw name and the canonical native id. The daemon
	// enforces this at dispatch so it fails closed regardless of the agent.
	// The list is read from the stored mission, as for invoke_tool, and a list
	// that cannot be read refuses the call.
	blockedTools, blockedErr := s.storedBlockedTools(ctx, req.Context)
	if blockedErr != nil {
		s.logger.ErrorContext(ctx, "tool call refused: the mission deny list could not be read", "tool", req.Name, "err", blockedErr)
		// gibson:no-tool-executed — no deny list, so nothing ran.
		return &harnesspb.CallToolProtoResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE,
				Message: "the mission policy could not be loaded",
			},
		}, nil
	}
	if blockedID, blockedOK := metatool.MatchBlocked(blockedTools, req.Name, "native:"+req.Name); blockedOK {
		s.publishEvent(ctx, "tool.call.blocked", map[string]interface{}{
			"tool_name":  req.Name,
			"mission_id": req.Context.MissionId,
			"agent_name": req.Context.AgentName,
		})
		// gibson:no-tool-executed — denied before dispatch; no tool ran, so
		// the flight recorder has nothing to corroborate.
		return &harnesspb.CallToolProtoResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED,
				Message: fmt.Sprintf("tool '%s' is blocked by mission policy", blockedID),
			},
		}, nil
	}

	// Publish tool.call.started event
	s.publishEvent(ctx, "tool.call.started", map[string]interface{}{
		"tool_name":      req.Name,
		"mission_id":     req.Context.MissionId,
		"agent_name":     req.Context.AgentName,
		"task_id":        callerTask(ctx, req.Context),
		"parent_span_id": req.Context.SpanId,
		"input_type":     req.InputType,
		"output_type":    req.OutputType,
	})

	// Get tool descriptor to validate it exists and extract metadata
	toolDesc, err := harness.GetToolDescriptor(ctx, req.Name)
	if err != nil {
		s.logger.Error("tool not found", "error", err, "tool", req.Name)
		// gibson:no-tool-executed — the tool was never resolved, so it never ran.
		return &harnesspb.CallToolProtoResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_NOT_FOUND,
				Message: fmt.Sprintf("tool not found: %s", req.Name),
			},
		}, nil
	}

	// Extract metadata from tool descriptor for FileDescriptorSet resolution
	toolMetadata := make(map[string]string)
	if toolDesc != nil && toolDesc.Metadata != nil {
		toolMetadata = toolDesc.Metadata
	}

	// Use resolver to unmarshal input JSON into proto message
	requestMsg, err := s.resolver.UnmarshalProtoJSON(ctx, req.InputType, req.InputJson, toolMetadata)
	if err != nil {
		s.logger.Error("failed to resolve and unmarshal input type",
			"error", err,
			"tool", req.Name,
			"input_type", req.InputType)
		// gibson:no-tool-executed — the request never became a valid proto
		// call, so no tool was invoked.
		return &harnesspb.CallToolProtoResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
				Message: fmt.Sprintf("failed to unmarshal input: %v", err),
			},
		}, nil
	}

	// Create empty output message for tool to fill
	responseMsg, err := s.resolver.ResolveOutputType(ctx, req.OutputType, toolMetadata)
	if err != nil {
		s.logger.Error("failed to resolve output type",
			"error", err,
			"tool", req.Name,
			"output_type", req.OutputType)
		// gibson:no-tool-executed — the output message could not even be
		// constructed, so CallToolProto below was never reached.
		return &harnesspb.CallToolProtoResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: fmt.Sprintf("failed to resolve output type: %v", err),
			},
		}, nil
	}

	// The id of this call. The record, the reply and the discovery processor
	// all use it. Nothing below mints a second id.
	toolCallID := newToolCallID(req.Context)

	// Execute tool using CallToolProto
	if err := harness.CallToolProto(ctx, req.Name, requestMsg, responseMsg); err != nil {
		s.logger.Error("tool execution failed", "error", err, "tool", req.Name)

		// Publish tool.call.failed event
		s.publishEvent(ctx, "tool.call.failed", map[string]interface{}{
			"tool_name":      req.Name,
			"mission_id":     req.Context.MissionId,
			"agent_name":     req.Context.AgentName,
			"task_id":        callerTask(ctx, req.Context),
			"error":          err.Error(),
			"parent_span_id": req.Context.SpanId,
		})

		// Flight recorder (ADR-0120, gibson#271): capture the failed call too —
		// the arguments the agent sent and why it failed, not just the ones
		// that succeeded.
		callID := s.captureToolCall(ctx, req.Context, toolCallID, req.Name, string(req.InputJson), "", err.Error())

		return &harnesspb.CallToolProtoResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: err.Error(),
			},
			ToolCallId: callID,
		}, nil
	}

	// Marshal proto response to JSON
	marshaler := protojson.MarshalOptions{
		UseProtoNames: true, // Use snake_case (proto field names) instead of camelCase
	}
	responseJSON, err := marshaler.Marshal(responseMsg)
	if err != nil {
		s.logger.Error("failed to marshal proto response to JSON", "error", err, "tool", req.Name)

		// Flight recorder completeness (ADR-0131): the tool DID run — this
		// is a post-execution failure, not a pre-dispatch validation error —
		// so it must still reach the sink. Without this, a tool that produced
		// a real (unmarshalable) result leaves no independent record at all,
		// which is exactly the unrecorded path the completeness guard exists
		// to catch.
		callID := s.captureToolCall(ctx, req.Context, toolCallID, req.Name, string(req.InputJson), "", fmt.Sprintf("failed to marshal response: %v", err))

		return &harnesspb.CallToolProtoResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: fmt.Sprintf("failed to marshal response: %v", err),
			},
			ToolCallId: callID,
		}, nil
	}

	// Publish tool.call.completed event
	s.publishEvent(ctx, "tool.call.completed", map[string]interface{}{
		"tool_name":      req.Name,
		"mission_id":     req.Context.MissionId,
		"agent_name":     req.Context.AgentName,
		"task_id":        callerTask(ctx, req.Context),
		"parent_span_id": req.Context.SpanId,
	})

	// Discovery compliance (gibson#625). A tool the catalog says emits a
	// DiscoveryResult, whose response carries none, produced no graph nodes —
	// which is how a parser that quietly stopped emitting them looks. Recorded
	// as a metric and a warning, never a failure: the tool DID run, and its
	// output is already on its way to the Timeline below.
	//
	// Measured here because this is the only place that holds both the tool
	// name and the response proto. Before it, the validator had no caller at
	// all, so gibson_tool_discovery_compliance_total and
	// gibson_tool_extraction_skipped_total were exported and always zero —
	// indistinguishable from "nothing was ever skipped".
	s.validator().ValidateDiscoveryCompliance(ctx, req.Name, responseMsg, req.Context.GetMissionRunId())

	// Flight recorder (ADR-0120, gibson#271): capture the full arguments +
	// result — the tool-I/O half of the flight recorder, alongside the LLM
	// transcript half captureLLMCall already folds in. Before this, tool I/O
	// only reached the daemon as bare tool.call.* pub/sub metadata (no
	// arguments/result text) and never became part of the Timeline.
	callID := s.captureToolCall(ctx, req.Context, toolCallID, req.Name, string(req.InputJson), string(responseJSON), "")

	// Discovery runs after the call is recorded. The parser evidence of the
	// discovery cites the recorded call, so the record has to exist before the
	// goroutine starts.
	if s.discoveryProcessor != nil {
		if pbDiscovery := sdkgraphrag.ExtractDiscovery(responseMsg); pbDiscovery != nil {
			execCtx := callToolDiscoveryScope(ctx, req.Context)
			// The discovery names the one id of this call, so the processor
			// finds the record that is written above.
			execCtx.ToolExecutionID = toolCallID

			// Process discovery asynchronously with timeout
			// This doesn't block the tool response
			// NOTE: Now passing proto directly (proto-first approach)
			go func() {
				processCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
				defer cancel()

				result, err := s.discoveryProcessor.Process(processCtx, execCtx, pbDiscovery)
				if err != nil {
					s.logger.ErrorContext(processCtx, "failed to process discovery",
						"error", err,
						"tool", req.Name,
						"mission_run_id", execCtx.MissionRunID,
					)
				} else if result != nil {
					// Log success (result type varies by processor implementation)
					s.logger.DebugContext(processCtx, "discovery processed successfully",
						"tool", req.Name,
						"mission_run_id", execCtx.MissionRunID,
					)
				}
			}()
		}
	}

	return &harnesspb.CallToolProtoResponse{
		OutputJson: responseJSON,
		ToolCallId: callID,
	}, nil
}

// ListTools implements the tool listing RPC.
func (s *HarnessCallbackService) ListTools(ctx context.Context, req *harnesspb.ListToolsRequest) (*harnesspb.ListToolsResponse, error) {
	harness, err := s.getHarness(ctx, req.Context)
	if err != nil {
		return nil, err
	}

	// Get tool descriptors
	tools := harness.ListTools()

	// At MCP catalog scale the agent does not see the full tool set as native
	// functions; it sees the two meta-tools and discovers via search_tools
	// (ADR-0065). Advertise them only when the catalog is wired.
	if s.metaToolsWired() {
		tools = append(tools, metaToolDescriptors()...)
	}

	// Convert to proto with structured schemas (including taxonomy)
	protoTools := make([]*harnesspb.HarnessToolDescriptor, len(tools))
	for i, tool := range tools {
		protoTools[i] = &harnesspb.HarnessToolDescriptor{
			Name:        tool.Name,
			Description: tool.Description,
			InputSchema: SchemaToCallbackProto(tool.InputSchema), // Structured schema with taxonomy
		}
	}

	return &harnesspb.ListToolsResponse{
		Tools: protoTools,
	}, nil
}

// QueueToolWork implements the queue-based parallel tool execution RPC.
// It queues multiple tool invocations to Redis for processing by distributed workers.
func (s *HarnessCallbackService) QueueToolWork(ctx context.Context, req *harnesspb.QueueToolWorkRequest) (*harnesspb.QueueToolWorkResponse, error) {
	// Check if queue manager is available
	if s.queueManager == nil {
		s.logger.Error("queue manager not configured", "tool", req.ToolName)
		return &harnesspb.QueueToolWorkResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: "queue-based tool execution not available (Redis not configured)",
			},
		}, nil
	}

	// Publish tool.queue.started event
	s.publishEvent(ctx, "tool.queue.started", map[string]interface{}{
		"tool_name":      req.ToolName,
		"mission_id":     req.Context.MissionId,
		"agent_name":     req.Context.AgentName,
		"task_id":        callerTask(ctx, req.Context),
		"parent_span_id": req.Context.SpanId,
		"input_type":     req.InputType,
		"output_type":    req.OutputType,
		"input_count":    len(req.InputJsons),
	})

	// Generate UUID for job ID
	jobID := uuid.New().String()

	// Get queue client
	queueClient := s.queueManager.Client()

	// Validate tool exists by checking Redis tools:available set
	availableTools, err := queueClient.ListTools(ctx)
	if err != nil {
		s.logger.Error("failed to list available tools", "error", err)
		return &harnesspb.QueueToolWorkResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: fmt.Sprintf("failed to check tool availability: %v", err),
			},
		}, nil
	}

	// Check if requested tool is available
	toolFound := false
	for _, tool := range availableTools {
		if tool.Name == req.ToolName {
			toolFound = true
			break
		}
	}

	if !toolFound {
		s.logger.Warn("tool not found in queue", "tool", req.ToolName, "available", len(availableTools))
		return &harnesspb.QueueToolWorkResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_NOT_FOUND,
				Message: fmt.Sprintf("tool %s not available in queue (no workers registered)", req.ToolName),
			},
		}, nil
	}

	// Extract trace context from current span
	var traceID, spanID string
	if span := trace.SpanFromContext(ctx); span.SpanContext().IsValid() {
		spanCtx := span.SpanContext()
		traceID = spanCtx.TraceID().String()
		spanID = spanCtx.SpanID().String()
	}

	// Current timestamp for submitted_at
	submittedAt := time.Now().UnixMilli()

	// Queue name for this tool
	queueName := fmt.Sprintf("tool:%s:queue", req.ToolName)

	// Push work items to Redis queue
	total := len(req.InputJsons)
	for i, inputJSON := range req.InputJsons {
		workItem := queue.WorkItem{
			JobID:       jobID,
			Index:       i,
			Total:       total,
			Tool:        req.ToolName,
			InputJSON:   inputJSON,
			InputType:   req.InputType,
			OutputType:  req.OutputType,
			TraceID:     traceID,
			SpanID:      spanID,
			SubmittedAt: submittedAt,
		}

		// Validate work item before pushing
		if err := workItem.IsValid(); err != nil {
			s.logger.Error("invalid work item", "error", err, "index", i)
			return &harnesspb.QueueToolWorkResponse{
				Error: &harnesspb.HarnessError{
					Code:    commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
					Message: fmt.Sprintf("invalid work item at index %d: %v", i, err),
				},
			}, nil
		}

		// Push to queue
		if err := queueClient.Push(ctx, queueName, workItem); err != nil {
			s.logger.Error("failed to push work item to queue",
				"error", err,
				"tool", req.ToolName,
				"job_id", jobID,
				"index", i,
			)
			return &harnesspb.QueueToolWorkResponse{
				Error: &harnesspb.HarnessError{
					Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
					Message: fmt.Sprintf("failed to queue work item %d: %v", i, err),
				},
			}, nil
		}

		// Record the call now. The tool name and the arguments are known at
		// submit time. The result joins the record when it arrives, under the
		// same id (ToolResults).
		s.captureToolCall(ctx, req.Context, queuedToolCallID(jobID, i), req.ToolName, string(inputJSON), "", "")
	}

	s.logger.Info("queued tool work",
		"tool", req.ToolName,
		"job_id", jobID,
		"count", total,
		"queue", queueName,
	)

	return &harnesspb.QueueToolWorkResponse{
		JobId: jobID,
	}, nil
}

// queuedToolCallNamespace is the UUID namespace of the ids of queued tool calls.
var queuedToolCallNamespace = uuid.MustParse("6f1c7d52-3a0e-4b9a-9c1e-5d2b8a4e7f10")

// queuedToolCallID returns the id of the tool call that one input of a queued
// job stands for. The id depends only on the job and the index. QueueToolWork
// records the call under it at submit time, and ToolResults returns it with
// the result, so the two need no shared state.
func queuedToolCallID(jobID string, index int) string {
	return uuid.NewSHA1(queuedToolCallNamespace, []byte(fmt.Sprintf("%s/%d", jobID, index))).String()
}

// ToolResults implements the streaming RPC that delivers results from queued tool work.
// It subscribes to the Redis pub/sub channel for the job and streams results as they arrive.
func (s *HarnessCallbackService) ToolResults(req *harnesspb.ToolResultsRequest, stream harnesspb.HarnessCallbackService_ToolResultsServer) error {
	ctx := stream.Context()

	// Check if queue manager is available
	if s.queueManager == nil {
		s.logger.Error("queue manager not configured for ToolResults")
		return status.Error(codes.Internal, "queue-based tool execution not available (Redis not configured)")
	}

	jobID := req.JobId
	if jobID == "" {
		s.logger.Error("missing job_id in ToolResults request")
		return status.Error(codes.InvalidArgument, "job_id is required")
	}

	s.logger.Info("starting ToolResults stream",
		"job_id", jobID,
		"mission_id", req.Context.MissionId,
		"agent_name", req.Context.AgentName,
	)

	// Subscribe to job results channel
	channel := fmt.Sprintf("results:%s", jobID)
	queueClient := s.queueManager.Client()
	resultChan, err := queueClient.Subscribe(ctx, channel)
	if err != nil {
		s.logger.Error("failed to subscribe to results channel",
			"error", err,
			"job_id", jobID,
			"channel", channel,
		)
		return status.Errorf(codes.Internal, "failed to subscribe to results: %v", err)
	}

	s.logger.Info("subscribed to results channel",
		"job_id", jobID,
		"channel", channel,
	)

	// Stream results as they arrive
	// The channel is closed when context is cancelled, so we don't need to track total
	resultCount := 0
	for result := range resultChan {
		resultCount++

		// Convert queue.Result to proto ToolResultResponse
		// The id is the one that QueueToolWork recorded for this input.
		toolCallID := queuedToolCallID(jobID, result.Index)
		protoResult := &harnesspb.ToolResultsResponse{
			Index:      boundedInt32(result.Index),
			ToolCallId: toolCallID,
		}

		if result.Error != "" {
			protoResult.Error = &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: result.Error,
			}
		} else {
			protoResult.OutputJson = result.OutputJSON
		}

		// Add the result to the record of the call.
		s.captureToolCall(ctx, req.Context, toolCallID, "", "", string(result.OutputJSON), result.Error)

		// Send result to stream
		if err := stream.Send(protoResult); err != nil {
			s.logger.Error("failed to send result to stream",
				"error", err,
				"job_id", jobID,
				"index", result.Index,
			)
			return err
		}

		s.logger.Debug("sent result to stream",
			"job_id", jobID,
			"index", result.Index,
			"result_count", resultCount,
		)
	}

	s.logger.Info("ToolResults stream closed",
		"job_id", jobID,
		"results_sent", resultCount,
	)

	return nil
}

// ============================================================================
// Plugin Operations
// ============================================================================

// QueryPlugin implements the plugin query RPC.
func (s *HarnessCallbackService) QueryPlugin(ctx context.Context, req *harnesspb.QueryPluginRequest) (*harnesspb.QueryPluginResponse, error) {
	harness, err := s.getHarness(ctx, req.Context)
	if err != nil {
		return nil, err
	}

	// Mission-level blocked_tools denial on the direct plugin-invocation path,
	// matched by the canonical connector id (mcp:<name>:<method>) and the bare
	// connector name. Without this, a PLUGIN node or an agent calling QueryPlugin
	// directly would sidestep the invoke_tool deny check — so enforce here too.
	// The list comes from the stored mission, and an unreadable list refuses.
	blockedTools, blockedErr := s.storedBlockedTools(ctx, req.Context)
	if blockedErr != nil {
		s.logger.ErrorContext(ctx, "plugin query refused: the mission deny list could not be read", "plugin", req.Name, "err", blockedErr)
		return &harnesspb.QueryPluginResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE,
				Message: "the mission policy could not be loaded",
			},
		}, nil
	}
	if blockedID, blockedOK := metatool.MatchBlocked(blockedTools, "mcp:"+req.Name+":"+req.Method, req.Name); blockedOK {
		return &harnesspb.QueryPluginResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED,
				Message: fmt.Sprintf("tool '%s' is blocked by mission policy", blockedID),
			},
		}, nil
	}

	// Convert params from proto map to Go map
	params := typedValueMapToMap(req.Params)

	// Query plugin
	result, err := harness.QueryPlugin(ctx, req.Name, req.Method, params)
	if err != nil {
		s.logger.Error("plugin query failed", "error", err, "plugin", req.Name, "method", req.Method)
		return &harnesspb.QueryPluginResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: err.Error(),
			},
		}, nil
	}

	return &harnesspb.QueryPluginResponse{
		Result: anyToTypedValue(result),
	}, nil
}

// ListPlugins implements the plugin listing RPC.
func (s *HarnessCallbackService) ListPlugins(ctx context.Context, req *harnesspb.ListPluginsRequest) (*harnesspb.ListPluginsResponse, error) {
	harness, err := s.getHarness(ctx, req.Context)
	if err != nil {
		return nil, err
	}

	// Get plugin descriptors
	plugins := harness.ListPlugins()

	// Convert to proto
	protoPlugins := make([]*harnesspb.HarnessPluginDescriptor, len(plugins))
	for i, plugin := range plugins {
		// Extract method names from MethodDescriptor slice
		methodNames := make([]string, len(plugin.Methods))
		for j, method := range plugin.Methods {
			methodNames[j] = method.Name
		}

		protoPlugins[i] = &harnesspb.HarnessPluginDescriptor{
			Name:        plugin.Name,
			Description: "",
			Version:     plugin.Version,
			Methods:     methodNames,
		}
	}

	return &harnesspb.ListPluginsResponse{
		Plugins: protoPlugins,
	}, nil
}

// ============================================================================
// Agent Operations
// ============================================================================

// ============================================================================
// Finding Operations
// ============================================================================

// SubmitFinding implements the finding submission RPC.
func (s *HarnessCallbackService) SubmitFinding(ctx context.Context, req *harnesspb.SubmitFindingRequest) (*harnesspb.SubmitFindingResponse, error) {
	harness, err := s.getHarness(ctx, req.Context)
	if err != nil {
		return nil, err
	}

	// Convert proto Finding to internal Finding
	finding := protoFindingToFinding(req.Finding)
	// A finding with an idempotency key has a stable identity: the same key
	// from the same agent in the same tenant names the same finding, so a
	// second read of one result of a tool of the buyer updates it
	// (gibson#1448). The daemon still authors the name: it is a hash, and the
	// agent cannot pick the id of a finding of another agent.
	if key := req.GetIdempotencyKey(); key != "" {
		id, err := auth.IdentityFromContext(ctx)
		if err != nil || id.Subject == "" {
			return nil, status.Error(codes.Unauthenticated, "SubmitFinding: an idempotency key needs an authenticated caller")
		}
		finding.ID = findingpkg.ResultID(auth.TenantStringFromContext(ctx), id.Subject, key)
	}

	// Tier 1 evidence comes from the record of each tool call that the agent
	// names. An ID that names no record of this mission and tenant fails the
	// whole submit, before the daemon stores anything.
	recorded, refusal, err := s.recordedFindingEvidence(ctx, harness.Mission().ID.String(), req.GetToolCallIds())
	if err != nil {
		return nil, err
	}
	if refusal != nil {
		return &harnesspb.SubmitFindingResponse{Error: refusal}, nil
	}
	finding.Evidence = append(recorded, finding.Evidence...)

	// Submit finding
	if err := harness.SubmitFinding(ctx, finding); err != nil {
		// An emit-bounds rejection is the caller's fault, not the daemon's,
		// and it is the one failure here that guarantees nothing was
		// written (ADR-0112, "Write contract"). Report it as invalid
		// argument so the emitter can tell "your payload is too big" from
		// "the daemon broke".
		if errors.Is(err, emitbounds.ErrLimitExceeded) {
			s.logger.Warn("finding rejected by emit bounds", "error", err)
			return &harnesspb.SubmitFindingResponse{
				Error: &harnesspb.HarnessError{
					Code:    commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
					Message: err.Error(),
				},
			}, nil
		}
		// An evidence item over the size limit is the fault of the caller. The
		// store wrote nothing, and it never truncates.
		if evidenceRejected(err) {
			s.logger.Warn("finding rejected for its evidence", "error", err)
			return &harnesspb.SubmitFindingResponse{
				Error: &harnesspb.HarnessError{
					Code:    commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
					Message: err.Error(),
				},
			}, nil
		}
		// The cause can name the database. It stays in the log, and the agent
		// gets a fixed message.
		s.logger.Error("finding submission failed", "error", err)
		message := "the finding could not be stored. Try again"
		var notProvisioned *datapool.NotProvisionedError
		if errors.As(err, &notProvisioned) {
			message = "the data plane of the tenant is not ready, so the finding was not stored"
		}
		return &harnesspb.SubmitFindingResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE,
				Message: message,
			},
		}, nil
	}

	return &harnesspb.SubmitFindingResponse{}, nil
}

// recordedFindingEvidence builds the tier 1 evidence of a finding from the
// tool calls that the agent names. It returns a HarnessError when an ID names
// no record of the mission of the caller in the tenant of the caller. It
// returns a gRPC error when the request is malformed or the daemon cannot read
// its record. An empty list of IDs gives no evidence and no error.
func (s *HarnessCallbackService) recordedFindingEvidence(
	ctx context.Context, missionID string, toolCallIDs []string,
) ([]*typespb.Evidence, *harnesspb.HarnessError, error) {
	evidence, missing, err := s.recordedEvidence(ctx, missionID, toolCallIDs)
	if err != nil {
		return nil, nil, err
	}
	if len(missing) > 0 {
		return nil, &harnesspb.HarnessError{
			Code: commonpb.ErrorCode_ERROR_CODE_NOT_FOUND,
			Message: fmt.Sprintf(
				"SubmitFinding: the daemon holds no record of tool call %q for this mission", missing[0]),
		}, nil
	}
	return evidence, nil, nil
}

// recordedEvidence reads the record of tool calls for a proof and for a
// finding. It calls brain.ReadRecordedEvidence, the one function that the
// component path also calls, and maps its errors to gRPC status errors.
func (s *HarnessCallbackService) recordedEvidence(
	ctx context.Context, missionID string, toolCallIDs []string,
) (evidence []*typespb.Evidence, missing []string, err error) {
	if len(toolCallIDs) == 0 {
		return nil, nil, nil
	}
	if s.proofSettlement == nil {
		return nil, nil, status.Error(codes.Unavailable,
			"the record of tool calls is not wired on this daemon")
	}
	evidence, missing, err = brain.ReadRecordedEvidence(ctx, s.proofSettlement, missionID, toolCallIDs)
	switch {
	case errors.Is(err, brain.ErrTooManyToolCalls):
		return nil, nil, status.Errorf(codes.InvalidArgument, "tool_call_ids: %v", err)
	case err != nil:
		return nil, nil, status.Errorf(codes.Internal, "%v", err)
	}
	return evidence, missing, nil
}

// ============================================================================
// Memory Operations
// ============================================================================

// ============================================================================
// GraphRAG Query Operations
// ============================================================================

// ============================================================================
// GraphRAG Storage Operations
// ============================================================================

// ============================================================================
// Distributed Tracing Operations
// ============================================================================

// RecordSpan implements the span recording RPC for distributed tracing.
// It receives spans from remote agents and forwards them to registered span processors.
func (s *HarnessCallbackService) RecordSpan(ctx context.Context, req *harnesspb.RecordSpanRequest) (*harnesspb.RecordSpanResponse, error) {
	if req.Span == nil {
		return &harnesspb.RecordSpanResponse{}, nil
	}

	// Convert proto span to span data and export
	spanData := s.protoToSpanData(req.Span)
	s.exportSpanData(spanData)

	return &harnesspb.RecordSpanResponse{}, nil
}

// RecordSpans implements the batch span recording RPC for distributed tracing.
// It receives multiple spans from remote agents and forwards them to registered span processors.
func (s *HarnessCallbackService) RecordSpans(ctx context.Context, req *harnesspb.RecordSpansRequest) (*harnesspb.RecordSpansResponse, error) {
	for _, protoSpan := range req.Spans {
		if protoSpan == nil {
			continue
		}

		// Convert proto span to span data and export
		spanData := s.protoToSpanData(protoSpan)
		s.exportSpanData(spanData)
	}

	return &harnesspb.RecordSpansResponse{}, nil
}

// exportSpanData creates a real span using the TracerProvider and immediately ends it.
// This allows the span to be processed by registered span processors.
func (s *HarnessCallbackService) exportSpanData(data *proxySpanData) {
	if data == nil || s.tracerProvider == nil {
		return
	}

	// Create parent context with the original trace context
	parentCtx := trace.ContextWithSpanContext(context.Background(), data.Parent)

	// Get tracer from the provider
	tracer := s.tracerProvider.Tracer("gibson-agent-proxy")

	// Create span with original attributes and timing
	_, span := tracer.Start(parentCtx, data.Name,
		trace.WithSpanKind(data.SpanKind),
		trace.WithTimestamp(data.StartTime),
		trace.WithAttributes(data.Attributes...),
	)

	// Add events
	for _, event := range data.Events {
		span.AddEvent(event.Name, trace.WithTimestamp(event.Time), trace.WithAttributes(event.Attributes...))
	}

	// Set status
	span.SetStatus(otelcodes.Code(data.Status.Code), data.Status.Description)

	// End span with original end time
	span.End(trace.WithTimestamp(data.EndTime))
}

// ============================================================================
// Helper Methods for Proto Conversions
// ============================================================================

// protoToSpanData converts a proto Span to a proxySpanData container.
// Since sdktrace.ReadOnlySpan has an unexported method, we can't implement it directly.
// Instead, we extract the data and export it directly via the OTLP exporter.
func (s *HarnessCallbackService) protoToSpanData(protoSpan *harnesspb.Span) *proxySpanData {
	// Parse trace ID and span ID from hex strings
	var traceID trace.TraceID
	var spanID trace.SpanID
	var parentSpanID trace.SpanID

	// Convert hex string to TraceID (16 bytes)
	if len(protoSpan.TraceId) == 32 {
		for i := 0; i < 16; i++ {
			_, _ = fmt.Sscanf(protoSpan.TraceId[i*2:i*2+2], "%02x", &traceID[i])
		}
	}

	// Convert hex string to SpanID (8 bytes)
	if len(protoSpan.SpanId) == 16 {
		for i := 0; i < 8; i++ {
			_, _ = fmt.Sscanf(protoSpan.SpanId[i*2:i*2+2], "%02x", &spanID[i])
		}
	}

	// Convert parent span ID if present
	hasParent := false
	if len(protoSpan.ParentSpanId) == 16 {
		hasParent = true
		for i := 0; i < 8; i++ {
			_, _ = fmt.Sscanf(protoSpan.ParentSpanId[i*2:i*2+2], "%02x", &parentSpanID[i])
		}
	}

	// Create span context
	spanContext := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: traceID,
		SpanID:  spanID,
	})

	// Create parent span context
	var parentContext trace.SpanContext
	if hasParent {
		parentContext = trace.NewSpanContext(trace.SpanContextConfig{
			TraceID: traceID,
			SpanID:  parentSpanID,
		})
	}

	// Create proxy span data container
	return s.createProxySpanData(
		protoSpan.Name,
		spanContext,
		parentContext,
		s.protoSpanKindToOtel(protoSpan.Kind),
		time.Unix(0, protoSpan.StartTimeUnixNano),
		time.Unix(0, protoSpan.EndTimeUnixNano),
		s.protoAttributesToOtel(protoSpan.Attributes),
		s.protoEventsToOtel(protoSpan.Events),
		sdktrace.Status{
			Code:        s.protoStatusCodeToOtel(protoSpan.StatusCode),
			Description: protoSpan.StatusMessage,
		},
	)
}

// protoSpanKindToOtel converts proto SpanKind to OpenTelemetry SpanKind.
func (s *HarnessCallbackService) protoSpanKindToOtel(kind harnesspb.SpanKind) trace.SpanKind {
	switch kind {
	case harnesspb.SpanKind_SPAN_KIND_INTERNAL:
		return trace.SpanKindInternal
	case harnesspb.SpanKind_SPAN_KIND_SERVER:
		return trace.SpanKindServer
	case harnesspb.SpanKind_SPAN_KIND_CLIENT:
		return trace.SpanKindClient
	case harnesspb.SpanKind_SPAN_KIND_PRODUCER:
		return trace.SpanKindProducer
	case harnesspb.SpanKind_SPAN_KIND_CONSUMER:
		return trace.SpanKindConsumer
	default:
		return trace.SpanKindUnspecified
	}
}

// protoStatusCodeToOtel converts proto StatusCode to OpenTelemetry status code.
func (s *HarnessCallbackService) protoStatusCodeToOtel(code harnesspb.StatusCode) otelcodes.Code {
	switch code {
	case harnesspb.StatusCode_STATUS_CODE_OK:
		return otelcodes.Ok
	case harnesspb.StatusCode_STATUS_CODE_ERROR:
		return otelcodes.Error
	default:
		return otelcodes.Unset
	}
}

// protoAttributesToOtel converts proto KeyValue attributes to OpenTelemetry attributes.
func (s *HarnessCallbackService) protoAttributesToOtel(protoAttrs []*harnesspb.KeyValue) []attribute.KeyValue {
	attrs := make([]attribute.KeyValue, 0, len(protoAttrs))
	for _, protoAttr := range protoAttrs {
		if protoAttr.Value == nil {
			continue
		}

		key := attribute.Key(protoAttr.Key)
		// Handle different value types from AnyValue
		switch v := protoAttr.Value.Value.(type) {
		case *harnesspb.AnyValue_StringValue:
			attrs = append(attrs, key.String(v.StringValue))
		case *harnesspb.AnyValue_BoolValue:
			attrs = append(attrs, key.Bool(v.BoolValue))
		case *harnesspb.AnyValue_IntValue:
			attrs = append(attrs, key.Int64(v.IntValue))
		case *harnesspb.AnyValue_DoubleValue:
			attrs = append(attrs, key.Float64(v.DoubleValue))
		}
	}
	return attrs
}

// protoEventsToOtel converts proto SpanEvents to OpenTelemetry Events.
func (s *HarnessCallbackService) protoEventsToOtel(protoEvents []*harnesspb.SpanEvent) []sdktrace.Event {
	events := make([]sdktrace.Event, len(protoEvents))
	for i, protoEvent := range protoEvents {
		events[i] = sdktrace.Event{
			Name:       protoEvent.Name,
			Time:       time.Unix(0, protoEvent.TimeUnixNano),
			Attributes: s.protoAttributesToOtel(protoEvent.Attributes),
		}
	}
	return events
}

// ============================================================================
// Span Data Container
// ============================================================================

// proxySpanData contains the data extracted from a proto span for export.
// Since sdktrace.ReadOnlySpan has an unexported private() method that prevents
// external implementation, we store the span data and export directly via OTLP.
type proxySpanData struct {
	Name        string
	SpanContext trace.SpanContext
	Parent      trace.SpanContext
	SpanKind    trace.SpanKind
	StartTime   time.Time
	EndTime     time.Time
	Attributes  []attribute.KeyValue
	Events      []sdktrace.Event
	Status      sdktrace.Status
}

// createProxySpanData creates a proxySpanData from the proto span data.
func (s *HarnessCallbackService) createProxySpanData(
	name string,
	spanContext trace.SpanContext,
	parent trace.SpanContext,
	spanKind trace.SpanKind,
	startTime time.Time,
	endTime time.Time,
	attributes []attribute.KeyValue,
	events []sdktrace.Event,
	status sdktrace.Status,
) *proxySpanData {
	return &proxySpanData{
		Name:        name,
		SpanContext: spanContext,
		Parent:      parent,
		SpanKind:    spanKind,
		StartTime:   startTime,
		EndTime:     endTime,
		Attributes:  attributes,
		Events:      events,
		Status:      status,
	}
}

// ============================================================================
// Credential Operations
// ============================================================================

// GetCredential retrieves a credential by name from the credential store.
// The credential is decrypted and returned with its secret value.
func (s *HarnessCallbackService) GetCredential(ctx context.Context, req *harnesspb.GetCredentialRequest) (*harnesspb.GetCredentialResponse, error) {
	// Per-secret authorization FIRST — before request validation, before the
	// store is touched, and before anything about the named credential is
	// revealed. gibson#1245: this RPC previously had no per-secret decision at
	// EITHER layer (the callback listener is not fronted by ext-authz, and the
	// handler did a bare store read), so any caller that reached it could read
	// any secret in its header-asserted tenant.
	if err := s.authorizeCredentialResolve(ctx, req.GetName()); err != nil {
		return nil, err
	}

	// req.Context (mission_id / agent_name) is used ONLY for the debug log
	// below: resolution is scoped by tenant (from ctx) + req.Name, and
	// authorization is the can_resolve check above — neither needs it. An
	// agent/harness caller always sends a Context, but a first-party plugin
	// resolving its OWN declared startup secret has no mission and no agent, so
	// its Context is legitimately nil (ADR-0066). Tolerate it rather than fail
	// closed on a field that does not gate the decision.
	var missionID, agentName string
	if req.Context != nil {
		missionID, agentName = req.Context.MissionId, req.Context.AgentName
	}
	s.logger.Debug("GetCredential request",
		"name", req.Name,
		"mission_id", missionID,
		"agent_name", agentName,
	)

	// Check if credential store is configured
	if s.credentialStore == nil {
		s.logger.Warn("GetCredential called but credential store not configured")
		return &harnesspb.GetCredentialResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE,
				Message: "credential store not available",
			},
		}, nil
	}

	// Retrieve credential. DaemonCredentialStore delegates to secrets.Service
	// which returns gRPC status errors. Map them to the appropriate HarnessError
	// code so callers can distinguish not-found from service-unavailable.
	cred, secret, err := s.credentialStore.GetCredential(ctx, req.Name)
	if err != nil {
		s.logger.Warn("GetCredential failed", "name", req.Name, "error", err)
		errCode := commonpb.ErrorCode_ERROR_CODE_NOT_FOUND
		if st, ok := status.FromError(err); ok {
			switch st.Code() {
			case codes.Unavailable:
				errCode = commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE
			case codes.PermissionDenied:
				errCode = commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED
			case codes.InvalidArgument:
				errCode = commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT
			case codes.NotFound:
				errCode = commonpb.ErrorCode_ERROR_CODE_NOT_FOUND
			default:
				errCode = commonpb.ErrorCode_ERROR_CODE_INTERNAL
			}
		}
		return &harnesspb.GetCredentialResponse{
			Error: &harnesspb.HarnessError{
				Code:    errCode,
				Message: fmt.Sprintf("credential %q: %v", req.Name, err),
			},
		}, nil
	}

	// Map internal credential type to proto type
	var credType harnesspb.CredentialType
	switch cred.Type {
	case types.CredentialTypeAPIKey:
		credType = harnesspb.CredentialType_CREDENTIAL_TYPE_API_KEY
	case types.CredentialTypeBearer:
		credType = harnesspb.CredentialType_CREDENTIAL_TYPE_BEARER
	case types.CredentialTypeBasic:
		credType = harnesspb.CredentialType_CREDENTIAL_TYPE_BASIC
	case types.CredentialTypeOAuth:
		credType = harnesspb.CredentialType_CREDENTIAL_TYPE_OAUTH
	case types.CredentialTypeCustom:
		credType = harnesspb.CredentialType_CREDENTIAL_TYPE_CUSTOM
	default:
		credType = harnesspb.CredentialType_CREDENTIAL_TYPE_API_KEY
	}

	s.logger.Debug("GetCredential succeeded", "name", req.Name)

	// Build credential with oneof secret_data based on type
	pbCred := &harnesspb.Credential{
		Name:     cred.Name,
		Type:     credType,
		Metadata: mapToTypedValueMap(map[string]any{"provider": cred.Provider, "tags": cred.Tags}),
	}

	// Set secret using oneof field based on credential type
	switch credType {
	case harnesspb.CredentialType_CREDENTIAL_TYPE_API_KEY:
		pbCred.SecretData = &harnesspb.Credential_ApiKey{ApiKey: secret}
	case harnesspb.CredentialType_CREDENTIAL_TYPE_BEARER:
		pbCred.SecretData = &harnesspb.Credential_BearerToken{BearerToken: secret}
	case harnesspb.CredentialType_CREDENTIAL_TYPE_CUSTOM:
		pbCred.SecretData = &harnesspb.Credential_CustomSecret{CustomSecret: secret}
	default:
		pbCred.SecretData = &harnesspb.Credential_ApiKey{ApiKey: secret}
	}

	return &harnesspb.GetCredentialResponse{
		Credential: pbCred,
	}, nil
}

// ============================================================================
// Helper Methods for Taxonomy Engine Integration
// ============================================================================

// requireEventBus stops a constructor that got no event bus (gibson#681). A
// callback service without one drops each tool and LLM event, and the
// execution graph then shows a run that did nothing.
func requireEventBus(s *HarnessCallbackService) {
	if s.eventBus == nil {
		panic("harness: the callback service requires an event bus (WithEventBus)")
	}
}

// publishEvent publishes an event to the event bus. This is a helper method
// that publishes events without blocking callback responses. Events are
// published in a goroutine to avoid latency.
func (s *HarnessCallbackService) publishEvent(ctx context.Context, eventType string, data map[string]interface{}) {
	// Extract trace context from OpenTelemetry span
	var traceID, spanID, parentSpanID string
	if span := trace.SpanFromContext(ctx); span.SpanContext().IsValid() {
		spanCtx := span.SpanContext()
		traceID = spanCtx.TraceID().String()
		spanID = spanCtx.SpanID().String()
	}

	// Extract parent_span_id from data if provided (for relationship creation)
	// This is passed explicitly by callers who know their parent span
	if psid, ok := data["parent_span_id"].(string); ok {
		parentSpanID = psid
	}

	// IMPORTANT: Add trace context to data map for taxonomy engine
	// The taxonomy engine reads from data map, not the event struct fields
	// This ensures LLMCall, ToolExecution nodes can create relationships
	timestamp := time.Now()
	data["trace_id"] = traceID
	data["span_id"] = spanID
	data["parent_span_id"] = parentSpanID
	data["timestamp"] = timestamp.Format(time.RFC3339Nano)

	// Create event structure matching daemon.GraphEvent
	event := struct {
		Type         string
		TraceID      string
		SpanID       string
		ParentSpanID string
		Timestamp    time.Time
		Data         map[string]interface{}
	}{
		Type:         eventType,
		TraceID:      traceID,
		SpanID:       spanID,
		ParentSpanID: parentSpanID,
		Timestamp:    timestamp,
		Data:         data,
	}

	// Publish in background to avoid blocking the callback response
	// Use timeout context to prevent goroutine leaks while still allowing
	// publish to complete after request context is cancelled
	go func() {
		pubCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := s.eventBus.Publish(pubCtx, event); err != nil {
			// Don't log context.Canceled - expected when request is cancelled
			if !errors.Is(err, context.Canceled) {
				s.logger.Warn("failed to publish event",
					"event_type", eventType,
					"error", err,
				)
			}
		}
	}()
}

// ============================================================================
// Taxonomy Operations
// ============================================================================

// GetTaxonomySchema returns the full taxonomy schema to agents.
// NOTE: Taxonomy has been removed. This returns an empty response.
func (s *HarnessCallbackService) GetTaxonomySchema(ctx context.Context, req *harnesspb.GetTaxonomySchemaRequest) (*harnesspb.GetTaxonomySchemaResponse, error) {
	s.logger.Debug("GetTaxonomySchema called (taxonomy removed)")
	return &harnesspb.GetTaxonomySchemaResponse{
		Version: "0.0.0",
	}, nil
}

// GenerateNodeID generates a deterministic node ID.
// NOTE: Taxonomy has been removed. Use domain types instead which generate their own IDs.
func (s *HarnessCallbackService) GenerateNodeID(ctx context.Context, req *harnesspb.GenerateNodeIDRequest) (*harnesspb.GenerateNodeIDResponse, error) {
	s.logger.Debug("GenerateNodeID called (taxonomy removed)")
	return &harnesspb.GenerateNodeIDResponse{
		Error: &harnesspb.HarnessError{
			Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
			Message: "taxonomy has been removed; use domain types which generate their own IDs",
		},
	}, nil
}

// ValidateFinding validates a finding.
// NOTE: Taxonomy-based validation has been removed. Basic validation is still performed.
func (s *HarnessCallbackService) ValidateFinding(ctx context.Context, req *harnesspb.ValidateFindingRequest) (*harnesspb.ValidateFindingResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
	}

	s.logger.Debug("ValidateFinding called")

	// Use the one conversion of a proto finding, the one that SubmitFinding uses.
	if req.Finding == nil {
		return &harnesspb.ValidateFindingResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
				Message: "finding cannot be nil",
			},
		}, nil
	}
	finding := protoFindingToFinding(req.Finding)

	resp := &harnesspb.ValidateFindingResponse{Valid: true}

	// Validate severity
	switch finding.Severity {
	case agent.SeverityCritical, agent.SeverityHigh, agent.SeverityMedium, agent.SeverityLow, agent.SeverityInfo:
	default:
		resp.Valid = false
		resp.Errors = append(resp.Errors, &harnesspb.ValidationError{
			Field:   "severity",
			Message: fmt.Sprintf("invalid severity: %s", finding.Severity),
			Code:    "INVALID_ENUM",
		})
	}

	// Validate required fields
	if finding.Title == "" {
		resp.Valid = false
		resp.Errors = append(resp.Errors, &harnesspb.ValidationError{
			Field:   "title",
			Message: "title is required",
			Code:    "MISSING_REQUIRED",
		})
	}

	s.logger.Debug("ValidateFinding completed", "valid", resp.Valid, "errors", len(resp.Errors))

	return resp, nil
}

// ValidateGraphNode validates a graph node.
// NOTE: Taxonomy-based validation has been removed. Returns success with a warning.
func (s *HarnessCallbackService) ValidateGraphNode(ctx context.Context, req *harnesspb.ValidateGraphNodeRequest) (*harnesspb.ValidateGraphNodeResponse, error) {
	s.logger.Debug("ValidateGraphNode called (taxonomy removed)")
	return &harnesspb.ValidateGraphNodeResponse{
		Valid:    true,
		Warnings: []string{"taxonomy-based validation has been removed; use domain types for type-safe node creation"},
	}, nil
}

// ValidateRelationship validates a relationship.
// NOTE: Taxonomy-based validation has been removed. Returns success with a warning.
func (s *HarnessCallbackService) ValidateRelationship(ctx context.Context, req *harnesspb.ValidateRelationshipRequest) (*harnesspb.ValidateRelationshipResponse, error) {
	s.logger.Debug("ValidateRelationship called (taxonomy removed)")
	return &harnesspb.ValidateRelationshipResponse{
		Valid:    true,
		Warnings: []string{"taxonomy-based validation has been removed; use domain types for type-safe relationship creation"},
	}, nil
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

// typedValueToAny converts a proto TypedValue to a Go any value.
func typedValueToAny(tv *commonpb.TypedValue) any {
	if tv == nil {
		return nil
	}

	switch kind := tv.Kind.(type) {
	case *commonpb.TypedValue_NullValue:
		return nil
	case *commonpb.TypedValue_StringValue:
		return kind.StringValue
	case *commonpb.TypedValue_IntValue:
		return kind.IntValue
	case *commonpb.TypedValue_DoubleValue:
		return kind.DoubleValue
	case *commonpb.TypedValue_BoolValue:
		return kind.BoolValue
	case *commonpb.TypedValue_BytesValue:
		return kind.BytesValue
	case *commonpb.TypedValue_ArrayValue:
		if kind.ArrayValue == nil {
			return []any{}
		}
		result := make([]any, len(kind.ArrayValue.Items))
		for i, item := range kind.ArrayValue.Items {
			result[i] = typedValueToAny(item)
		}
		return result
	case *commonpb.TypedValue_MapValue:
		if kind.MapValue == nil {
			return map[string]any{}
		}
		result := make(map[string]any)
		for k, v := range kind.MapValue.Entries {
			result[k] = typedValueToAny(v)
		}
		return result
	default:
		return nil
	}
}

// ============================================================================
// Proto Conversion Helpers
// ============================================================================

// typedValueMapToMap converts map[string]*TypedValue to map[string]any.
func typedValueMapToMap(m map[string]*commonpb.TypedValue) map[string]any {
	if m == nil {
		return make(map[string]any)
	}

	result := make(map[string]any)
	for k, v := range m {
		result[k] = typedValueToAny(v)
	}
	return result
}

// mapToTypedValueMap converts a map[string]any to a map[string]*commonpb.TypedValue.
func mapToTypedValueMap(m map[string]any) map[string]*commonpb.TypedValue {
	if m == nil {
		return make(map[string]*commonpb.TypedValue)
	}

	result := make(map[string]*commonpb.TypedValue)
	for k, v := range m {
		result[k] = anyToTypedValue(v)
	}
	return result
}

// protoFindingToFinding converts a proto Finding to an internal agent.Finding.
func protoFindingToFinding(pf *typespb.Finding) agent.Finding {
	if pf == nil {
		return agent.Finding{}
	}

	finding := agent.Finding{
		Title:       pf.Title,
		Description: pf.Description,
		Severity:    protoSeverityToAgentSeverity(pf.Severity),
		Confidence:  pf.Confidence,
		Category:    pf.Category,
	}

	// Identity is assigned by the daemon and never read from the payload
	// (ADR-0112, "Entity references are generational handles"; gibson#1259).
	// The emitter is remote and untrusted, and a brain id is enumerable, so
	// honouring pf.Id would let a compromised tool choose the identity its
	// finding lands under — and so attach fabricated evidence to a name
	// another mission's finding already owns. The agent authors the
	// finding's content; the daemon authors its name. The component emit
	// path has always done this (GraphRAGFindingSubmitter.Submit, "assign a
	// canonical finding ID, overwriting any client-supplied ID"); this makes
	// the harness callback path agree.
	finding.ID = types.NewID()

	// Parse TargetID if present
	if pf.TargetId != "" {
		if id, err := uuid.Parse(pf.TargetId); err == nil {
			targetID := types.ID(id.String())
			finding.TargetID = &targetID
		}
	}

	// Evidence that the agent typed is tier 2. The daemon sets the tier and
	// the tool call ID itself. A value that the agent sent for either field is
	// dropped, so an agent cannot claim a tool call that backs an item.
	if len(pf.Evidence) > 0 {
		finding.Evidence = make([]*typespb.Evidence, len(pf.Evidence))
		for i, ev := range pf.Evidence {
			typed := proto.Clone(ev).(*typespb.Evidence)
			typed.Tier = typespb.EvidenceTier_EVIDENCE_TIER_TYPED
			typed.ToolCallId = ""
			finding.Evidence[i] = typed
		}
	}

	// Convert CVSS score if present
	if pf.CvssScore > 0 {
		finding.CVSS = &agent.CVSSScore{
			Score: pf.CvssScore,
			// Vector not available in proto, leave empty
		}
	}

	// Parse timestamp if present
	if pf.CreatedAt > 0 {
		finding.CreatedAt = time.Unix(0, pf.CreatedAt*int64(time.Millisecond))
	} else {
		finding.CreatedAt = time.Now()
	}

	return finding
}

// protoSeverityToAgentSeverity converts proto FindingSeverity to agent.FindingSeverity.
func protoSeverityToAgentSeverity(severity typespb.FindingSeverity) agent.FindingSeverity {
	switch severity {
	case typespb.FindingSeverity_FINDING_SEVERITY_CRITICAL:
		return agent.SeverityCritical
	case typespb.FindingSeverity_FINDING_SEVERITY_HIGH:
		return agent.SeverityHigh
	case typespb.FindingSeverity_FINDING_SEVERITY_MEDIUM:
		return agent.SeverityMedium
	case typespb.FindingSeverity_FINDING_SEVERITY_LOW:
		return agent.SeverityLow
	case typespb.FindingSeverity_FINDING_SEVERITY_INFO:
		return agent.SeverityInfo
	default:
		return agent.SeverityInfo
	}
}

// Observe forwards a typed agent observation to the brain via the observation
// sink (ADR-0107). The brain resolves identity and topology.
//
// Tenant and scope are resolved here, server-side, from the mission record the
// daemon created (ADR-0112). getHarness performs the lookup and refuses a caller
// whose authenticated tenant is not the mission's, so from that point the tenant
// is the mission's own; the scope is the mission's target. Neither is readable
// from the payload — ObserveRequest has no field for either.
//
// The request's mission_id is an address, not an authority: it selects which
// registered harness to consult, and every value that decides where the write
// lands is then read off that harness.
func (s *HarnessCallbackService) Observe(ctx context.Context, req *harnesspb.ObserveRequest) (*harnesspb.ObserveResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "missing observe request")
	}

	// Bounds before the sink, and before the no-op short-circuit below, so an
	// over-limit observation is refused identically whether or not the brain
	// is wired (ADR-0112, "Write contract"). The emitter is remote and
	// untrusted; the wire size is the cap that bounds it, since the typed
	// Observation carries no free-form property map — its unbounded surfaces
	// are its repeated fields and string lengths, all of which the byte cap
	// covers. Rejected, never truncated: nothing reaches the Timeline.
	if err := emitbounds.CheckPayloadBytes(proto.Size(req)); err != nil {
		s.logger.Warn("observation rejected by emit bounds",
			"mission_id", req.GetContext().GetMissionId(),
			"task_id", req.GetContext().GetTaskId(),
			"error", err)
		return &harnesspb.ObserveResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
				Message: err.Error(),
			},
		}, nil
	}
	if err := s.observeCounter().Admit(observeTaskKey(ctx, req.GetContext())); err != nil {
		s.logger.Warn("observation rejected by emit bounds",
			"mission_id", req.GetContext().GetMissionId(),
			"task_id", req.GetContext().GetTaskId(),
			"error", err)
		return &harnesspb.ObserveResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_RESOURCE_EXHAUSTED,
				Message: err.Error(),
			},
		}, nil
	}
	// Resolve the mission record only after the bounds have passed. Attribution
	// needs the harness registry; the bounds deliberately do not, so an
	// over-limit observation is refused identically whether or not the brain is
	// wired — the invariant the caps exist to hold (ADR-0112, "Write contract").
	harness, err := s.getHarness(ctx, req.Context)
	if err != nil {
		return nil, err
	}
	attr, err := observationAttribution(harness)
	if err != nil {
		return nil, err
	}

	ctx = middleware.WithMissionContext(ctx, attr.MissionID, req.Context.AgentName)

	if s.observationSink == nil {
		return &harnesspb.ObserveResponse{}, nil
	}
	if err := s.observationSink(ctx, attr, req); err != nil {
		return &harnesspb.ObserveResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: err.Error(),
			},
		}, nil
	}
	return &harnesspb.ObserveResponse{}, nil
}

// observationAttribution reads the tenant and scope for an emitted observation
// off the daemon's own mission record.
//
// The tenant needs no check here: getHarness has already refused an empty
// mission tenant and any caller whose tenant differs from it.
//
// The scope does. An observation with no resolvable scope is REJECTED, never
// defaulted: an empty ScopeID would make (ScopeID, Address) collapse every
// scanned network onto one coordinate, so 10.0.0.1 on two customers' networks
// would silently become one host. A mission always has a target — target_id is
// required at mission creation (mission.Validate) — so an empty one means the
// mission record is broken, and refusing the write is the only safe reading.
func observationAttribution(h AgentHarness) (ObservationAttribution, error) {
	mission := h.Mission()
	scope := h.Target().ID.String()
	if scope == "" {
		return ObservationAttribution{}, status.Errorf(codes.FailedPrecondition,
			"observation rejected: mission %s has no target, so no scope can be resolved; "+
				"a scope-less observation would merge entities from different networks onto one coordinate",
			mission.ID.String())
	}
	return ObservationAttribution{
		Tenant:    mission.TenantID,
		ScopeID:   scope,
		MissionID: mission.ID.String(),
		RunID:     mission.MissionRunID,
	}, nil
}

// ============================================================================
// Mission Management Operations
// ============================================================================

// CreateMission implements the mission creation RPC: an agent, from inside the
// mission it was dispatched to, originates a child mission.
//
// The parent is mandatory and is resolved through getHarness, never read from
// the request payload (ADR-0063, gibson#1398, gibson#1657). Two properties
// follow, and both are the point:
//
//   - A caller that is not inside a live mission cannot originate at all. A
//     bare component grant reaches this RPC and gets NotFound from the harness
//     registry, because there is no live harness for the mission it names. The
//     ADR's "a component may only originate from inside one it was dispatched
//     to" is therefore enforced by the same lookup every other callback uses,
//     rather than by a second rule that could drift from it.
//   - The parent id, the tenant and the originator are taken from the mission
//     record the daemon created, so a caller cannot name someone else's mission
//     as its parent, cross a tenant, or launder attribution through the wire.
//     This is the same rule the graph writes follow (CONTEXT.md, "Write
//     attribution"): the bar is not that a human was present, it is that every
//     write is attributable to a mission a human approved.
//
// A mission with no parent is refused rather than created ambient. Every bound
// origination has — budget, scope, lineage — is expressed relative to a parent,
// so a parentless child would have no envelope to be clamped against.
func (s *HarnessCallbackService) CreateMission(ctx context.Context, req *harnesspb.CreateMissionRequest) (*harnesspb.CreateMissionResponse, error) {
	s.logger.Debug("CreateMission called",
		"mission_id", req.GetContext().GetMissionId(),
		"agent_name", req.GetContext().GetAgentName(),
		"target_id", req.TargetId,
		"name", req.Name,
	)

	// Check if mission manager is available
	if s.missionManager == nil {
		s.logger.Warn("mission creation not available - mission manager not configured")
		return &harnesspb.CreateMissionResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE,
				Message: "mission creation not available - mission manager not configured",
			},
		}, nil
	}

	// Prove the caller is inside a live mission of its own tenant, and take the
	// parent from that mission rather than from the payload. getHarness is the
	// authority: it fails closed on a missing context, an unknown mission, a
	// missing tenant and a tenant mismatch alike.
	parentHarness, err := s.getHarness(ctx, req.GetContext())
	if err != nil {
		s.logger.Warn("mission origination refused: no live parent mission for the caller",
			"mission_id", req.GetContext().GetMissionId(),
			"agent_name", req.GetContext().GetAgentName(),
			"error", err,
		)
		return nil, err
	}

	parentMission := parentHarness.Mission()
	parentMissionID := parentMission.ID
	if parentMissionID.String() == "" {
		return nil, status.Error(codes.FailedPrecondition,
			"mission origination refused: the parent mission has no id, so the child could not be attributed to it")
	}

	// Parse target ID
	targetID, err := types.ParseID(req.TargetId)
	if err != nil {
		s.logger.Error("failed to parse target ID",
			"target_id", req.TargetId,
			"error", err,
		)
		return &harnesspb.CreateMissionResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
				Message: fmt.Sprintf("invalid target ID: %v", err),
			},
		}, nil
	}

	// canonical_constraints is the one constraint field (ADR-0004). The sdk
	// writes it since v0.197.0, and the daemon reads no other (gibson#683).
	constraints := req.GetCanonicalConstraints()

	// Convert metadata
	metadata := make(map[string]any)
	for k, v := range req.Metadata {
		if v != nil {
			metadata[k] = protoTypedValueToAny(v)
		}
	}
	// Lineage, written from the resolved parent rather than the payload, so a
	// child always answers "which mission, and whose agent, asked for this".
	// The caller cannot set these: a payload entry of the same name is
	// overwritten here.
	metadata[MetadataParentMissionID] = parentMissionID.String()
	metadata[MetadataOriginatingAgent] = req.GetContext().GetAgentName()
	if runID := parentMission.MissionRunID; runID != "" {
		metadata[MetadataParentMissionRunID] = runID
	}

	// Which graph runs: the caller's own, or the checked-in catalog mission it
	// named (ADR-0118). Exactly one; an unknown parameter is refused rather
	// than dropped.
	definitionJSON, defErr := resolveMissionDefinitionJSON(ctx, req)
	if defErr != nil {
		s.logger.Warn("mission origination refused",
			"parent_mission_id", parentMissionID.String(),
			"catalog_mission", req.GetCatalogMission(),
			"error", defErr,
		)
		return &harnesspb.CreateMissionResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
				Message: defErr.Error(),
			},
		}, nil
	}

	// A child that starts from the state of the caller is a fork of the
	// caller sandbox (ADR-0169, gibson#803). Each check that needs no child
	// runs first, so a refused fork creates no mission.
	var forkPlan *callerForkPlan
	if req.GetStartsFrom() == harnesspb.OriginationStart_ORIGINATION_START_CALLER_STATE {
		plan, perr := s.planCallerFork(ctx, parentHarness, req)
		if perr != nil {
			s.logger.Warn("mission origination refused: the caller cannot be forked",
				"parent_mission_id", parentMissionID.String(), "error", perr)
			return nil, perr
		}
		forkPlan = plan
	}

	// Create mission request
	createReq := &CreateMissionRequest{
		MissionDefinitionJSON: definitionJSON,
		TargetID:              targetID,
		ParentMissionID:       &parentMissionID,
		ParentDepth:           parentMission.DelegationDepth,
		Name:                  req.Name,
		Constraints:           constraints,
		Metadata:              metadata,
		Tags:                  req.Tags,
	}

	// Create the mission through the manager
	missionInfo, err := s.missionManager.CreateMission(ctx, createReq)
	if err != nil {
		s.logger.Error("failed to create mission",
			"error", err,
			"parent_mission_id", parentMissionID.String(),
			"target_id", req.TargetId,
		)
		return &harnesspb.CreateMissionResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: fmt.Sprintf("failed to create mission: %v", err),
			},
		}, nil
	}

	// The bounds of ADR-0063 ran in CreateMission, before the snapshot. A
	// fork that fails cancels the child, so no child waits for a fork that
	// does not exist.
	if forkPlan != nil {
		if ferr := s.forkCallerForChild(ctx, forkPlan, missionInfo.ID); ferr != nil {
			if cerr := s.missionManager.Cancel(ctx, missionInfo.ID); cerr != nil {
				s.logger.Error("cancel the child mission of a failed fork", "mission_id", missionInfo.ID, "error", cerr)
			}
			s.logger.Warn("mission origination failed: the caller was not forked",
				"mission_id", missionInfo.ID, "parent_mission_id", parentMissionID.String(), "error", ferr)
			return nil, ferr
		}
	}

	s.logger.Info("mission originated from inside its parent",
		"mission_id", missionInfo.ID,
		"parent_mission_id", parentMissionID.String(),
		"originating_agent", req.GetContext().GetAgentName(),
		"name", req.Name,
	)

	// Convert mission info to proto response
	pbMission := &harnesspb.MissionInfo{
		Id:       missionInfo.ID.String(),
		Name:     missionInfo.Name,
		Status:   missionStatusToProto(missionInfo.Status),
		TargetId: missionInfo.TargetID.String(),
	}
	if missionInfo.ParentMissionID != nil {
		pbMission.ParentMissionId = missionInfo.ParentMissionID.String()
	}

	return &harnesspb.CreateMissionResponse{
		Mission: pbMission,
	}, nil
}

// protoTypedValueToAny converts a proto TypedValue to a Go any value
func protoTypedValueToAny(tv *commonpb.TypedValue) any {
	if tv == nil {
		return nil
	}

	switch v := tv.Kind.(type) {
	case *commonpb.TypedValue_StringValue:
		return v.StringValue
	case *commonpb.TypedValue_IntValue:
		return v.IntValue
	case *commonpb.TypedValue_DoubleValue:
		return v.DoubleValue
	case *commonpb.TypedValue_BoolValue:
		return v.BoolValue
	case *commonpb.TypedValue_BytesValue:
		return v.BytesValue
	default:
		return nil
	}
}

// missionStatusToProto converts internal MissionStatus to proto format
func missionStatusToProto(status MissionStatus) harnesspb.MissionStatus {
	switch status {
	case MissionStatusSubmitted:
		return harnesspb.MissionStatus_MISSION_STATUS_SUBMITTED
	case MissionStatusWorking:
		return harnesspb.MissionStatus_MISSION_STATUS_WORKING
	case MissionStatusCompleted:
		return harnesspb.MissionStatus_MISSION_STATUS_COMPLETED
	case MissionStatusFailed:
		return harnesspb.MissionStatus_MISSION_STATUS_FAILED
	case MissionStatusCanceled:
		return harnesspb.MissionStatus_MISSION_STATUS_CANCELED
	case MissionStatusPaused:
		return harnesspb.MissionStatus_MISSION_STATUS_PAUSED
	case MissionStatusInputRequired:
		return harnesspb.MissionStatus_MISSION_STATUS_INPUT_REQUIRED
	default:
		return harnesspb.MissionStatus_MISSION_STATUS_UNSPECIFIED
	}
}

// missionStatusFromProto converts a proto MissionStatus to the internal status.
// It is the inverse of missionStatusToProto. The proto enum names PENDING and
// RUNNING stay in the SDK until the SDK renames them.
func missionStatusFromProto(state harnesspb.MissionStatus) MissionStatus {
	switch state {
	case harnesspb.MissionStatus_MISSION_STATUS_SUBMITTED:
		return MissionStatusSubmitted
	case harnesspb.MissionStatus_MISSION_STATUS_WORKING:
		return MissionStatusWorking
	case harnesspb.MissionStatus_MISSION_STATUS_COMPLETED:
		return MissionStatusCompleted
	case harnesspb.MissionStatus_MISSION_STATUS_FAILED:
		return MissionStatusFailed
	case harnesspb.MissionStatus_MISSION_STATUS_CANCELED:
		return MissionStatusCanceled
	case harnesspb.MissionStatus_MISSION_STATUS_PAUSED:
		return MissionStatusPaused
	case harnesspb.MissionStatus_MISSION_STATUS_INPUT_REQUIRED:
		return MissionStatusInputRequired
	case harnesspb.MissionStatus_MISSION_STATUS_UNSPECIFIED:
		// An unspecified status has no internal status.
	}
	return ""
}

// RunMission implements the mission execution RPC by delegating to the MissionOperator.
func (s *HarnessCallbackService) RunMission(ctx context.Context, req *harnesspb.RunMissionRequest) (*harnesspb.RunMissionResponse, error) {
	if s.missionManager == nil {
		return &harnesspb.RunMissionResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE,
				Message: "mission management not configured",
			},
		}, nil
	}

	if req.MissionId == "" {
		return &harnesspb.RunMissionResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
				Message: "mission_id is required",
			},
		}, nil
	}

	if err := s.missionManager.Run(ctx, req.MissionId); err != nil {
		s.logger.Error("RunMission: failed to run mission", "mission_id", req.MissionId, "error", err)
		return &harnesspb.RunMissionResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: err.Error(),
			},
		}, nil
	}

	s.logger.Info("RunMission: mission started", "mission_id", req.MissionId)
	return &harnesspb.RunMissionResponse{}, nil
}

// GetMissionStatus implements the mission status query RPC by delegating to the MissionOperator.
func (s *HarnessCallbackService) GetMissionStatus(ctx context.Context, req *harnesspb.GetMissionStatusRequest) (*harnesspb.GetMissionStatusResponse, error) {
	if s.missionManager == nil {
		return &harnesspb.GetMissionStatusResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE,
				Message: "mission management not configured",
			},
		}, nil
	}

	if req.MissionId == "" {
		return &harnesspb.GetMissionStatusResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
				Message: "mission_id is required",
			},
		}, nil
	}

	statusInfo, err := s.missionManager.GetStatus(ctx, req.MissionId)
	if err != nil {
		s.logger.Error("GetMissionStatus: failed to get status", "mission_id", req.MissionId, "error", err)
		return &harnesspb.GetMissionStatusResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: err.Error(),
			},
		}, nil
	}

	// Convert finding counts from map[string]int to map[string]int32.
	findingCounts := make(map[string]int32, len(statusInfo.FindingCounts))
	for k, v := range statusInfo.FindingCounts {
		findingCounts[k] = int32(v)
	}

	return &harnesspb.GetMissionStatusResponse{
		Status: &harnesspb.MissionStatusInfo{
			Status:        missionStatusToProto(statusInfo.Status),
			Progress:      statusInfo.Progress,
			Phase:         statusInfo.Phase,
			FindingCounts: findingCounts,
			TokenUsage:    statusInfo.TokenUsage,
			DurationMs:    statusInfo.Duration.Milliseconds(),
			Error:         statusInfo.Error,
		},
	}, nil
}

// WaitForMission implements the mission wait RPC by delegating to the MissionOperator.
func (s *HarnessCallbackService) WaitForMission(ctx context.Context, req *harnesspb.WaitForMissionRequest) (*harnesspb.WaitForMissionResponse, error) {
	if s.missionManager == nil {
		return &harnesspb.WaitForMissionResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE,
				Message: "mission management not configured",
			},
		}, nil
	}

	if req.MissionId == "" {
		return &harnesspb.WaitForMissionResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
				Message: "mission_id is required",
			},
		}, nil
	}

	timeout := time.Duration(req.TimeoutMs) * time.Millisecond
	result, err := s.missionManager.WaitForCompletion(ctx, req.MissionId, timeout)
	if err != nil {
		s.logger.Error("WaitForMission: failed to wait", "mission_id", req.MissionId, "error", err)
		return &harnesspb.WaitForMissionResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: err.Error(),
			},
		}, nil
	}

	s.logger.Info("WaitForMission: mission completed", "mission_id", req.MissionId, "status", result.Status)
	return &harnesspb.WaitForMissionResponse{
		Result: &harnesspb.MissionResult{
			MissionId:   result.MissionID,
			Status:      missionStatusToProto(result.Status),
			Error:       result.Error,
			CompletedAt: result.CompletedAt.UnixMilli(),
		},
	}, nil
}

// ListMissions implements the mission listing RPC by delegating to the MissionOperator.
func (s *HarnessCallbackService) ListMissions(ctx context.Context, req *harnesspb.ListMissionsRequest) (*harnesspb.ListMissionsResponse, error) {
	if s.missionManager == nil {
		return &harnesspb.ListMissionsResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE,
				Message: "mission management not configured",
			},
		}, nil
	}

	// Window returns ErrBadToken only. The harness reports a refusal in the
	// response, as for every other refusal of this service.
	offset, limit, pageErr := pagetoken.Window(req.GetPageSize(), req.GetPageToken())
	if errors.Is(pageErr, pagetoken.ErrBadToken) {
		return &harnesspb.ListMissionsResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
				Message: pagetoken.ErrBadToken.Error(),
			},
		}, nil
	}
	filter := &MissionFilter{Limit: limit, Offset: offset}
	if req.Filter != nil {
		if req.Filter.Status != harnesspb.MissionStatus_MISSION_STATUS_UNSPECIFIED {
			// Map the proto MissionStatus enum back to the internal status.
			st := missionStatusFromProto(req.Filter.Status)
			filter.Status = &st
		}
	}

	records, err := s.missionManager.List(ctx, filter)
	if err != nil {
		s.logger.Error("ListMissions: failed to list", "error", err)
		return &harnesspb.ListMissionsResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: err.Error(),
			},
		}, nil
	}

	missions := make([]*harnesspb.MissionInfo, 0, len(records))
	for _, rec := range records {
		missions = append(missions, &harnesspb.MissionInfo{
			Id:     rec.ID.String(),
			Status: missionStatusToProto(rec.Status),
		})
	}

	s.logger.Info("ListMissions: listed missions", "count", len(missions))
	return &harnesspb.ListMissionsResponse{
		Missions:      missions,
		NextPageToken: pagetoken.Next(offset, limit, len(missions), -1),
	}, nil
}

// CancelMission implements the mission cancellation RPC by delegating to the MissionOperator.
func (s *HarnessCallbackService) CancelMission(ctx context.Context, req *harnesspb.CancelMissionRequest) (*harnesspb.CancelMissionResponse, error) {
	if s.missionManager == nil {
		return &harnesspb.CancelMissionResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE,
				Message: "mission management not configured",
			},
		}, nil
	}

	if req.MissionId == "" {
		return &harnesspb.CancelMissionResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
				Message: "mission_id is required",
			},
		}, nil
	}

	missionID, err := types.ParseID(req.MissionId)
	if err != nil {
		return &harnesspb.CancelMissionResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
				Message: fmt.Sprintf("invalid mission_id: %v", err),
			},
		}, nil
	}

	if err := s.missionManager.Cancel(ctx, missionID); err != nil {
		s.logger.Error("CancelMission: failed to cancel", "mission_id", req.MissionId, "error", err)
		return &harnesspb.CancelMissionResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: err.Error(),
			},
		}, nil
	}

	s.logger.Info("CancelMission: mission cancelled", "mission_id", req.MissionId)
	return &harnesspb.CancelMissionResponse{}, nil
}

// GetMissionResults implements the mission results retrieval RPC by delegating to the MissionOperator.
func (s *HarnessCallbackService) GetMissionResults(ctx context.Context, req *harnesspb.GetMissionResultsRequest) (*harnesspb.GetMissionResultsResponse, error) {
	if s.missionManager == nil {
		return &harnesspb.GetMissionResultsResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE,
				Message: "mission management not configured",
			},
		}, nil
	}

	if req.MissionId == "" {
		return &harnesspb.GetMissionResultsResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
				Message: "mission_id is required",
			},
		}, nil
	}

	missionID, err := types.ParseID(req.MissionId)
	if err != nil {
		return &harnesspb.GetMissionResultsResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
				Message: fmt.Sprintf("invalid mission_id: %v", err),
			},
		}, nil
	}

	result, err := s.missionManager.GetResults(ctx, missionID)
	if err != nil {
		s.logger.Error("GetMissionResults: failed to get results", "mission_id", req.MissionId, "error", err)
		return &harnesspb.GetMissionResultsResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: err.Error(),
			},
		}, nil
	}

	s.logger.Info("GetMissionResults: results retrieved", "mission_id", req.MissionId, "status", result.Status)
	return &harnesspb.GetMissionResultsResponse{
		Result: &harnesspb.MissionResult{
			MissionId:   result.MissionID,
			Status:      missionStatusToProto(result.Status),
			Error:       result.Error,
			CompletedAt: result.CompletedAt.UnixMilli(),
		},
	}, nil
}

// callToolDiscoveryScope is the scope of a discovery that a tool call of an
// agent returns: the mission ids of the call, and the tenant of the callback
// call. A call with no tenant gives a scope with no tenant, and the discovery
// processor then drops the discovery.
func callToolDiscoveryScope(ctx context.Context, info *harnesspb.ContextInfo) ingest.ExecContext {
	ec := ingest.ExecContext{
		MissionRunID:    info.GetMissionRunId(),
		MissionID:       info.GetMissionId(),
		AgentName:       info.GetAgentName(),
		AgentRunID:      info.GetAgentRunId(),
		ToolExecutionID: info.GetToolExecutionId(),
	}
	if tenant, ok := auth.TenantFromContext(ctx); ok {
		ec.TenantID = tenant
	}
	return ec
}
