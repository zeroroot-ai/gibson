// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

// service.go implements the ComponentServiceServer gRPC handlers.
//
// This server is the single ingress point that all Gibson components (agents,
// tools, plugins) connect to. It delegates to ComponentRegistry for lifecycle
// tracking and WorkQueue for pull-based work dispatch.
//
// Generated proto code location: github.com/zeroroot-ai/sdk/api/gen/componentpb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"

	"github.com/zeroroot-ai/gibson/internal/engine/emitbounds"
	"github.com/zeroroot-ai/gibson/internal/engine/graphrag/ingest"
	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	bankpb "github.com/zeroroot-ai/sdk/api/gen/gibson/bank/v1"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
	"github.com/zeroroot-ai/sdk/auth"
	sdkgraphrag "github.com/zeroroot-ai/sdk/graphrag"
)

// ---------------------------------------------------------------------------
// Harness proxy dependency interfaces
//
// These narrow interfaces decouple ComponentServiceServer from the concrete
// LLM and finding pipeline implementations. Wire them at construction time.
// Both interfaces will be replaced by direct harness delegation once the
// mission-context lookup layer (task 5.3+) is in place.
// ---------------------------------------------------------------------------

// LLMCompleter routes a completion request for a given mission slot to the
// appropriate LLM provider. The missionID is used to resolve per-mission
// slot configuration overrides before falling back to tenant-level defaults.
type LLMCompleter interface {
	// Complete executes a blocking completion using the named slot.
	// messagesJSON is a JSON-encoded []llm.Message.
	// Returns the response content, finish reason, token usage, and resolved model.
	Complete(ctx context.Context, tenant, missionID, slot, messagesJSON string, maxTokens int32, temperature float32) (content, finishReason, modelUsed string, promptTokens, completionTokens int32, err error)

	// Stream executes a streaming completion using the named slot and sends
	// chunks to the provided send function until completion or error.
	// messagesJSON is a JSON-encoded []llm.Message.
	Stream(ctx context.Context, tenant, missionID, slot, messagesJSON string, maxTokens int32, temperature float32, send func(delta, finishReason string) error) error
}

// FindingSubmitter persists a serialized finding produced by a remote agent.
// The JSON payload must conform to the agent.Finding schema. The submitter also
// folds the finding into the tenant's World, which is what makes the graph
// projector materialize a :Finding node — there is no second write path.
type FindingSubmitter interface {
	// Submit stores the finding and returns a generated finding_id.
	Submit(ctx context.Context, tenant, workID, findingJSON, severity, title string) (findingID string, err error)
}

// ResultDiscoveryProcessor processes a DiscoveryResult (proto field 100) extracted
// from a tool response and persists the discovered entities in Neo4j.
// It is satisfied by *processor.discoveryProcessor from the graphrag/processor package.
type ResultDiscoveryProcessor interface {
	// Process persists all entities in the DiscoveryResult to the knowledge graph.
	// The execCtx carries mission/agent provenance for the DISCOVERED relationship.
	Process(ctx context.Context, execCtx ingest.ExecContext, discovery *graphragpb.DiscoveryResult) (interface{}, error)
}

// ---------------------------------------------------------------------------
// Local memory tier string constants
//
// These match the tier strings used by the generated MemoryRequest proto type.
// ---------------------------------------------------------------------------

const (
	memTierWorking  = "working"
	memTierMission  = "mission"
	memTierLongTerm = "long_term"
)

// ---------------------------------------------------------------------------
// Connection parameter defaults
//
// These values are returned to every registering component so they know how
// frequently to heartbeat and poll. They are intentionally conservative so
// that a component defaults to safe behaviour before any server-pushed config
// is available.
// ---------------------------------------------------------------------------

const (
	// defaultHeartbeatIntervalMs is the recommended heartbeat cadence sent to
	// components on registration. Must be shorter than the registry TTL (30 s).
	defaultHeartbeatIntervalMs = 10_000 // 10 seconds

	// defaultPollIntervalMs is the recommended back-off between empty polls.
	defaultPollIntervalMs = 1_000 // 1 second

	// defaultPollTimeoutMs is the server-side long-poll window a component
	// should request. Matches the registry TTL so an idle component is never
	// blocking for longer than its registration would be valid.
	defaultPollTimeoutMs = 20_000 // 20 seconds

	// maxPollTimeoutMs caps the client-requested poll timeout to prevent
	// goroutine leaks from extremely long-running blocking claims.
	maxPollTimeoutMs = 30_000 // 30 seconds
)

// ---------------------------------------------------------------------------
// ComponentServiceServer
// ---------------------------------------------------------------------------

// ComponentServiceServer handles the four core lifecycle RPCs that every
// Gibson component calls:
//
//   - RegisterComponent  - announce existence, receive instance_id + config
//   - Heartbeat          - refresh TTL, detect forced deregistration
//   - PollWork           - long-poll for a work item (blocking claim)
//   - SubmitResult       - deliver work outcome back to the orchestrator
//
// All operations are tenant-scoped: the tenant is extracted from the context
// via auth.TenantStringFromContext and forwarded to both the registry and queue so
// that data from different tenants is never commingled.
type ComponentServiceServer struct {
	componentpb.UnimplementedComponentServiceServer

	registry ComponentRegistry
	queue    WorkQueue
	logger   *slog.Logger

	// Harness proxy dependencies.
	//
	// llmCompleter routes LLM completions back to Gibson's provider system.
	// May be nil; Complete and CompleteStream return codes.Unimplemented when nil.
	llmCompleter LLMCompleter

	// workContext records the work-item→mission/tenant mapping (gibson#756; the
	// memory tiers were retired). May be nil.
	workContext WorkContextRegistry

	// missionCtx resolves a work item ID to its parent mission ID and any
	// per-mission LLM slot overrides. Used by Complete and CompleteStream to
	// apply per-mission provider configuration before delegating to llmCompleter.
	// May be nil; when nil, Complete and CompleteStream pass an empty missionID
	// and no overrides (current behaviour preserved).
	missionCtx *MissionContextResolver

	// findingSubmitter persists findings from remote agents.
	// May be nil; SubmitFinding logs and generates an ID when nil.
	findingSubmitter FindingSubmitter

	// componentAccess manages tenant opt-in and encrypted configuration for plugins.
	// May be nil; plugin access RPCs return codes.Unimplemented when nil.
	componentAccess ComponentAccessStore

	// memberStatus records what a bank member reports on its heartbeat
	// (ADR-0019, gibson#1716). Nil means this daemon serves no banks, and a
	// member heartbeat is refused rather than dropped.
	memberStatus MemberStatusSink

	// auditLog records security-relevant mutations for compliance purposes.
	// May be nil; when nil, audit events are silently skipped.
	auditLog *audit.AuditLogger

	// quotaManager enforces per-tenant agent quotas during RegisterComponent.
	// May be nil; when nil, quota checks are skipped entirely.
	quotaManager *QuotaManager

	// llmToolCompleter extends LLM completions with tool-calling and structured output.
	// May be nil; CompleteWithTools and CompleteStructured return codes.Unimplemented when nil.
	llmToolCompleter LLMToolCompleter

	// toolExecutor dispatches tool execution for streaming and queued operations.
	// May be nil; tool streaming and queue RPCs return codes.Unimplemented when nil.
	toolExecutor ToolExecutor

	// toolJobs tracks queued tool batches for ToolResults streaming.
	toolJobsMu sync.Mutex
	toolJobs   map[string]*toolJob

	// --- Harness parity dependencies (platform-harness-parity spec) ---

	// graphrag handles knowledge graph operations for remote agents.
	// May be nil; GraphRAG RPCs return codes.Unimplemented when nil.
	graphrag GraphRAGQuerier

	// findingQuerier reads findings for remote agents.
	// May be nil; finding query RPCs return codes.Unimplemented when nil.
	findingQuerier FindingQuerier

	// missionMgr handles sub-mission lifecycle for remote agents.
	// May be nil; mission management RPCs return codes.Unimplemented when nil.
	missionMgr MissionManager

	// capabilityChecker verifies a calling component's session capabilities
	// (capname.MissionDelegate, capname.MissionOriginate) before a
	// capability-gated RPC proceeds — gibson#1186 slice C. May be nil; every
	// capability-gated RPC DENIES rather than allows when nil, since an
	// unwired checker must never be silently equivalent to "granted".
	capabilityChecker CapabilityChecker

	// credentialStore retrieves tenant-scoped credentials for remote agents.
	// May be nil; GetCredential returns codes.Unimplemented when nil.
	credentialStore CredentialStore

	// taxonomyProvider returns the taxonomy schema for remote agents.
	// May be nil; GetTaxonomySchema returns codes.Unimplemented when nil.
	taxonomyProvider TaxonomyProvider

	// stepHintsReporter accepts planning step hints from remote agents.
	// May be nil; ReportStepHints returns codes.Unimplemented when nil.
	stepHintsReporter StepHintsReporter

	// discoveryProcessor persists DiscoveryResult (proto field 100) from tool responses to Neo4j.
	// May be nil; when nil, field-100 discovery data is not stored to the graph.
	discoveryProcessor ResultDiscoveryProcessor

	// authorizer writes and deletes FGA relationship tuples for component ownership.
	// May be nil; when nil (noop/disabled mode), all FGA writes are skipped silently.
	// Set via WithAuthorizer. Added by agent-auth-fga-integration spec (task 3).
	authorizer authz.Authorizer

	// componentInstallRegistry is the daemon-side plugin install registry.
	// When non-nil, RegisterComponent calls with kind="plugin" are forwarded to
	// componentInstallRegistry.Register so install metadata is persisted and transient state
	// is initialised in Redis. Heartbeat calls for plugin components are forwarded
	// to componentInstallRegistry.Heartbeat to refresh the 90-second Redis TTL.
	// When nil, plugin registration is handled via the standard component registry only.
	// Set via WithComponentInstallRegistry. Added by plugin-runtime spec (Task 16).
	componentInstallRegistry ComponentInstallRegistry

	// ontologyReasoner merges ontology extensions contributed by enrolling
	// components. Set via WithOntologyReasoner. When nil, any OntologyExtension
	// payload in RegisterComponent is silently ignored (no error returned to the
	// caller — the extension is deferred until a follow-up proto change carries
	// the full OntologyExtension payload over the enrollment RPC).
	ontologyReasoner OntologyReasoner

	// emitCounts bounds how many observations one work item may emit
	// (emitbounds.MaxObservationsPerTask, ADR-0012 "Write contract"). Remote
	// components have a work id on the wire but no per-task object here to
	// hang a counter on, so this path uses the keyed, bounded pool. Lazily
	// created by emitCounter so the zero-value server stays usable.
	emitCountsOnce sync.Once
	emitCounts     *emitbounds.TaskCounter
}

// emitCounter returns the per-work-item observation counter, creating it on
// first use.
func (s *ComponentServiceServer) emitCounter() *emitbounds.TaskCounter {
	s.emitCountsOnce.Do(func() {
		s.emitCounts = emitbounds.NewTaskCounter()
	})
	return s.emitCounts
}

// NewComponentServiceServer constructs a ComponentServiceServer with the core
// lifecycle dependencies. Both registry and queue must be non-nil.
//
// Harness proxy dependencies (llmCompleter, memStore, findingSubmitter,
// componentAccess) are optional at this stage: pass nil to leave the
// corresponding RPCs returning codes.Unimplemented until the subsystems are
// wired (tasks 5.3–5.5).
//
// auditLog may be nil; when nil, audit events are silently skipped.
func NewComponentServiceServer(
	registry ComponentRegistry,
	queue WorkQueue,
	logger *slog.Logger,
	llmCompleter LLMCompleter,
	findingSubmitter FindingSubmitter,
	componentAccess ComponentAccessStore,
	auditLog *audit.AuditLogger,
) *ComponentServiceServer {
	if registry == nil {
		panic("component.NewComponentServiceServer: registry must not be nil")
	}
	if queue == nil {
		panic("component.NewComponentServiceServer: queue must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &ComponentServiceServer{
		registry:         registry,
		queue:            queue,
		logger:           logger,
		llmCompleter:     llmCompleter,
		findingSubmitter: findingSubmitter,
		componentAccess:  componentAccess,
		auditLog:         auditLog,
	}
}

// WithMemoryResolver attaches a MemoryResolver to the server so that
// MemoryGet, MemorySet, and MemorySearch route mission-tier operations to the
// per-agent mission namespace rather than a shared store.
//
// Call this immediately after NewComponentServiceServer, before serving any
// RPCs:
//
//	svc := component.NewComponentServiceServer(...)
//	svc.WithWorkContextRegistry(component.NewRedisWorkContextRegistry(stateClient))
func (s *ComponentServiceServer) WithWorkContextRegistry(r WorkContextRegistry) *ComponentServiceServer {
	s.workContext = r
	return s
}

// WithMissionContextResolver attaches a MissionContextResolver so that
// Complete and CompleteStream can look up per-mission LLM slot overrides
// before delegating to the LLMCompleter. When non-nil the resolver is called
// with the request's work_id and any returned overrides are passed to the
// completer. Missing mission context is handled gracefully — the server falls
// back to tenant-level defaults so existing behaviour is fully preserved.
//
// Call this immediately after NewComponentServiceServer, before serving RPCs:
//
//	svc := component.NewComponentServiceServer(...)
//	svc.WithMissionContextResolver(component.NewMissionContextResolver(sc, ts, logger))
func (s *ComponentServiceServer) WithMissionContextResolver(r *MissionContextResolver) *ComponentServiceServer {
	s.missionCtx = r
	return s
}

// WithQuotaManager attaches a QuotaManager so that RegisterComponent enforces
// per-tenant agent quotas. Call this immediately after NewComponentServiceServer
// and before serving any RPCs:
//
//	svc := component.NewComponentServiceServer(...)
//	svc.WithQuotaManager(quotaMgr)
func (s *ComponentServiceServer) WithQuotaManager(qm *QuotaManager) *ComponentServiceServer {
	s.quotaManager = qm
	return s
}

// WithToolExecutor attaches a ToolExecutor for streaming and queued tool execution.
// May be nil; tool streaming and queue RPCs return codes.Unimplemented when nil.
func (s *ComponentServiceServer) WithToolExecutor(te ToolExecutor) *ComponentServiceServer {
	s.toolExecutor = te
	return s
}

// WithLLMToolCompleter attaches an LLMToolCompleter for tool-calling and structured completions.
// May be nil; CompleteWithTools and CompleteStructured return codes.Unimplemented when nil.
func (s *ComponentServiceServer) WithLLMToolCompleter(tc LLMToolCompleter) *ComponentServiceServer {
	s.llmToolCompleter = tc
	return s
}

// WithGraphRAG attaches a GraphRAGQuerier for knowledge graph operations.
// May be nil; GraphRAG RPCs return codes.Unimplemented when nil.
func (s *ComponentServiceServer) WithGraphRAG(g GraphRAGQuerier) *ComponentServiceServer {
	s.graphrag = g
	return s
}

// WithFindingQuerier attaches a FindingQuerier for finding read operations.
// May be nil; finding query RPCs return codes.Unimplemented when nil.
func (s *ComponentServiceServer) WithFindingQuerier(fq FindingQuerier) *ComponentServiceServer {
	s.findingQuerier = fq
	return s
}

// WithMissionManager attaches a MissionManager for sub-mission lifecycle.
// May be nil; mission management RPCs return codes.Unimplemented when nil.
func (s *ComponentServiceServer) WithMissionManager(mm MissionManager) *ComponentServiceServer {
	s.missionMgr = mm
	return s
}

// WithCapabilityChecker attaches a CapabilityChecker for session-capability
// gates (mission:delegate, mission:originate — gibson#1186 slice C).
// May be nil; capability-gated RPCs deny when nil rather than skipping the
// check.
func (s *ComponentServiceServer) WithCapabilityChecker(cc CapabilityChecker) *ComponentServiceServer {
	s.capabilityChecker = cc
	return s
}

// WithCredentialStore attaches a CredentialStore for credential retrieval.
// May be nil; GetCredential returns codes.Unimplemented when nil.
func (s *ComponentServiceServer) WithCredentialStore(cs CredentialStore) *ComponentServiceServer {
	s.credentialStore = cs
	return s
}

// WithTaxonomyProvider attaches a TaxonomyProvider for taxonomy schema access.
// May be nil; GetTaxonomySchema returns codes.Unimplemented when nil.
func (s *ComponentServiceServer) WithTaxonomyProvider(tp TaxonomyProvider) *ComponentServiceServer {
	s.taxonomyProvider = tp
	return s
}

// WithStepHintsReporter attaches a StepHintsReporter for planning hints.
// May be nil; ReportStepHints returns codes.Unimplemented when nil.
func (s *ComponentServiceServer) WithStepHintsReporter(sr StepHintsReporter) *ComponentServiceServer {
	s.stepHintsReporter = sr
	return s
}

// WithDiscoveryProcessor attaches a ResultDiscoveryProcessor so that SubmitResult
// automatically persists DiscoveryResult (proto field 100) from tool responses
// into the Neo4j knowledge graph. When nil, field-100 data is silently skipped.
func (s *ComponentServiceServer) WithDiscoveryProcessor(dp ResultDiscoveryProcessor) *ComponentServiceServer {
	s.discoveryProcessor = dp
	return s
}

// WithAuthorizer wires an FGA Authorizer so that RegisterComponent writes a
// component ownership tuple ("tenant:<slug> owner component:<name>") on
// successful registration. The tuple enables the FGA computed relation
// "admin from owner" to propagate tenant-level permissions to all components
// owned by that tenant without requiring per-component grants.
//
// When az is nil or authz is disabled (noop mode), all FGA writes are silently
// skipped — registration never fails due to FGA unavailability.
//
// Added by the agent-auth-fga-integration spec (task 3).
func (s *ComponentServiceServer) WithAuthorizer(az authz.Authorizer) *ComponentServiceServer {
	s.authorizer = az
	return s
}

// WithComponentInstallRegistry wires a ComponentInstallRegistry so that RegisterComponent calls with
// kind="plugin" are forwarded to persist install metadata in Postgres and initialise
// transient Redis state. Heartbeat calls for plugin components are forwarded to
// refresh the 90-second TTL.
//
// When pr is nil, plugin-kind registrations are handled via the standard component
// registry only (install metadata is not persisted to the plugin_install table).
//
// Added by the plugin-runtime spec (Task 16).
func (s *ComponentServiceServer) WithComponentInstallRegistry(pr ComponentInstallRegistry) *ComponentServiceServer {
	s.componentInstallRegistry = pr
	return s
}

// WithOntologyReasoner wires the daemon's singleton ontology reasoner so that
// RegisterComponent can call reasoner.RegisterExtension when an enrolling
// component contributes an OntologyExtension payload.
//
// When or is nil (the default), any OntologyExtension in the registration
// request is silently ignored — no error is returned to the caller. This
// preserves backward compatibility until the proto change that carries
// OntologyExtension over the enrollment RPC is merged.
//
// Added by the ontology-extension-system epic.
func (s *ComponentServiceServer) WithOntologyReasoner(or OntologyReasoner) *ComponentServiceServer {
	s.ontologyReasoner = or
	return s
}

// ---------------------------------------------------------------------------
// RegisterComponent
// ---------------------------------------------------------------------------

// RegisterComponent handles a component announcing itself to Gibson.
//
// Flow:
//  1. Extract tenant from context — unauthenticated callers are rejected.
//  2. Build a ComponentInfo from the request fields.
//  3. Call registry.Register which assigns a unique instance ID and stores
//     the entry with a TTL.
//  4. Return the instance ID and the recommended connection parameters.
func (s *ComponentServiceServer) RegisterComponent(
	ctx context.Context,
	req *componentpb.RegisterComponentRequest,
) (*componentpb.RegisterComponentResponse, error) {
	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "missing tenant in context")
	}

	// Authorization is enforced by the FGA interceptor at the Envoy layer.
	// Component kind/name scope filtering (allowed_kinds/allowed_names) has
	// moved to ext_authz; the daemon trusts the signed identity headers.

	if req.Kind == "" {
		return nil, status.Error(codes.InvalidArgument, "kind is required")
	}
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}

	// Enforce per-tenant agent quota before touching the registry.
	// Only agent-kind components count against the agent quota; tools and plugins
	// are infrastructure components and are not subject to this limit.
	if req.Kind == "agent" && s.quotaManager != nil {
		if err := s.quotaManager.CheckAgentQuota(ctx); err != nil {
			s.logger.WarnContext(ctx, "agent registration rejected: quota exceeded",
				slog.String("tenant", tenant),
				slog.String("name", req.Name),
				slog.String("error", err.Error()),
			)
			return nil, err
		}
	}

	info := ComponentInfo{
		Kind:     req.Kind,
		Name:     req.Name,
		Version:  req.Version,
		TenantID: tenant,
		Metadata: req.Metadata,
	}
	if info.Metadata == nil {
		info.Metadata = make(map[string]string)
	}

	// Capabilities, methods, and descriptor set are stored in metadata so that
	// the registry remains agnostic to component type semantics.
	for _, cap := range req.Capabilities {
		info.Metadata["capability:"+cap] = "true"
	}
	for _, method := range req.Methods {
		info.Metadata["method:"+method] = "true"
	}
	// Structured per-method descriptors (name + description + input schema) so the
	// connector catalog / SearchTools can surface descriptions. The names-only
	// metadata above is kept for back-compat. Per ADR-0047 facet 5.
	for _, md := range req.GetMethodDescriptors() {
		info.Methods = append(info.Methods, MethodInfo{
			Name:            md.GetName(),
			Description:     md.GetDescription(),
			InputSchemaJSON: md.GetInputSchemaJson(),
		})
	}
	// Populate input/output message types. Prefer the explicitly declared fields on the
	// registration request. When a FileDescriptorSet is provided but the explicit fields
	// are absent, fall back to extracting types from the descriptor by convention
	// (messages whose names end in "Request"/"Response").
	inputMsgType := req.InputMessageType
	outputMsgType := req.OutputMessageType
	if len(req.FileDescriptorSet) > 0 {
		if inputMsgType == "" || outputMsgType == "" {
			var fds descriptorpb.FileDescriptorSet
			if err := proto.Unmarshal(req.FileDescriptorSet, &fds); err == nil {
				extracted, extractedOut := extractMessageTypesFromFDS(&fds)
				if inputMsgType == "" {
					inputMsgType = extracted
				}
				if outputMsgType == "" {
					outputMsgType = extractedOut
				}
			}
		}
	}
	if inputMsgType != "" {
		info.Metadata["input_message_type"] = inputMsgType
	}
	if outputMsgType != "" {
		info.Metadata["output_message_type"] = outputMsgType
	}

	// Record the registering user so ExecutorUser attribution works when a
	// parent agent later delegates to this component. Populated from the
	// authenticated caller's identity when present; absent for anonymous
	// registrations (which graceful-degrade to no executor_user_id on
	// downstream spans). Spec: llm-user-attribution-governance Req 1.5.
	if id, err := auth.IdentityFromContext(ctx); err == nil && id.Subject != "" {
		info.Metadata[ComponentMetadataOwnerUserID] = id.Subject
	} else if uid, ok := auth.ActingUserFromContext(ctx); ok && uid != "" {
		info.Metadata[ComponentMetadataOwnerUserID] = uid
	}

	instanceID, err := s.registry.Register(ctx, tenant, req.Kind, req.Name, info)
	if err != nil {
		s.logger.ErrorContext(ctx, "component registration failed",
			slog.String("tenant", tenant),
			slog.String("kind", req.Kind),
			slog.String("name", req.Name),
			slog.String("error", err.Error()),
		)
		return nil, status.Errorf(codes.Internal, "failed to register component: %v", err)
	}

	s.logger.InfoContext(ctx, "component registered",
		slog.String("tenant", tenant),
		slog.String("kind", req.Kind),
		slog.String("name", req.Name),
		slog.String("version", req.Version),
		slog.String("instance_id", instanceID),
	)

	// Bind can_resolve for a plugin's manifest-declared secrets so it can read
	// them at runtime (ADR-0066). SVID pod plugins register here rather than via
	// the old RegisterPlugin binding path.
	if req.Kind == "plugin" {
		s.bindDeclaredSecrets(ctx, tenant, req.Metadata)
	}

	// Spec plans-and-quotas-simplification: agent registration alone no
	// longer consumes the concurrent_agents quota. Counters increment when
	// an agent transitions idle→busy (first task pickup) and decrement on
	// busy→idle. Wiring into the harness's per-agent inFlightTasks
	// callbacks lives in the orchestrator/agent package.

	// Forward plugin-kind registrations to the ComponentInstallRegistry for install persistence.
	// The ComponentInstallRegistry persists install metadata in Postgres (plugin_install table) and
	// initialises transient Redis state. Plugin-specific metadata keys are carried in
	// req.Metadata using the "plugin:" prefix convention.
	//
	// Best-effort: a failed componentInstallRegistry call is logged but never fails the RPC —
	// the component is already in the Redis registry and will heartbeat normally.
	if s.componentInstallRegistry != nil {
		tenantID, tenantParseErr := auth.NewTenantID(tenant)
		if tenantParseErr != nil {
			s.logger.WarnContext(ctx, "register component: invalid tenant for component install registry forwarding; skipping",
				slog.String("tenant", tenant), slog.String("error", tenantParseErr.Error()))
		} else {
			install := &ComponentInstall{
				ID:                 instanceID,
				TenantID:           tenantID,
				Kind:               req.Kind,
				Name:               req.Name,
				Version:            req.Version,
				ManifestHash:       req.Metadata["plugin:manifest_hash"],
				DeclaredMethods:    req.Methods,
				ProtoDescriptorSet: req.FileDescriptorSet,
				HostID:             req.Metadata["plugin:host_id"],
				RuntimeMode:        req.Metadata["plugin:runtime_mode"],
				SetecRequired:      req.Metadata["plugin:setec_required"] == "true",
				ContentTrust:       contentTrustFromMetadata(req.Metadata["plugin:content_trust"]),
			}
			if install.RuntimeMode == "" {
				install.RuntimeMode = "process"
			}
			if prErr := s.componentInstallRegistry.Register(ctx, install); prErr != nil {
				// Fail the registration rather than logging and continuing.
				// "Non-fatal" was true of the RPC and false of the platform: the
				// live Redis registry recorded an instance the durable record
				// never knew about, so the two stores diverged permanently and
				// silently — for every component, since a nil descriptor set
				// made the write impossible (gibson#1205).
				//
				// A component that cannot be recorded is not installed. Better
				// the caller sees it and retries than the fleet carries a
				// component nothing can account for.
				s.logger.ErrorContext(ctx, "register component: durable install record failed",
					slog.String("tenant", tenant),
					slog.String("component", req.Name),
					slog.String("kind", req.Kind),
					slog.String("instance_id", instanceID),
					slog.String("error", prErr.Error()),
				)
				return nil, status.Errorf(codes.Internal,
					"register component %q: could not record the install: %v", req.Name, prErr)
			}
		}
	}

	// Auto-create access record for any self-hosted component (agent/tool/plugin)
	// so it appears in the tenant's inventory (gibson#662 — kind-agnostic).
	if tenant != "_system" && s.componentAccess != nil {
		if err := s.componentAccess.EnableSelfHosted(ctx, tenant, req.Name); err != nil {
			s.logger.WarnContext(ctx, "register component: failed to auto-create component access record",
				slog.String("tenant", tenant),
				slog.String("plugin", req.Name),
				slog.String("error", err.Error()),
			)
			// Non-fatal: registration succeeds even if access record creation fails.
		}
	}

	// Store component config schema if declared (any kind — gibson#662).
	if req.ConfigSchemaJson != "" && s.componentAccess != nil {
		if err := s.componentAccess.StoreConfigSchema(ctx, req.Name, req.ConfigSchemaJson); err != nil {
			s.logger.WarnContext(ctx, "register component: failed to store component config schema",
				slog.String("plugin", req.Name),
				slog.String("error", err.Error()),
			)
			// Non-fatal: registration succeeds even if schema storage fails.
		}
	}

	// Register ontology extension contributed by this component, if any.
	//
	// The OntologyExtension payload arrives over the wire on
	// RegisterComponentRequest (sdk v1.9.0+). When a reasoner is wired and the
	// component sent a non-empty extension, hand it off to the reasoner so
	// hierarchies / equivalences / IFPs / prefixes contributed by this
	// component become live in the tenant's closure.
	//
	// Best-effort: a registration failure is logged at WARN and never fails
	// the enrollment RPC — missing ontology hierarchy is a soft degradation,
	// not a hard failure (the component still registers and can serve work;
	// hierarchy-aware queries simply won't see this component's contribution
	// until a successful retry).
	if s.ontologyReasoner != nil && req.GetOntologyExtension() != nil {
		ext := sdkgraphrag.OntologyExtensionFromProto(req.GetOntologyExtension())
		if err := s.ontologyReasoner.RegisterExtension(req.GetName(), ext); err != nil {
			s.logger.WarnContext(ctx, "register component: ontology extension registration failed",
				slog.String("component", req.GetName()),
				slog.String("tenant", tenant),
				slog.String("error", err.Error()),
			)
		}
	}

	// Write FGA component ownership tuple so the "admin from owner" computed
	// relation fires: any tenant admin automatically has full access to all
	// components owned by that tenant without per-component grants.
	// Best-effort: a failed write is logged as WARN and never fails registration.
	if s.authorizer != nil {
		if err := s.authorizer.Write(ctx, []authz.Tuple{{
			User:     "tenant:" + tenant,
			Relation: "owner",
			Object:   authz.ComponentObject(req.Kind, req.Name),
		}}); err != nil {
			s.logger.WarnContext(ctx, "register component: failed to write FGA ownership tuple",
				slog.String("component", req.Name),
				slog.String("tenant", tenant),
				slog.String("error", err.Error()),
			)
			// Non-fatal: registration succeeds even if FGA write fails.
		}
	}

	return &componentpb.RegisterComponentResponse{
		InstanceId:          instanceID,
		HeartbeatIntervalMs: defaultHeartbeatIntervalMs,
		PollIntervalMs:      defaultPollIntervalMs,
		PollTimeoutMs:       defaultPollTimeoutMs,
		Config:              map[string]string{},
	}, nil
}

// ---------------------------------------------------------------------------
// Heartbeat
// ---------------------------------------------------------------------------

// Heartbeat handles a periodic liveness pulse from a registered component.
//
// Flow:
//  1. Extract tenant from context.
//  2. Resolve the component kind and name from the instance ID via Discover
//     (the heartbeat request only carries instance_id, not kind/name).
//  3. Call registry.RefreshTTL to reset the expiry clock.
//  4. Return registered=false when the instance is no longer known so the
//     component knows to re-register.
//
// Note: The HeartbeatRequest carries only instance_id, so we must locate the
// component record before refreshing. If the component is unknown we return
// registered=false rather than an error — this is a normal operational signal
// that tells the client to re-register rather than treating it as a fault.
func (s *ComponentServiceServer) Heartbeat(
	ctx context.Context,
	req *componentpb.HeartbeatRequest,
) (*componentpb.HeartbeatResponse, error) {
	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "missing tenant in context")
	}

	if req.InstanceId == "" {
		return nil, status.Error(codes.InvalidArgument, "instance_id is required")
	}
	// A bank member heartbeats with its status and is not a registered
	// component instance (ADR-0019, gibson#1716).
	if req.GetMember() != nil {
		return s.memberHeartbeat(ctx, tenant, req)
	}

	// Discover all tenant components and find the one matching the instance ID.
	// This is intentionally a lightweight scan: the registry keeps a small hot
	// set per tenant and the common case is O(1) Redis GET after SCAN.
	components, err := s.registry.ListTenantComponents(ctx, tenant)
	if err != nil {
		s.logger.ErrorContext(ctx, "heartbeat: failed to list tenant components",
			slog.String("tenant", tenant),
			slog.String("instance_id", req.InstanceId),
			slog.String("error", err.Error()),
		)
		return nil, status.Errorf(codes.Internal, "failed to lookup component instance: %v", err)
	}

	var target *ComponentInfo
	for i := range components {
		if components[i].InstanceID == req.InstanceId {
			target = &components[i]
			break
		}
	}

	if target == nil {
		// Instance is not registered — caller must re-register.
		s.logger.InfoContext(ctx, "heartbeat: instance not found, signalling re-register",
			slog.String("tenant", tenant),
			slog.String("instance_id", req.InstanceId),
		)
		return &componentpb.HeartbeatResponse{Registered: false}, nil
	}

	err = s.registry.RefreshTTL(ctx, tenant, target.Kind, target.Name, req.InstanceId)
	if err != nil {
		if errors.Is(err, ErrComponentNotFound) {
			// Key expired between the Discover scan and the RefreshTTL call.
			s.logger.InfoContext(ctx, "heartbeat: instance expired between scan and refresh",
				slog.String("tenant", tenant),
				slog.String("instance_id", req.InstanceId),
			)
			return &componentpb.HeartbeatResponse{Registered: false}, nil
		}
		s.logger.ErrorContext(ctx, "heartbeat: failed to refresh TTL",
			slog.String("tenant", tenant),
			slog.String("kind", target.Kind),
			slog.String("name", target.Name),
			slog.String("instance_id", req.InstanceId),
			slog.String("error", err.Error()),
		)
		return nil, status.Errorf(codes.Internal, "failed to refresh component TTL: %v", err)
	}

	s.logger.DebugContext(ctx, "heartbeat: TTL refreshed",
		slog.String("tenant", tenant),
		slog.String("kind", target.Kind),
		slog.String("name", target.Name),
		slog.String("instance_id", req.InstanceId),
		slog.String("health_status", req.HealthStatus),
	)

	// Forward plugin heartbeats to the ComponentInstallRegistry so the 90-second transient
	// Redis TTL is refreshed and last_heartbeat_at is updated.
	// The gRPC address is not available in HeartbeatRequest; pass "" so the registry
	// preserves the address already stored from the prior heartbeat call.
	if target.Kind == "plugin" && s.componentInstallRegistry != nil {
		if prErr := s.componentInstallRegistry.Heartbeat(ctx, req.InstanceId, ""); prErr != nil {
			s.logger.WarnContext(ctx, "heartbeat: plugin registry TTL refresh failed (non-fatal)",
				slog.String("tenant", tenant),
				slog.String("plugin", target.Name),
				slog.String("instance_id", req.InstanceId),
				slog.String("error", prErr.Error()),
			)
			// Non-fatal: component registry TTL is already refreshed above.
		}
	}

	return &componentpb.HeartbeatResponse{
		Registered:    true,
		ConfigUpdates: map[string]string{},
	}, nil
}

// MemberStatusSink records a bank member's heartbeat (ADR-0019 decision 13).
// The daemon backs it with the bank store and the live console.
type MemberStatusSink interface {
	// ReportMemberStatus stores what the member reported and stamps its
	// heartbeat. An error means the member is unknown or the store is down.
	ReportMemberStatus(ctx context.Context, tenantID, memberID string, status *bankpb.MemberStatus) error
}

// WithMemberStatusSink wires where a member heartbeat is recorded.
func (s *ComponentServiceServer) WithMemberStatusSink(sink MemberStatusSink) *ComponentServiceServer {
	s.memberStatus = sink
	return s
}

// memberHeartbeat handles a heartbeat that carries a member status.
//
// A member is not a registered component instance: it is a sandboxed agent
// launched by the bank reconciler, so there is no instance row to refresh.
// instance_id names the member, which is what the launcher put in
// GIBSON_MEMBER_ID. The caller's tenant bounds what it can touch, and a
// member's status is the only thing a heartbeat can change: taking work and
// reporting on it are bound to the member's grant (gibson#1711), not to this.
func (s *ComponentServiceServer) memberHeartbeat(ctx context.Context, tenant string, req *componentpb.HeartbeatRequest) (*componentpb.HeartbeatResponse, error) {
	if s.memberStatus == nil {
		return nil, status.Error(codes.FailedPrecondition, "this daemon serves no banks, so it takes no member status")
	}
	if err := s.memberStatus.ReportMemberStatus(ctx, tenant, req.GetInstanceId(), req.GetMember()); err != nil {
		s.logger.WarnContext(ctx, "heartbeat: member status not recorded",
			slog.String("tenant", tenant),
			slog.String("member_id", req.GetInstanceId()),
			slog.String("error", err.Error()))
		return nil, status.Errorf(codes.NotFound, "member %s: %v", req.GetInstanceId(), err)
	}
	return &componentpb.HeartbeatResponse{Registered: true, ConfigUpdates: map[string]string{}}, nil
}

// ---------------------------------------------------------------------------
// PollWork
// ---------------------------------------------------------------------------

// PollWork long-polls for the next available work item assigned to this
// component instance.
//
// Flow:
//  1. Extract tenant from context.
//  2. Resolve kind and name from the instance ID.
//  3. Compute the blocking duration: use the client-requested timeout clamped
//     to maxPollTimeoutMs, falling back to defaultPollTimeoutMs.
//  4. Call queue.Claim which blocks until a message arrives or the timeout
//     elapses.
//  5. Return the work item fields, or an empty response if no work arrived.
//
// An empty response (work_id == "") signals that the timeout expired without
// available work. The component should loop back and call PollWork again after
// the recommended poll_interval_ms.
func (s *ComponentServiceServer) PollWork(
	ctx context.Context,
	req *componentpb.PollWorkRequest,
) (*componentpb.PollWorkResponse, error) {
	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "missing tenant in context")
	}

	if req.InstanceId == "" {
		return nil, status.Error(codes.InvalidArgument, "instance_id is required")
	}

	// Resolve the component record so we can route the claim to the correct stream.
	components, err := s.registry.ListTenantComponents(ctx, tenant)
	if err != nil {
		s.logger.ErrorContext(ctx, "poll work: failed to list tenant components",
			slog.String("tenant", tenant),
			slog.String("instance_id", req.InstanceId),
			slog.String("error", err.Error()),
		)
		return nil, status.Errorf(codes.Internal, "failed to lookup component instance: %v", err)
	}

	var target *ComponentInfo
	for i := range components {
		if components[i].InstanceID == req.InstanceId {
			target = &components[i]
			break
		}
	}

	if target == nil {
		// Component is not registered; tell the caller to re-register.
		return nil, status.Errorf(codes.NotFound,
			"component instance %q not found; re-register before polling", req.InstanceId)
	}

	// Clamp the requested block timeout.
	timeoutMs := int32(defaultPollTimeoutMs)
	if req.TimeoutMs > 0 {
		timeoutMs = req.TimeoutMs
	}
	if timeoutMs > maxPollTimeoutMs {
		timeoutMs = maxPollTimeoutMs
	}
	blockTimeout := time.Duration(timeoutMs) * time.Millisecond

	item, err := s.queue.Claim(ctx, tenant, target.Kind, target.Name, req.InstanceId, blockTimeout)
	if err != nil {
		// Distinguish context cancellation from genuine queue errors.
		if ctx.Err() != nil {
			return nil, status.FromContextError(ctx.Err()).Err()
		}
		s.logger.ErrorContext(ctx, "poll work: claim failed",
			slog.String("tenant", tenant),
			slog.String("kind", target.Kind),
			slog.String("name", target.Name),
			slog.String("instance_id", req.InstanceId),
			slog.String("error", err.Error()),
		)
		return nil, status.Errorf(codes.Internal, "failed to claim work item: %v", err)
	}

	if item == nil {
		// Timeout elapsed with no work available — empty response is the
		// normal signal for the component to loop.
		return &componentpb.PollWorkResponse{}, nil
	}

	s.logger.InfoContext(ctx, "poll work: dispatched work item",
		slog.String("tenant", tenant),
		slog.String("kind", target.Kind),
		slog.String("name", target.Name),
		slog.String("instance_id", req.InstanceId),
		slog.String("work_id", item.WorkID),
		slog.String("work_type", item.WorkType),
	)

	// Register the work-item→mission mapping so that MemoryGet/MemorySet/
	// MemorySearch can resolve the correct per-mission namespace later.
	// This is best-effort: if it fails we still return the work item; the
	// agent will receive a NotFound on any memory RPC rather than a hard failure.
	if s.workContext != nil && item.WorkID != "" {
		missionID := item.Context["mission_id"]
		if missionID != "" {
			// A shared (_system) component claims across every tenant's stream,
			// so its own identity is not the work item's tenant. Record the
			// tenant the item was claimed from — Claim takes it from the stream
			// key, not from the component — so the mapping names the tenant that
			// actually owns the work.
			ownerTenant := tenant
			if tenant == systemTenant && item.Context["tenant_id"] != "" {
				ownerTenant = item.Context["tenant_id"]
			}
			if err := s.workContext.RegisterWorkContext(ctx, item.WorkID, missionID, ownerTenant); err != nil {
				s.logger.WarnContext(ctx, "poll work: failed to register work context for memory resolver; memory RPCs will return NotFound",
					slog.String("tenant", tenant),
					slog.String("work_id", item.WorkID),
					slog.String("mission_id", missionID),
					slog.String("error", err.Error()),
				)
			}
		}
	}

	// Enrich context with mission execution metadata for pull-mode harness.
	// This enables PlatformHarness to populate MissionExecutionContext(),
	// PlanContext(), and ContinuityMode() from the work item context.
	if item.Context == nil {
		item.Context = make(map[string]string)
	}
	if s.missionMgr != nil {
		// The mission id comes from the work item the daemon itself
		// enqueued, not from anything the poller said — the seam takes a
		// mission id for exactly that reason (it used to take the work id
		// and re-resolve it, which meant trusting a caller-echoed id on a
		// path that already knew the answer).
		missionID := item.Context["mission_id"]
		if missionID != "" {
			if execCtxJSON, err := s.missionMgr.GetMissionRunHistory(ctx, tenant, missionID); err == nil && len(execCtxJSON) > 0 {
				item.Context["mission_execution_context_json"] = string(execCtxJSON)
			}
		}
	}

	return &componentpb.PollWorkResponse{
		WorkId:    item.WorkID,
		WorkType:  item.WorkType,
		Payload:   item.Payload,
		Context:   item.Context,
		TimeoutMs: item.TimeoutMs,
	}, nil
}

// ---------------------------------------------------------------------------
// SubmitResult
// ---------------------------------------------------------------------------

// resolveWorkOwner checks that tenant is entitled to act on workID and returns
// the tenant that enqueued it.
//
// A work id is a routing token the daemon hands to a remote component, and it
// comes back to the daemon on RPCs that component controls. It therefore proves
// nothing on its own: possession of an id is not evidence of entitlement to the
// work it names. Every RPC that accepts a component-supplied work id resolves
// the tenant that enqueued it and compares that to the caller's authenticated
// tenant before letting the id select any state.
//
// The owning tenant is returned rather than the caller's because they differ for
// shared components: a _system deployment serves every tenant's queue, so the
// state a work item touches belongs to the tenant that enqueued it.
//
// Unknown and foreign work ids are refused with the same message, so the
// response does not reveal whether an id exists.
func (s *ComponentServiceServer) resolveWorkOwner(ctx context.Context, tenant, workID string) (string, error) {
	const denied = "work_id %q is not an outstanding work item for this tenant"

	if s.workContext == nil {
		// Ownership cannot be established, so it must not be assumed. Refusing
		// keeps an unwired registry from becoming a way to skip the check.
		s.logger.ErrorContext(ctx, "work ownership: registry not wired; refusing work-scoped request",
			slog.String("tenant", tenant),
			slog.String("work_id", workID),
		)
		return "", status.Error(codes.FailedPrecondition, "work-context registry is not configured")
	}

	owner, err := s.workContext.WorkOwner(ctx, workID)
	if err != nil {
		if errors.Is(err, ErrWorkOwnerUnknown) {
			s.logger.WarnContext(ctx, "work ownership: no owner on record for work id",
				slog.String("tenant", tenant),
				slog.String("work_id", workID),
			)
			return "", status.Errorf(codes.PermissionDenied, denied, workID)
		}
		s.logger.ErrorContext(ctx, "work ownership: owner lookup failed",
			slog.String("tenant", tenant),
			slog.String("work_id", workID),
			slog.String("error", err.Error()),
		)
		return "", status.Errorf(codes.Internal, "failed to resolve owner of work %q", workID)
	}

	if !tenantMayActOnWork(tenant, owner) {
		s.logger.WarnContext(ctx, "work ownership: caller is not entitled to this work item",
			slog.String("tenant", tenant),
			slog.String("work_id", workID),
		)
		return "", status.Errorf(codes.PermissionDenied, denied, workID)
	}

	return owner, nil
}

// SubmitResult accepts the outcome of a completed work item from a component.
//
// Flow:
//  1. Extract tenant from context and confirm the caller owns the work item the
//     result claims to answer. The work id arrives from the component, so it is
//     checked against the owner recorded at enqueue rather than trusted.
//  2. Convert the optional proto ComponentError to a WorkError.
//  3. Call queue.DeliverResult to persist the result and unblock any caller
//     waiting in WaitForResult.
//  4. Return an empty response.
func (s *ComponentServiceServer) SubmitResult(
	ctx context.Context,
	req *componentpb.SubmitResultRequest,
) (*componentpb.SubmitResultResponse, error) {
	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "missing tenant in context")
	}

	if req.WorkId == "" {
		return nil, status.Error(codes.InvalidArgument, "work_id is required")
	}

	workOwner, err := s.resolveWorkOwner(ctx, tenant, req.WorkId)
	if err != nil {
		return nil, err
	}

	result := WorkResult{
		WorkID: req.WorkId,
		Result: req.Result,
	}

	if req.Error != nil && req.Error.Code != "" {
		result.Error = &WorkError{
			Code:      req.Error.Code,
			Message:   req.Error.Message,
			Retryable: req.Error.Retryable,
		}
	}

	if err = s.queue.DeliverResult(ctx, req.WorkId, result); err != nil {
		s.logger.ErrorContext(ctx, "submit result: deliver failed",
			slog.String("tenant", tenant),
			slog.String("work_id", req.WorkId),
			slog.String("error", err.Error()),
		)
		return nil, status.Errorf(codes.Internal, "failed to deliver result for work %q: %v", req.WorkId, err)
	}

	s.logger.InfoContext(ctx, "submit result: result delivered",
		slog.String("tenant", tenant),
		slog.String("work_id", req.WorkId),
		slog.Bool("has_error", result.Error != nil),
	)

	// Additive side-effect: if the tool response contains a DiscoveryResult (proto field 100)
	// and a discoveryProcessor is wired, persist the discovered entities to Neo4j.
	// This runs asynchronously so it never delays the response to the component.
	//
	// The work id is safe to use as the graph scope here only because ownership
	// was established above: it is a work item of the owning tenant, not an
	// arbitrary string the component chose. The scope is the work item's owner
	// rather than the caller, because a shared component returns results for
	// tenants other than itself; stamping it keeps the write from landing
	// owner-less.
	if s.discoveryProcessor != nil && len(req.Result) > 0 {
		if discovery := extractDiscoveryField100(req.Result); discovery != nil {
			tenantID, tenantErr := auth.NewTenantID(workOwner)
			if tenantErr != nil {
				s.logger.WarnContext(ctx, "submit result: work owner is not a graph-addressable tenant; discovery not processed",
					slog.String("tenant", tenant),
					slog.String("work_owner", workOwner),
					slog.String("work_id", req.WorkId),
					slog.String("error", tenantErr.Error()),
				)
				return &componentpb.SubmitResultResponse{}, nil
			}

			go func() {
				// Carry the request context for its values (trace, tenant) but
				// strip cancellation: the RPC returns before this finishes.
				processCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
				defer cancel()
				// Scope to the owning tenant so tenant-scoped stores downstream
				// route to it rather than to the caller.
				processCtx = auth.ContextWithTenantString(processCtx, workOwner)

				execCtx := ingest.ExecContext{
					MissionRunID: req.WorkId,
					TenantID:     tenantID,
				}

				if _, err := s.discoveryProcessor.Process(processCtx, execCtx, discovery); err != nil {
					s.logger.WarnContext(processCtx, "submit result: discovery processing failed (best-effort)",
						slog.String("tenant", tenant),
						slog.String("work_id", req.WorkId),
						slog.String("error", err.Error()),
					)
				} else {
					s.logger.DebugContext(processCtx, "submit result: discovery processed",
						slog.String("tenant", tenant),
						slog.String("work_id", req.WorkId),
					)
				}
			}()
		}
	}

	return &componentpb.SubmitResultResponse{}, nil
}

// extractDiscoveryField100 parses raw proto bytes and extracts the DiscoveryResult
// stored at field number 100 (the standard discovery field convention for all
// Gibson tool responses). Returns nil if field 100 is absent or malformed.
func extractDiscoveryField100(raw []byte) *graphragpb.DiscoveryResult {
	const discoveryFieldNumber = 100
	b := raw
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			break
		}
		b = b[n:]
		if num == discoveryFieldNumber && typ == protowire.BytesType {
			fieldBytes, n := protowire.ConsumeBytes(b)
			if n < 0 {
				break
			}
			var result graphragpb.DiscoveryResult
			if err := proto.Unmarshal(fieldBytes, &result); err == nil {
				return &result
			}
			break
		}
		// Skip fields that are not field 100.
		n = protowire.ConsumeFieldValue(num, typ, b)
		if n < 0 {
			break
		}
		b = b[n:]
	}
	return nil
}

// ---------------------------------------------------------------------------
// Harness proxy RPCs
//
// The methods below proxy operations that a remote agent needs to perform
// during task execution — LLM completions, tool/plugin dispatch, finding
// submission, and memory access — back to Gibson's internal subsystems.
//
// Each method follows the same tenant-extraction pattern as the lifecycle RPCs
// above. Nil dependencies cause the method to return codes.Unimplemented so
// that operators can incrementally wire subsystems without breaking the server.
// ---------------------------------------------------------------------------

// Complete proxies an LLM completion request from a remote agent to Gibson's
// LLM provider system.
//
// Flow:
//  1. Extract tenant; reject unauthenticated callers.
//  2. Validate required fields (slot, messages).
//  3. Marshal req.Messages to JSON for the LLMCompleter interface.
//  4. Resolve mission context so that slot resolution uses per-mission model
//     configuration rather than tenant-level defaults.
//  5. Delegate to llmCompleter.Complete which resolves the slot to a provider
//     and model, forwards the messages, and returns usage metrics.
//  6. Return the assistant content and token usage to the caller.
func (s *ComponentServiceServer) Complete(
	ctx context.Context,
	req *componentpb.CompleteRequest,
) (*componentpb.CompleteResponse, error) {
	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "missing tenant in context")
	}

	if s.llmCompleter == nil {
		return nil, status.Error(codes.Unimplemented, "LLM completion not yet wired on this server")
	}

	if req.Slot == "" {
		return nil, status.Error(codes.InvalidArgument, "slot is required")
	}
	if len(req.Messages) == 0 {
		return nil, status.Error(codes.InvalidArgument, "messages is required")
	}

	messagesJSON, err := json.Marshal(req.Messages)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to marshal messages: %v", err)
	}

	s.logger.DebugContext(ctx, "complete: routing LLM request",
		slog.String("tenant", tenant),
		slog.String("work_id", req.WorkId),
		slog.String("slot", req.Slot),
	)

	// Resolve per-mission slot overrides. Missing context is not an error;
	// the resolver returns empty strings and nil overrides so we fall back to
	// the tenant-level defaults that were in place before this lookup was added.
	missionID, slotOverrides, resolveErr := resolveMissionContext(ctx, s.missionCtx, req.WorkId, tenant, req.Slot, s.logger)
	if resolveErr != nil {
		// Log and continue; the lookup is best-effort.
		s.logger.WarnContext(ctx, "complete: mission context lookup failed; using tenant defaults",
			slog.String("tenant", tenant),
			slog.String("work_id", req.WorkId),
			slog.String("slot", req.Slot),
			slog.String("error", resolveErr.Error()),
		)
	}

	maxTokens, temperature := applySlotOverrides(req.Slot, slotOverrides)

	content, finishReason, modelUsed, promptTokens, completionTokens, err := s.llmCompleter.Complete(
		ctx,
		tenant,
		missionID,
		req.Slot,
		string(messagesJSON),
		maxTokens,
		temperature,
	)
	if err != nil {
		s.logger.ErrorContext(ctx, "complete: LLM completion failed",
			slog.String("tenant", tenant),
			slog.String("work_id", req.WorkId),
			slog.String("slot", req.Slot),
			slog.String("error", err.Error()),
		)
		return nil, status.Errorf(codes.Internal, "LLM completion failed: %v", err)
	}

	s.logger.InfoContext(ctx, "complete: LLM completion succeeded",
		slog.String("tenant", tenant),
		slog.String("work_id", req.WorkId),
		slog.String("slot", req.Slot),
		slog.String("model_used", modelUsed),
		slog.Int("prompt_tokens", int(promptTokens)),
		slog.Int("completion_tokens", int(completionTokens)),
	)

	_ = finishReason // captured in response via Done on stream; not surfaced in unary response

	return &componentpb.CompleteResponse{
		Response: &componentpb.LLMMessage{
			Role:    "assistant",
			Content: content,
		},
		Usage: &componentpb.TokenUsage{
			InputTokens:  promptTokens,
			OutputTokens: completionTokens,
		},
	}, nil
}

// CompleteStream is the server-streaming variant of Complete. It invokes the
// LLM and sends incremental content deltas to the client as they arrive.
// Mission context is resolved from the work_id so that slot resolution uses
// per-mission model configuration rather than tenant-level defaults.
//
// The final chunk carries Done=true to signal stream termination. On error
// mid-stream, the gRPC error status is returned after a best-effort final chunk.
func (s *ComponentServiceServer) CompleteStream(
	req *componentpb.CompleteStreamRequest,
	stream grpc.ServerStreamingServer[componentpb.CompleteStreamResponse],
) error {
	ctx := stream.Context()

	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" {
		return status.Error(codes.Unauthenticated, "missing tenant in context")
	}

	if s.llmCompleter == nil {
		return status.Error(codes.Unimplemented, "LLM streaming not yet wired on this server")
	}

	if req.Slot == "" {
		return status.Error(codes.InvalidArgument, "slot is required")
	}
	if len(req.Messages) == 0 {
		return status.Error(codes.InvalidArgument, "messages is required")
	}

	messagesJSON, err := json.Marshal(req.Messages)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "failed to marshal messages: %v", err)
	}

	s.logger.DebugContext(ctx, "complete stream: starting streaming LLM request",
		slog.String("tenant", tenant),
		slog.String("work_id", req.WorkId),
		slog.String("slot", req.Slot),
	)

	// Resolve per-mission slot overrides. Missing context is not an error;
	// the resolver returns empty strings and nil overrides so we fall back to
	// the tenant-level defaults that were in place before this lookup was added.
	missionID, slotOverrides, resolveErr := resolveMissionContext(ctx, s.missionCtx, req.WorkId, tenant, req.Slot, s.logger)
	if resolveErr != nil {
		s.logger.WarnContext(ctx, "complete stream: mission context lookup failed; using tenant defaults",
			slog.String("tenant", tenant),
			slog.String("work_id", req.WorkId),
			slog.String("slot", req.Slot),
			slog.String("error", resolveErr.Error()),
		)
	}

	maxTokens, temperature := applySlotOverrides(req.Slot, slotOverrides)

	err = s.llmCompleter.Stream(
		ctx,
		tenant,
		missionID,
		req.Slot,
		string(messagesJSON),
		maxTokens,
		temperature,
		func(delta, finishReason string) error {
			done := finishReason != ""
			return stream.Send(&componentpb.CompleteStreamResponse{
				Content: delta,
				Done:    done,
			})
		},
	)
	if err != nil {
		s.logger.ErrorContext(ctx, "complete stream: streaming LLM request failed",
			slog.String("tenant", tenant),
			slog.String("work_id", req.WorkId),
			slog.String("slot", req.Slot),
			slog.String("error", err.Error()),
		)
		// Best-effort: send a done chunk before returning the gRPC error so
		// that clients that do not inspect the trailing status still see the
		// stream terminated.
		_ = stream.Send(&componentpb.CompleteStreamResponse{Done: true})
		return status.Errorf(codes.Internal, "LLM streaming failed: %v", err)
	}

	return nil
}

// CallTool dispatches a tool invocation on behalf of a remote agent.
//
// Flow:
//  1. Extract tenant; reject unauthenticated callers.
//  2. Validate required fields.
//  3. Discover tool instances via registry (tenant namespace first, then _system).
//  4. Enqueue a work item on the tool's work stream via WorkQueue.Enqueue.
//  5. Block on WorkQueue.WaitForResult until the tool responds or the timeout
//     elapses.
//  6. Return the tool output or surface the tool's structured error.
//
// The direct in-cluster gRPC call path (for tools that have a gRPC endpoint in
// their ComponentInfo.Metadata) is deferred: all dispatch goes through the
// work queue for now, keeping the flow uniform and observable.
func (s *ComponentServiceServer) CallTool(
	ctx context.Context,
	req *componentpb.CallToolRequest,
) (*componentpb.CallToolResponse, error) {
	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "missing tenant in context")
	}

	if req.ToolName == "" {
		return nil, status.Error(codes.InvalidArgument, "tool_name is required")
	}
	if req.InputJson == "" {
		return nil, status.Error(codes.InvalidArgument, "input_json is required")
	}

	// Discover tool: tenant-scoped first, then _system fallback (handled by Discover).
	instances, err := s.registry.Discover(ctx, tenant, "tool", req.ToolName)
	if err != nil {
		s.logger.ErrorContext(ctx, "call tool: discovery failed",
			slog.String("tenant", tenant),
			slog.String("tool_name", req.ToolName),
			slog.String("error", err.Error()),
		)
		return nil, status.Errorf(codes.Internal, "tool discovery failed: %v", err)
	}
	if len(instances) == 0 {
		s.logger.WarnContext(ctx, "call tool: tool not found",
			slog.String("tenant", tenant),
			slog.String("tool_name", req.ToolName),
		)
		return nil, status.Errorf(codes.NotFound, "tool %q not available for tenant %q", req.ToolName, tenant)
	}

	// Build the work item targeting the tool component. The work id is minted
	// here and waited on below: Enqueue returns the Redis stream message id,
	// which is not what the component echoes back on SubmitResult.
	workID := uuid.New().String()
	workItem := WorkItem{
		WorkID:    workID,
		WorkType:  "execute_proto",
		Payload:   []byte(req.InputJson),
		TimeoutMs: req.TimeoutMs,
		Context: map[string]string{
			"source_work_id": req.WorkId,
			"caller_tenant":  tenant,
		},
	}

	if _, err := s.queue.Enqueue(ctx, tenant, "tool", req.ToolName, workItem); err != nil {
		s.logger.ErrorContext(ctx, "call tool: enqueue failed",
			slog.String("tenant", tenant),
			slog.String("tool_name", req.ToolName),
			slog.String("error", err.Error()),
		)
		return nil, status.Errorf(codes.Internal, "failed to enqueue tool work: %v", err)
	}

	timeout := time.Duration(req.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}

	s.logger.DebugContext(ctx, "call tool: waiting for result",
		slog.String("tenant", tenant),
		slog.String("tool_name", req.ToolName),
		slog.String("work_id", workID),
		slog.Duration("timeout", timeout),
	)

	result, err := s.queue.WaitForResult(ctx, workID, timeout)
	if err != nil {
		s.logger.ErrorContext(ctx, "call tool: wait for result failed",
			slog.String("tenant", tenant),
			slog.String("tool_name", req.ToolName),
			slog.String("work_id", workID),
			slog.String("error", err.Error()),
		)
		return nil, status.Errorf(codes.DeadlineExceeded, "tool execution timed out or failed: %v", err)
	}

	resp := &componentpb.CallToolResponse{OutputJson: string(result.Result)}
	if result.Error != nil && result.Error.Code != "" {
		resp.Error = &componentpb.ComponentError{
			Code:    fmt.Sprintf("[%s]", result.Error.Code),
			Message: result.Error.Message,
		}
	}

	s.logger.InfoContext(ctx, "call tool: result received",
		slog.String("tenant", tenant),
		slog.String("tool_name", req.ToolName),
		slog.String("work_id", workID),
		slog.Bool("has_error", resp.Error != nil),
	)

	return resp, nil
}

// QueryPlugin dispatches a plugin query on behalf of a remote agent.
//
// The dispatch pattern is identical to CallTool — discover via registry,
// enqueue on the plugin's work stream, wait for result — with the component
// kind set to "plugin" instead of "tool".
func (s *ComponentServiceServer) QueryPlugin(
	ctx context.Context,
	req *componentpb.QueryPluginRequest,
) (*componentpb.QueryPluginResponse, error) {
	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "missing tenant in context")
	}

	if req.PluginName == "" {
		return nil, status.Error(codes.InvalidArgument, "plugin_name is required")
	}
	if req.ParamsJson == "" {
		return nil, status.Error(codes.InvalidArgument, "params_json is required")
	}

	// Discover plugin: tenant-scoped first, then _system fallback.
	instances, err := s.registry.Discover(ctx, tenant, "plugin", req.PluginName)
	if err != nil {
		s.logger.ErrorContext(ctx, "query plugin: discovery failed",
			slog.String("tenant", tenant),
			slog.String("plugin_name", req.PluginName),
			slog.String("error", err.Error()),
		)
		return nil, status.Errorf(codes.Internal, "plugin discovery failed: %v", err)
	}
	if len(instances) == 0 {
		s.logger.WarnContext(ctx, "query plugin: plugin not found",
			slog.String("tenant", tenant),
			slog.String("plugin_name", req.PluginName),
		)
		return nil, status.Errorf(codes.NotFound, "plugin %q not available for tenant %q", req.PluginName, tenant)
	}

	workCtx := map[string]string{
		"source_work_id": req.WorkId,
		"caller_tenant":  tenant,
		"method":         req.Method,
	}

	// Inject plugin_config for _system plugins so the remote worker has the
	// tenant's decrypted credentials available in the work item context.
	// Only injected for _system instances — tenant-scoped plugins own their
	// own config and must never receive another tenant's credentials.
	if instances[0].TenantID == "_system" && s.componentAccess != nil {
		pluginCfg, cfgErr := s.componentAccess.GetDecryptedConfig(ctx, tenant, req.PluginName)
		if cfgErr == nil {
			cfgJSON, marshalErr := json.Marshal(pluginCfg)
			if marshalErr == nil {
				workCtx["plugin_config"] = string(cfgJSON)
			} else {
				s.logger.WarnContext(ctx, "query plugin: failed to marshal plugin config for work item context, proceeding without it",
					slog.String("tenant", tenant),
					slog.String("plugin_name", req.PluginName),
					slog.String("error", marshalErr.Error()),
				)
			}
		} else {
			s.logger.WarnContext(ctx, "query plugin: failed to retrieve plugin config for work item context, proceeding without it",
				slog.String("tenant", tenant),
				slog.String("plugin_name", req.PluginName),
				slog.String("error", cfgErr.Error()),
			)
		}
	}

	// Mint the work id here and wait on it: Enqueue returns the Redis stream
	// message id, which is not what the component echoes back on SubmitResult.
	workID := uuid.New().String()
	workItem := WorkItem{
		WorkID:    workID,
		WorkType:  "execute_proto",
		Payload:   []byte(req.ParamsJson),
		TimeoutMs: req.TimeoutMs,
		Context:   workCtx,
	}

	if _, err := s.queue.Enqueue(ctx, tenant, "plugin", req.PluginName, workItem); err != nil {
		s.logger.ErrorContext(ctx, "query plugin: enqueue failed",
			slog.String("tenant", tenant),
			slog.String("plugin_name", req.PluginName),
			slog.String("error", err.Error()),
		)
		return nil, status.Errorf(codes.Internal, "failed to enqueue plugin work: %v", err)
	}

	timeout := time.Duration(req.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}

	s.logger.DebugContext(ctx, "query plugin: waiting for result",
		slog.String("tenant", tenant),
		slog.String("plugin_name", req.PluginName),
		slog.String("work_id", workID),
		slog.Duration("timeout", timeout),
	)

	result, err := s.queue.WaitForResult(ctx, workID, timeout)
	if err != nil {
		s.logger.ErrorContext(ctx, "query plugin: wait for result failed",
			slog.String("tenant", tenant),
			slog.String("plugin_name", req.PluginName),
			slog.String("work_id", workID),
			slog.String("error", err.Error()),
		)
		return nil, status.Errorf(codes.DeadlineExceeded, "plugin execution timed out or failed: %v", err)
	}

	resp := &componentpb.QueryPluginResponse{ResultJson: string(result.Result)}
	if result.Error != nil && result.Error.Code != "" {
		resp.Error = &componentpb.ComponentError{
			Code:    fmt.Sprintf("[%s]", result.Error.Code),
			Message: result.Error.Message,
		}
	}

	s.logger.InfoContext(ctx, "query plugin: result received",
		slog.String("tenant", tenant),
		slog.String("plugin_name", req.PluginName),
		slog.String("work_id", workID),
		slog.Bool("has_error", resp.Error != nil),
	)

	return resp, nil
}

// SubmitFinding accepts a serialized finding from a remote agent and persists it.
//
// Flow:
//  1. Extract tenant; reject unauthenticated callers.
//  2. Validate that finding is present.
//  3. Delegate to findingSubmitter if wired; otherwise generate a finding_id
//     and log the payload so that no findings are silently dropped during
//     the development phase.
//
// The finding reaches the knowledge graph through findingSubmitter's World sink
// and the graph projector, never from here (ADR-0007/ADR-0012).
func (s *ComponentServiceServer) SubmitFinding(
	ctx context.Context,
	req *componentpb.SubmitFindingRequest,
) (*componentpb.SubmitFindingResponse, error) {
	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "missing tenant in context")
	}

	if len(req.Finding) == 0 {
		return nil, status.Error(codes.InvalidArgument, "finding is required")
	}

	// Bounds before anything else touches the payload (ADR-0012, "Write
	// contract"). The byte cap is checked ahead of the JSON parse, and both
	// checks run ahead of every write below, so an over-limit emit is
	// rejected whole and leaves no partial state. Nothing is truncated.
	if err := emitbounds.CheckPayload(req.Finding); err != nil {
		s.logger.WarnContext(ctx, "submit finding: rejected by emit bounds",
			slog.String("tenant", tenant),
			slog.String("work_id", req.WorkId),
			slog.String("error", err.Error()),
		)
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := s.emitCounter().Admit(req.WorkId); err != nil {
		s.logger.WarnContext(ctx, "submit finding: rejected by emit bounds",
			slog.String("tenant", tenant),
			slog.String("work_id", req.WorkId),
			slog.String("error", err.Error()),
		)
		return nil, status.Error(codes.ResourceExhausted, err.Error())
	}

	// A finding may be submitted outside any work item (work_id empty), in which
	// case it is simply tenant-ambient. When a work id IS supplied it selects the
	// mission the finding is attributed to, so the caller must own it. The owner's
	// name is not needed here — the submitter's World sink scopes the finding —
	// but the ownership check is, and it fails the RPC when it does not hold.
	if req.WorkId != "" {
		if _, ownerErr := s.resolveWorkOwner(ctx, tenant, req.WorkId); ownerErr != nil {
			return nil, ownerErr
		}
	}

	findingJSON := string(req.Finding)

	if s.findingSubmitter != nil {
		findingID, err := s.findingSubmitter.Submit(
			ctx,
			tenant,
			req.WorkId,
			findingJSON,
			"", // severity no longer in proto
			"", // title no longer in proto
		)
		if err != nil {
			s.logger.ErrorContext(ctx, "submit finding: storage failed",
				slog.String("tenant", tenant),
				slog.String("work_id", req.WorkId),
				slog.String("error", err.Error()),
			)
			return nil, status.Errorf(codes.Internal, "failed to store finding: %v", err)
		}

		s.logger.InfoContext(ctx, "submit finding: finding stored",
			slog.String("tenant", tenant),
			slog.String("work_id", req.WorkId),
			slog.String("finding_id", findingID),
		)

		return &componentpb.SubmitFindingResponse{FindingId: findingID}, nil
	}

	// findingSubmitter not yet wired — generate an ID and log the payload so
	// that findings are traceable during development without being silently lost.
	findingID := uuid.New().String()

	s.logger.WarnContext(ctx, "submit finding: no finding submitter wired; logging payload only",
		slog.String("tenant", tenant),
		slog.String("work_id", req.WorkId),
		slog.String("finding_id", findingID),
		slog.String("finding_json", findingJSON),
	)

	return &componentpb.SubmitFindingResponse{FindingId: findingID}, nil
}

// ListAvailablePlugins returns the full plugin catalog visible to the calling
// tenant, with each entry annotated with the tenant's enablement status.
func (s *ComponentServiceServer) ListAvailablePlugins(
	ctx context.Context,
	_ *componentpb.ListAvailablePluginsRequest,
) (*componentpb.ListAvailablePluginsResponse, error) {
	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "missing tenant in context")
	}

	if s.componentAccess == nil {
		return nil, status.Error(codes.Unimplemented, "plugin access store not yet wired on this server")
	}

	entries, err := s.componentAccess.ListAvailablePlugins(ctx, tenant)
	if err != nil {
		s.logger.ErrorContext(ctx, "list available plugins: failed",
			slog.String("tenant", tenant),
			slog.String("error", err.Error()),
		)
		return nil, status.Errorf(codes.Internal, "failed to list available plugins: %v", err)
	}

	protos := make([]*componentpb.PluginCatalogEntryProto, 0, len(entries))
	for _, e := range entries {
		protos = append(protos, &componentpb.PluginCatalogEntryProto{
			Name:             e.Name,
			Version:          e.Version,
			Description:      e.Description,
			Methods:          e.Methods,
			ConfigSchemaJson: e.ConfigSchema,
			Enabled:          e.Enabled,
			Configured:       e.Configured,
			HealthStatus:     e.HealthStatus,
			Source:           e.Source,
			InstanceCount:    int32(e.InstanceCount),
		})
	}

	s.logger.DebugContext(ctx, "list available plugins: completed",
		slog.String("tenant", tenant),
		slog.Int("count", len(protos)),
	)

	return &componentpb.ListAvailablePluginsResponse{Plugins: protos}, nil
}

// EnablePlugin activates a plugin for the calling tenant, optionally supplying
// initial configuration as a JSON object.
func (s *ComponentServiceServer) EnablePlugin(
	ctx context.Context,
	req *componentpb.EnablePluginRequest,
) (*componentpb.EnablePluginResponse, error) {
	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "missing tenant in context")
	}

	if s.componentAccess == nil {
		return nil, status.Error(codes.Unimplemented, "plugin access store not yet wired on this server")
	}

	if req.PluginName == "" {
		return nil, status.Error(codes.InvalidArgument, "plugin_name is required")
	}

	var cfg map[string]any
	if req.ConfigJson != "" {
		if err := json.Unmarshal([]byte(req.ConfigJson), &cfg); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "config_json is not valid JSON: %v", err)
		}
	}

	if err := s.componentAccess.Enable(ctx, tenant, req.PluginName, cfg, tenant); err != nil {
		s.logger.ErrorContext(ctx, "enable plugin: failed",
			slog.String("tenant", tenant),
			slog.String("plugin_name", req.PluginName),
			slog.String("error", err.Error()),
		)
		return nil, componentAccessErrToStatus(err, req.PluginName)
	}

	s.logger.InfoContext(ctx, "enable plugin: plugin enabled",
		slog.String("tenant", tenant),
		slog.String("plugin_name", req.PluginName),
	)

	if s.auditLog != nil {
		s.auditLog.Log(ctx, "plugin.enable", "plugin", req.PluginName, nil)
	}

	return &componentpb.EnablePluginResponse{
		Success: true,
		Message: fmt.Sprintf("plugin %q enabled for tenant %q", req.PluginName, tenant),
	}, nil
}

// DisablePlugin deactivates a plugin for the calling tenant and removes its
// stored configuration.
func (s *ComponentServiceServer) DisablePlugin(
	ctx context.Context,
	req *componentpb.DisablePluginRequest,
) (*componentpb.DisablePluginResponse, error) {
	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "missing tenant in context")
	}

	if s.componentAccess == nil {
		return nil, status.Error(codes.Unimplemented, "plugin access store not yet wired on this server")
	}

	if req.PluginName == "" {
		return nil, status.Error(codes.InvalidArgument, "plugin_name is required")
	}

	if err := s.componentAccess.Disable(ctx, tenant, req.PluginName); err != nil {
		s.logger.ErrorContext(ctx, "disable plugin: failed",
			slog.String("tenant", tenant),
			slog.String("plugin_name", req.PluginName),
			slog.String("error", err.Error()),
		)
		return nil, componentAccessErrToStatus(err, req.PluginName)
	}

	s.logger.InfoContext(ctx, "disable plugin: plugin disabled",
		slog.String("tenant", tenant),
		slog.String("plugin_name", req.PluginName),
	)

	if s.auditLog != nil {
		s.auditLog.Log(ctx, "plugin.disable", "plugin", req.PluginName, nil)
	}

	return &componentpb.DisablePluginResponse{
		Success: true,
		Message: fmt.Sprintf("plugin %q disabled for tenant %q", req.PluginName, tenant),
	}, nil
}

// UpdatePluginConfig replaces the stored configuration for an already-enabled
// plugin. The new config is supplied as a JSON object.
func (s *ComponentServiceServer) UpdatePluginConfig(
	ctx context.Context,
	req *componentpb.UpdatePluginConfigRequest,
) (*componentpb.UpdatePluginConfigResponse, error) {
	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "missing tenant in context")
	}

	if s.componentAccess == nil {
		return nil, status.Error(codes.Unimplemented, "plugin access store not yet wired on this server")
	}

	if req.PluginName == "" {
		return nil, status.Error(codes.InvalidArgument, "plugin_name is required")
	}
	if req.ConfigJson == "" {
		return nil, status.Error(codes.InvalidArgument, "config_json is required")
	}

	var cfg map[string]any
	if err := json.Unmarshal([]byte(req.ConfigJson), &cfg); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "config_json is not valid JSON: %v", err)
	}

	if err := s.componentAccess.UpdateConfig(ctx, tenant, req.PluginName, cfg, tenant); err != nil {
		s.logger.ErrorContext(ctx, "update plugin config: failed",
			slog.String("tenant", tenant),
			slog.String("plugin_name", req.PluginName),
			slog.String("error", err.Error()),
		)
		return nil, componentAccessErrToStatus(err, req.PluginName)
	}

	s.logger.InfoContext(ctx, "update plugin config: config updated",
		slog.String("tenant", tenant),
		slog.String("plugin_name", req.PluginName),
	)

	if s.auditLog != nil {
		s.auditLog.Log(ctx, "plugin.config.update", "plugin", req.PluginName, nil)
	}

	return &componentpb.UpdatePluginConfigResponse{
		Success: true,
		Message: fmt.Sprintf("configuration updated for plugin %q", req.PluginName),
	}, nil
}

// GetPluginConfig returns the masked configuration for an enabled plugin
// together with its JSON Schema so callers can render a config form.
func (s *ComponentServiceServer) GetPluginConfig(
	ctx context.Context,
	req *componentpb.GetPluginConfigRequest,
) (*componentpb.GetPluginConfigResponse, error) {
	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "missing tenant in context")
	}

	if s.componentAccess == nil {
		return nil, status.Error(codes.Unimplemented, "plugin access store not yet wired on this server")
	}

	if req.PluginName == "" {
		return nil, status.Error(codes.InvalidArgument, "plugin_name is required")
	}

	maskedCfg, err := s.componentAccess.GetMaskedConfig(ctx, tenant, req.PluginName)
	if err != nil {
		s.logger.ErrorContext(ctx, "get plugin config: failed",
			slog.String("tenant", tenant),
			slog.String("plugin_name", req.PluginName),
			slog.String("error", err.Error()),
		)
		return nil, componentAccessErrToStatus(err, req.PluginName)
	}

	cfgBytes, err := json.Marshal(maskedCfg)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to serialize masked config: %v", err)
	}

	// Include the schema so clients can render a config form without a second
	// round-trip. Missing schema is not an error — it is returned as an empty
	// string and the caller renders a generic key-value editor.
	schema, err := s.componentAccess.GetConfigSchema(ctx, req.PluginName)
	if err != nil {
		s.logger.WarnContext(ctx, "get plugin config: schema lookup failed; returning empty schema",
			slog.String("tenant", tenant),
			slog.String("plugin_name", req.PluginName),
			slog.String("error", err.Error()),
		)
		schema = ""
	}

	s.logger.DebugContext(ctx, "get plugin config: config retrieved",
		slog.String("tenant", tenant),
		slog.String("plugin_name", req.PluginName),
	)

	return &componentpb.GetPluginConfigResponse{
		ConfigJson:       string(cfgBytes),
		ConfigSchemaJson: schema,
	}, nil
}

// TestPluginConnection validates plugin credentials by dispatching a
// health-check work item to the _system plugin and waiting for the result.
//
// The dispatch pattern mirrors QueryPlugin: the work item is enqueued on the
// _system tenant's plugin work stream with work_type "health_check" so the
// plugin worker can run a lightweight connectivity probe using the supplied
// config without persisting it.
func (s *ComponentServiceServer) TestPluginConnection(
	ctx context.Context,
	req *componentpb.TestPluginConnectionRequest,
) (*componentpb.TestPluginConnectionResponse, error) {
	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "missing tenant in context")
	}

	if s.componentAccess == nil {
		return nil, status.Error(codes.Unimplemented, "plugin access store not yet wired on this server")
	}

	if req.PluginName == "" {
		return nil, status.Error(codes.InvalidArgument, "plugin_name is required")
	}

	// Discover the plugin in the _system namespace; the health probe must reach
	// the actual plugin worker regardless of tenant-level enablement.
	instances, err := s.registry.Discover(ctx, "_system", "plugin", req.PluginName)
	if err != nil {
		s.logger.ErrorContext(ctx, "test plugin connection: discovery failed",
			slog.String("tenant", tenant),
			slog.String("plugin_name", req.PluginName),
			slog.String("error", err.Error()),
		)
		return nil, status.Errorf(codes.Internal, "plugin discovery failed: %v", err)
	}
	if len(instances) == 0 {
		s.logger.WarnContext(ctx, "test plugin connection: plugin not found in _system",
			slog.String("tenant", tenant),
			slog.String("plugin_name", req.PluginName),
		)
		return nil, status.Errorf(codes.NotFound, "plugin %q is not available", req.PluginName)
	}

	// Mint the work id here and wait on it: Enqueue returns the Redis stream
	// message id, which is not what the component echoes back on SubmitResult.
	workID := uuid.New().String()
	workItem := WorkItem{
		WorkID:   workID,
		WorkType: "health_check",
		Payload:  []byte(req.ConfigJson),
		Context: map[string]string{
			"caller_tenant": tenant,
		},
	}

	if _, err := s.queue.Enqueue(ctx, systemTenant, "plugin", req.PluginName, workItem); err != nil {
		s.logger.ErrorContext(ctx, "test plugin connection: enqueue failed",
			slog.String("tenant", tenant),
			slog.String("plugin_name", req.PluginName),
			slog.String("error", err.Error()),
		)
		return nil, status.Errorf(codes.Internal, "failed to enqueue health check: %v", err)
	}

	// Use a conservative timeout for connectivity probes.
	const healthCheckTimeout = 30 * time.Second

	s.logger.DebugContext(ctx, "test plugin connection: waiting for result",
		slog.String("tenant", tenant),
		slog.String("plugin_name", req.PluginName),
		slog.String("work_id", workID),
	)

	start := time.Now()
	result, err := s.queue.WaitForResult(ctx, workID, healthCheckTimeout)
	latencyMs := time.Since(start).Milliseconds()
	if err != nil {
		s.logger.ErrorContext(ctx, "test plugin connection: wait for result failed",
			slog.String("tenant", tenant),
			slog.String("plugin_name", req.PluginName),
			slog.String("work_id", workID),
			slog.String("error", err.Error()),
		)
		return &componentpb.TestPluginConnectionResponse{
			Success:   false,
			Message:   fmt.Sprintf("connection test timed out or failed: %v", err),
			LatencyMs: latencyMs,
		}, nil
	}

	resp := &componentpb.TestPluginConnectionResponse{
		LatencyMs: latencyMs,
	}
	if result.Error != nil && result.Error.Code != "" {
		resp.Success = false
		resp.Message = result.Error.Message
	} else {
		resp.Success = true
		resp.Message = "connection successful"
	}

	s.logger.InfoContext(ctx, "test plugin connection: probe completed",
		slog.String("tenant", tenant),
		slog.String("plugin_name", req.PluginName),
		slog.String("work_id", workID),
		slog.Bool("success", resp.Success),
		slog.Int64("latency_ms", latencyMs),
	)

	return resp, nil
}

// ListTenantPlugins returns all plugin access records belonging to the calling
// tenant, i.e. every plugin the tenant has explicitly enabled.
func (s *ComponentServiceServer) ListTenantPlugins(
	ctx context.Context,
	_ *componentpb.ListTenantPluginsRequest,
) (*componentpb.ListTenantPluginsResponse, error) {
	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "missing tenant in context")
	}

	if s.componentAccess == nil {
		return nil, status.Error(codes.Unimplemented, "plugin access store not yet wired on this server")
	}

	records, err := s.componentAccess.ListTenantPlugins(ctx, tenant)
	if err != nil {
		s.logger.ErrorContext(ctx, "list tenant plugins: failed",
			slog.String("tenant", tenant),
			slog.String("error", err.Error()),
		)
		return nil, status.Errorf(codes.Internal, "failed to list tenant plugins: %v", err)
	}

	protos := make([]*componentpb.PluginAccessProto, 0, len(records))
	for _, r := range records {
		protos = append(protos, &componentpb.PluginAccessProto{
			TenantId:     r.TenantID,
			PluginName:   r.PluginName,
			Enabled:      r.Enabled,
			Source:       r.Source,
			ConfiguredAt: r.ConfiguredAt,
			ConfiguredBy: r.ConfiguredBy,
			HasConfig:    r.HasConfig,
		})
	}

	s.logger.DebugContext(ctx, "list tenant plugins: completed",
		slog.String("tenant", tenant),
		slog.Int("count", len(protos)),
	)

	return &componentpb.ListTenantPluginsResponse{Plugins: protos}, nil
}

// extractMessageTypesFromFDS scans a FileDescriptorSet for proto messages that follow the
// Gibson tool convention: one *Request message for input and one *Response message for output.
// It returns the fully-qualified type names (package + "." + message name).
//
// This is called during RegisterComponent when a FileDescriptorSet is present but the
// explicit InputMessageType/OutputMessageType fields are empty, providing automatic type
// resolution without requiring tools to repeat information already encoded in their protos.
func extractMessageTypesFromFDS(fds *descriptorpb.FileDescriptorSet) (inputType, outputType string) {
	if fds == nil {
		return
	}
	for _, fd := range fds.GetFile() {
		pkg := fd.GetPackage()
		for _, msg := range fd.GetMessageType() {
			name := msg.GetName()
			qualified := name
			if pkg != "" {
				qualified = pkg + "." + name
			}
			if strings.HasSuffix(name, "Request") {
				inputType = qualified
			}
			if strings.HasSuffix(name, "Response") {
				outputType = qualified
			}
		}
	}
	return
}

// componentAccessErrToStatus converts sentinel errors from ComponentAccessStore to
// the appropriate gRPC status codes.
func componentAccessErrToStatus(err error, componentName string) error {
	switch {
	case errors.Is(err, ErrComponentNotEnabled):
		return status.Errorf(codes.NotFound, "plugin %q is not enabled for this tenant; enable it first", componentName)
	case errors.Is(err, ErrComponentNotConfigured):
		return status.Errorf(codes.FailedPrecondition, "plugin %q is enabled but has no configuration stored", componentName)
	default:
		return status.Errorf(codes.Internal, "plugin access operation failed: %v", err)
	}
}

// contentTrustFromMetadata maps the plugin:content_trust registration metadata
// value (set by the SDK from the manifest's spec.policy.content_trust) to the
// componentpb.ContentTrust enum. "untrusted" opts the component into
// dispatch-policy gating (ADR-0010 / gibson#997); "trusted" is explicit-trusted;
// any other value (including empty, for registrants that predate the field)
// maps to UNSPECIFIED, which the gate treats as trusted.
func contentTrustFromMetadata(v string) componentpb.ContentTrust {
	switch v {
	case "untrusted":
		return componentpb.ContentTrust_CONTENT_TRUST_UNTRUSTED
	case "trusted":
		return componentpb.ContentTrust_CONTENT_TRUST_TRUSTED
	default:
		return componentpb.ContentTrust_CONTENT_TRUST_UNSPECIFIED
	}
}
