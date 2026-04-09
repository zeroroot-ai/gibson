package component

// service.go implements the ComponentServiceServer gRPC handlers.
//
// This server is the single ingress point that all Gibson components (agents,
// tools, plugins) connect to. It delegates to ComponentRegistry for lifecycle
// tracking and WorkQueue for pull-based work dispatch.
//
// Generated proto code location: github.com/zero-day-ai/sdk/api/gen/componentpb

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

	"github.com/zero-day-ai/gibson/internal/audit"
	"github.com/zero-day-ai/gibson/internal/auth"
	"github.com/zero-day-ai/gibson/internal/graphrag/loader"
	"github.com/zero-day-ai/gibson/internal/memory"
	"github.com/zero-day-ai/gibson/internal/types"
	componentpb "github.com/zero-day-ai/sdk/api/gen/gibson/component/v1"
	graphragpb "github.com/zero-day-ai/sdk/api/gen/gibson/graphrag/v1"
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
// The JSON payload must conform to the agent.Finding schema.
// When graphLoader is also wired, the finding is additionally stored to Neo4j
// via LoadFindings for knowledge graph integration.
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
	Process(ctx context.Context, execCtx loader.ExecContext, discovery *graphragpb.DiscoveryResult) (interface{}, error)
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
// via auth.TenantFromContext and forwarded to both the registry and queue so
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

	// memory provides access to all three memory tiers on behalf of remote agents.
	// May be nil; MemoryGet, MemorySet, and MemorySearch fall back to
	// memoryResolver when non-nil, or return codes.Unimplemented when both are nil.
	memory memory.MemoryStore

	// memoryResolver maps a work_id to its mission-scoped MissionMemory instance.
	// When non-nil it takes precedence over the shared s.memory.Mission() for
	// mission-tier operations, giving each agent access to its own namespace.
	// May be nil; the server falls back to s.memory when nil.
	memoryResolver MemoryResolver

	// missionCtx resolves a work item ID to its parent mission ID and any
	// per-mission LLM slot overrides. Used by Complete and CompleteStream to
	// apply per-mission provider configuration before delegating to llmCompleter.
	// May be nil; when nil, Complete and CompleteStream pass an empty missionID
	// and no overrides (current behaviour preserved).
	missionCtx *MissionContextResolver

	// findingSubmitter persists findings from remote agents.
	// May be nil; SubmitFinding logs and generates an ID when nil.
	findingSubmitter FindingSubmitter

	// pluginAccess manages tenant opt-in and encrypted configuration for plugins.
	// May be nil; plugin access RPCs return codes.Unimplemented when nil.
	pluginAccess PluginAccessStore

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

	// agentDelegator dispatches sub-agent execution for remote agents.
	// May be nil; delegation RPCs return codes.Unimplemented when nil.
	agentDelegator AgentDelegator

	// componentLister provides tool/agent discovery for remote agents.
	// May be nil; list RPCs return codes.Unimplemented when nil.
	componentLister ComponentLister

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

	// graphLoader persists finding nodes to Neo4j when SubmitFinding succeeds.
	// May be nil; when nil, findings are only stored via findingSubmitter (not graphed).
	graphLoader *loader.GraphLoader
}

// NewComponentServiceServer constructs a ComponentServiceServer with the core
// lifecycle dependencies. Both registry and queue must be non-nil.
//
// Harness proxy dependencies (llmCompleter, memStore, findingSubmitter,
// pluginAccess) are optional at this stage: pass nil to leave the
// corresponding RPCs returning codes.Unimplemented until the subsystems are
// wired (tasks 5.3–5.5).
//
// auditLog may be nil; when nil, audit events are silently skipped.
func NewComponentServiceServer(
	registry ComponentRegistry,
	queue WorkQueue,
	logger *slog.Logger,
	llmCompleter LLMCompleter,
	memStore memory.MemoryStore,
	findingSubmitter FindingSubmitter,
	pluginAccess PluginAccessStore,
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
		memory:           memStore,
		findingSubmitter: findingSubmitter,
		pluginAccess:     pluginAccess,
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
//	svc.WithMemoryResolver(component.NewRedisMemoryResolver(stateClient))
func (s *ComponentServiceServer) WithMemoryResolver(r MemoryResolver) *ComponentServiceServer {
	s.memoryResolver = r
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

// WithAgentDelegator attaches an AgentDelegator for sub-agent dispatch.
// May be nil; delegation RPCs return codes.Unimplemented when nil.
func (s *ComponentServiceServer) WithAgentDelegator(ad AgentDelegator) *ComponentServiceServer {
	s.agentDelegator = ad
	return s
}

// WithComponentLister attaches a ComponentLister for tool/agent discovery.
// May be nil; list RPCs return codes.Unimplemented when nil.
func (s *ComponentServiceServer) WithComponentLister(cl ComponentLister) *ComponentServiceServer {
	s.componentLister = cl
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

// WithGraphLoader attaches a GraphLoader so that SubmitFinding stores the finding
// node in the Neo4j knowledge graph in addition to the finding store. This is
// best-effort: graph storage errors do not fail the RPC. When nil, graph storage
// is skipped and only the finding store path is used.
func (s *ComponentServiceServer) WithGraphLoader(gl *loader.GraphLoader) *ComponentServiceServer {
	s.graphLoader = gl
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
	tenant := auth.TenantFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "missing tenant in context")
	}

	// ---------------------------------------------------------------------------
	// Capability-based authorization
	//
	// When an authenticated identity is present in the context, validate that the
	// registering component's Kind and Name are permitted by the identity's
	// allowed_kinds / allowed_names claims, and that the identity holds the
	// "components:register" Casbin capability. Identities without these claims
	// (empty slice = unrestricted) pass through.
	//
	// When no identity is present we skip all checks to preserve backward
	// compatibility for dev mode and in-cluster service accounts that do not
	// carry a Gibson identity.
	// ---------------------------------------------------------------------------
	if identity, ok := auth.GibsonIdentityFromContext(ctx); ok {
		// Check allowed_kinds: if the claim is non-empty, the request Kind must
		// appear in it. An empty (or absent) slice means all kinds are permitted.
		if rawKinds, exists := identity.Claims["allowed_kinds"]; exists {
			var allowedKinds []string
			switch v := rawKinds.(type) {
			case []string:
				allowedKinds = v
			case []interface{}:
				for _, elem := range v {
					if s, ok := elem.(string); ok {
						allowedKinds = append(allowedKinds, s)
					}
				}
			}
			if len(allowedKinds) > 0 {
				permitted := false
				for _, k := range allowedKinds {
					if k == req.Kind {
						permitted = true
						break
					}
				}
				if !permitted {
					s.logger.WarnContext(ctx, "component registration rejected: kind not in allowed_kinds",
						slog.String("tenant", tenant),
						slog.String("kind", req.Kind),
						slog.String("subject", identity.Subject),
					)
					return nil, status.Errorf(codes.PermissionDenied, "component kind %q not permitted for this identity", req.Kind)
				}
			}
		}

		// Check allowed_names: if the claim is non-empty, the request Name must
		// appear in it. An empty (or absent) slice means all names are permitted.
		if rawNames, exists := identity.Claims["allowed_names"]; exists {
			var allowedNames []string
			switch v := rawNames.(type) {
			case []string:
				allowedNames = v
			case []interface{}:
				for _, elem := range v {
					if s, ok := elem.(string); ok {
						allowedNames = append(allowedNames, s)
					}
				}
			}
			if len(allowedNames) > 0 {
				permitted := false
				for _, n := range allowedNames {
					if n == req.Name {
						permitted = true
						break
					}
				}
				if !permitted {
					s.logger.WarnContext(ctx, "component registration rejected: name not in allowed_names",
						slog.String("tenant", tenant),
						slog.String("name", req.Name),
						slog.String("subject", identity.Subject),
					)
					return nil, status.Errorf(codes.PermissionDenied, "component name %q not permitted for this identity", req.Name)
				}
			}
		}

	}

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

	// Track registered agent count for quota enforcement.
	if req.Kind == "agent" && s.quotaManager != nil {
		if err := s.quotaManager.IncrementAgentCount(ctx); err != nil {
			s.logger.WarnContext(ctx, "failed to increment agent quota counter",
				slog.String("tenant", tenant),
				slog.String("name", req.Name),
				slog.String("error", err.Error()),
			)
			// Non-fatal: registration already succeeded; counter mismatch will
			// self-correct via decrementCounter's floor-at-zero logic.
		}
	}

	// Auto-create access record for self-hosted plugins so they appear in tenant's inventory.
	if req.Kind == "plugin" && tenant != "_system" && s.pluginAccess != nil {
		if err := s.pluginAccess.EnableSelfHosted(ctx, tenant, req.Name); err != nil {
			s.logger.WarnContext(ctx, "register component: failed to auto-create plugin access record",
				slog.String("tenant", tenant),
				slog.String("plugin", req.Name),
				slog.String("error", err.Error()),
			)
			// Non-fatal: registration succeeds even if access record creation fails.
		}
	}

	// Store plugin config schema if declared.
	if req.Kind == "plugin" && req.ConfigSchemaJson != "" && s.pluginAccess != nil {
		if err := s.pluginAccess.StoreConfigSchema(ctx, req.Name, req.ConfigSchemaJson); err != nil {
			s.logger.WarnContext(ctx, "register component: failed to store plugin config schema",
				slog.String("plugin", req.Name),
				slog.String("error", err.Error()),
			)
			// Non-fatal: registration succeeds even if schema storage fails.
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
	tenant := auth.TenantFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "missing tenant in context")
	}

	if req.InstanceId == "" {
		return nil, status.Error(codes.InvalidArgument, "instance_id is required")
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

	return &componentpb.HeartbeatResponse{
		Registered:    true,
		ConfigUpdates: map[string]string{},
	}, nil
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
	tenant := auth.TenantFromContext(ctx)
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
	if s.memoryResolver != nil && item.WorkID != "" {
		missionID := item.Context["mission_id"]
		if missionID != "" {
			if err := s.memoryResolver.RegisterWorkContext(ctx, item.WorkID, missionID, tenant); err != nil {
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
		missionID := item.Context["mission_id"]
		if missionID != "" {
			if execCtxJSON, err := s.missionMgr.GetMissionRunHistory(ctx, tenant, item.WorkID); err == nil && len(execCtxJSON) > 0 {
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

// SubmitResult accepts the outcome of a completed work item from a component.
//
// Flow:
//  1. Extract tenant from context (for audit logging; DeliverResult is keyed
//     by work_id which is globally unique, so no further tenant routing is
//     needed at the queue layer).
//  2. Convert the optional proto ComponentError to a WorkError.
//  3. Call queue.DeliverResult to persist the result and unblock any caller
//     waiting in WaitForResult.
//  4. Return an empty response.
func (s *ComponentServiceServer) SubmitResult(
	ctx context.Context,
	req *componentpb.SubmitResultRequest,
) (*componentpb.SubmitResultResponse, error) {
	tenant := auth.TenantFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "missing tenant in context")
	}

	if req.WorkId == "" {
		return nil, status.Error(codes.InvalidArgument, "work_id is required")
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

	if err := s.queue.DeliverResult(ctx, req.WorkId, result); err != nil {
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
	if s.discoveryProcessor != nil && len(req.Result) > 0 {
		if discovery := extractDiscoveryField100(req.Result); discovery != nil {
			go func() {
				processCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()

				execCtx := loader.ExecContext{
					MissionRunID: req.WorkId, // best-effort: work_id as mission_run scope
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

// storeSubmittedFindingToGraph is a best-effort helper that converts a finding JSON
// payload to a graphragpb.Finding proto and stores it via the GraphLoader. It runs
// in a goroutine and must never return an error to the caller.
func (s *ComponentServiceServer) storeSubmittedFindingToGraph(workID, findingID, findingJSON, tenant string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Decode the finding JSON to extract title and severity for proto population.
	// Use a simple map decode — full agent.Finding parsing is not needed here.
	var raw map[string]any
	if err := json.Unmarshal([]byte(findingJSON), &raw); err != nil {
		s.logger.WarnContext(ctx, "submit finding: failed to decode finding JSON for graph storage",
			slog.String("finding_id", findingID),
			slog.String("error", err.Error()),
		)
		return
	}

	title, _ := raw["title"].(string)
	severity, _ := raw["severity"].(string)
	description, _ := raw["description"].(string)
	category, _ := raw["category"].(string)

	pbFinding := &graphragpb.Finding{
		Id:          &findingID,
		Title:       title,
		Severity:    severity,
		Description: &description,
		Category:    &category,
	}

	execCtx := loader.ExecContext{
		MissionRunID: workID,
	}

	result, err := s.graphLoader.LoadFindings(ctx, execCtx, []*graphragpb.Finding{pbFinding})
	if err != nil {
		s.logger.WarnContext(ctx, "submit finding: graph storage failed (best-effort)",
			slog.String("finding_id", findingID),
			slog.String("tenant", tenant),
			slog.String("error", err.Error()),
		)
		return
	}
	if result != nil && result.HasErrors() {
		for _, e := range result.Errors {
			s.logger.WarnContext(ctx, "submit finding: partial graph storage error",
				slog.String("finding_id", findingID),
				slog.String("error", e.Error()),
			)
		}
	}

	s.logger.DebugContext(ctx, "submit finding: finding stored to graph",
		slog.String("finding_id", findingID),
		slog.String("tenant", tenant),
	)
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
	tenant := auth.TenantFromContext(ctx)
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

	tenant := auth.TenantFromContext(ctx)
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
	tenant := auth.TenantFromContext(ctx)
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

	// Build the work item targeting the tool component.
	workItem := WorkItem{
		WorkType:  "execute_proto",
		Payload:   []byte(req.InputJson),
		TimeoutMs: req.TimeoutMs,
		Context: map[string]string{
			"source_work_id": req.WorkId,
			"caller_tenant":  tenant,
		},
	}

	workID, err := s.queue.Enqueue(ctx, tenant, "tool", req.ToolName, workItem)
	if err != nil {
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
	tenant := auth.TenantFromContext(ctx)
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
	if instances[0].TenantID == "_system" && s.pluginAccess != nil {
		pluginCfg, cfgErr := s.pluginAccess.GetDecryptedConfig(ctx, tenant, req.PluginName)
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

	workItem := WorkItem{
		WorkType:  "execute_proto",
		Payload:   []byte(req.ParamsJson),
		TimeoutMs: req.TimeoutMs,
		Context:   workCtx,
	}

	workID, err := s.queue.Enqueue(ctx, tenant, "plugin", req.PluginName, workItem)
	if err != nil {
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
//  4. Best-effort: if graphLoader is wired, persist the finding node to Neo4j.
func (s *ComponentServiceServer) SubmitFinding(
	ctx context.Context,
	req *componentpb.SubmitFindingRequest,
) (*componentpb.SubmitFindingResponse, error) {
	tenant := auth.TenantFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "missing tenant in context")
	}

	if len(req.Finding) == 0 {
		return nil, status.Error(codes.InvalidArgument, "finding is required")
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

		// Best-effort: persist finding node to Neo4j via graphLoader (errors must not fail RPC).
		if s.graphLoader != nil {
			go s.storeSubmittedFindingToGraph(req.WorkId, findingID, findingJSON, tenant)
		}

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

// ---------------------------------------------------------------------------
// Memory helpers
// ---------------------------------------------------------------------------

// resolveMissionMemory resolves the MissionMemory for a work item using the
// MemoryResolver. It falls back to s.memory.Mission() when no MemoryResolver is
// configured, so that the server works with a shared store during development.
//
// Returns a gRPC status error on failure:
//   - codes.Unimplemented — neither resolver nor shared store is wired
//   - codes.NotFound      — resolver found no mapping for workID
//   - codes.Internal      — unexpected resolver or store error
func (s *ComponentServiceServer) resolveMissionMemory(
	ctx context.Context,
	workID, tenant string,
) (memory.MissionMemory, error) {
	if s.memoryResolver != nil {
		mm, err := s.memoryResolver.ResolveForWork(ctx, workID, tenant)
		if err != nil {
			var gibsonErr *types.GibsonError
			if errors.As(err, &gibsonErr) && gibsonErr.Code == ErrCodeWorkContextNotFound {
				return nil, status.Errorf(codes.NotFound,
					"no mission context found for work item %q; ensure the agent was dispatched via PollWork", workID)
			}
			return nil, status.Errorf(codes.Internal, "failed to resolve mission memory for work %q: %v", workID, err)
		}
		return mm, nil
	}

	// Fall back to the shared mission memory store (useful when running without
	// the full resolver stack, e.g., in integration tests).
	if s.memory != nil {
		return s.memory.Mission(), nil
	}

	return nil, status.Error(codes.Unimplemented, "mission memory not available: neither resolver nor shared store is wired")
}

// MemoryGet retrieves a value from the requested memory tier by key.
//
// Tier routing:
//   - working   — in-process ephemeral map; returns not-found when key absent.
//   - mission   — Redis-backed persistent store scoped to the work item's mission;
//     requires memoryResolver to be wired (falls back to s.memory.Mission() when not).
//   - long_term — not suitable for point lookups; returns codes.InvalidArgument.
func (s *ComponentServiceServer) MemoryGet(
	ctx context.Context,
	req *componentpb.MemoryGetRequest,
) (*componentpb.MemoryGetResponse, error) {
	tenant := auth.TenantFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "missing tenant in context")
	}

	if s.memory == nil && s.memoryResolver == nil {
		return nil, status.Error(codes.Unimplemented, "memory store not yet wired on this server")
	}

	if req.Key == "" {
		return nil, status.Error(codes.InvalidArgument, "key is required")
	}

	switch req.Tier {
	case memTierWorking:
		if s.memory == nil {
			return nil, status.Error(codes.Unimplemented, "working memory not available (shared memory store not wired)")
		}
		val, ok := s.memory.Working().Get(req.Key)
		if !ok {
			return &componentpb.MemoryGetResponse{Found: false}, nil
		}
		// Serialize the retrieved value to JSON for the wire format.
		// Working memory stores arbitrary any values; JSON is the lowest common
		// denominator for cross-language clients.
		item := memory.NewMemoryItem(req.Key, val, nil)
		data, err := item.MarshalValue()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to serialize working memory value: %v", err)
		}
		return &componentpb.MemoryGetResponse{Found: true, Value: data}, nil

	case memTierMission:
		missionMem, err := s.resolveMissionMemory(ctx, req.WorkId, tenant)
		if err != nil {
			return nil, err
		}
		item, err := missionMem.Retrieve(ctx, req.Key)
		if err != nil {
			// Translate not-found into a Found=false response instead of an error
			// to keep the client contract simple. Mission memory signals not-found
			// via *types.GibsonError with code ErrCodeMissionMemoryNotFound.
			var gibsonErr *types.GibsonError
			if errors.As(err, &gibsonErr) && gibsonErr.Code == memory.ErrCodeMissionMemoryNotFound {
				return &componentpb.MemoryGetResponse{Found: false}, nil
			}
			s.logger.ErrorContext(ctx, "memory get: mission retrieve failed",
				slog.String("tenant", tenant),
				slog.String("work_id", req.WorkId),
				slog.String("key", req.Key),
				slog.String("error", err.Error()),
			)
			return nil, status.Errorf(codes.Internal, "failed to retrieve mission memory key %q: %v", req.Key, err)
		}
		data, err := item.MarshalValue()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to serialize mission memory value: %v", err)
		}
		return &componentpb.MemoryGetResponse{Found: true, Value: data}, nil

	case memTierLongTerm:
		// Long-term memory is a semantic vector store; it does not support
		// direct key lookups. Use MemorySearch with a precise query instead.
		return nil, status.Error(codes.InvalidArgument,
			"long-term memory does not support key-based Get; use MemorySearch instead")

	default:
		return nil, status.Errorf(codes.InvalidArgument, "unknown memory tier %q", req.Tier)
	}
}

// MemorySet writes a value to the requested memory tier.
//
// Tier routing:
//   - working   — in-process ephemeral map; value is deserialized into any.
//   - mission   — Redis-backed persistent store scoped to the work item's mission;
//     requires memoryResolver to be wired (falls back to s.memory.Mission() when not).
//   - long_term — use the Store call (ID + content); key becomes the ID and
//     value becomes the content.
func (s *ComponentServiceServer) MemorySet(
	ctx context.Context,
	req *componentpb.MemorySetRequest,
) (*componentpb.MemorySetResponse, error) {
	tenant := auth.TenantFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "missing tenant in context")
	}

	if s.memory == nil && s.memoryResolver == nil {
		return nil, status.Error(codes.Unimplemented, "memory store not yet wired on this server")
	}

	if req.Key == "" {
		return nil, status.Error(codes.InvalidArgument, "key is required")
	}
	if len(req.Value) == 0 {
		return nil, status.Error(codes.InvalidArgument, "value is required")
	}

	valueStr := string(req.Value)

	switch req.Tier {
	case memTierWorking:
		// Store the raw value string in working memory. The agent is responsible
		// for deserializing on retrieval; this keeps working memory agnostic to
		// schema.
		if s.memory == nil {
			return nil, status.Error(codes.Unimplemented, "working memory not available (shared memory store not wired)")
		}
		if err := s.memory.Working().Set(req.Key, valueStr); err != nil {
			s.logger.ErrorContext(ctx, "memory set: working memory set failed",
				slog.String("tenant", tenant),
				slog.String("key", req.Key),
				slog.String("error", err.Error()),
			)
			return nil, status.Errorf(codes.Internal, "failed to set working memory key %q: %v", req.Key, err)
		}

	case memTierMission:
		missionMem, err := s.resolveMissionMemory(ctx, req.WorkId, tenant)
		if err != nil {
			return nil, err
		}
		// Mission memory accepts any value; store the string directly.
		if err := missionMem.Store(ctx, req.Key, valueStr, nil); err != nil {
			s.logger.ErrorContext(ctx, "memory set: mission memory store failed",
				slog.String("tenant", tenant),
				slog.String("work_id", req.WorkId),
				slog.String("key", req.Key),
				slog.String("error", err.Error()),
			)
			return nil, status.Errorf(codes.Internal, "failed to store mission memory key %q: %v", req.Key, err)
		}

	case memTierLongTerm:
		// Long-term memory requires content as a plain string for embedding.
		// value is treated as that content; key becomes the vector entry ID.
		if s.memory == nil {
			return nil, status.Error(codes.Unimplemented, "long-term memory not available (shared memory store not wired)")
		}
		if err := s.memory.LongTerm().Store(ctx, req.Key, valueStr, nil); err != nil {
			s.logger.ErrorContext(ctx, "memory set: long-term memory store failed",
				slog.String("tenant", tenant),
				slog.String("key", req.Key),
				slog.String("error", err.Error()),
			)
			return nil, status.Errorf(codes.Internal, "failed to store long-term memory entry %q: %v", req.Key, err)
		}

	default:
		return nil, status.Errorf(codes.InvalidArgument, "unknown memory tier %q", req.Tier)
	}

	s.logger.DebugContext(ctx, "memory set: value stored",
		slog.String("tenant", tenant),
		slog.String("tier", req.Tier),
		slog.String("key", req.Key),
	)

	return &componentpb.MemorySetResponse{}, nil
}

// MemorySearch performs a semantic or full-text search over a memory tier.
//
// Tier routing:
//   - working   — not suitable for search; returns codes.InvalidArgument.
//   - mission   — full-text search (RediSearch FTS) over the agent's mission-scoped
//     namespace, resolved from the work_id via MemoryResolver.
//   - long_term — vector-similarity search using the configured embedder.
func (s *ComponentServiceServer) MemorySearch(
	ctx context.Context,
	req *componentpb.MemorySearchRequest,
) (*componentpb.MemorySearchResponse, error) {
	tenant := auth.TenantFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "missing tenant in context")
	}

	if s.memory == nil && s.memoryResolver == nil {
		return nil, status.Error(codes.Unimplemented, "memory store not yet wired on this server")
	}

	if req.Query == "" {
		return nil, status.Error(codes.InvalidArgument, "query is required")
	}

	topK := int(req.Limit)
	if topK <= 0 {
		topK = 10
	}

	switch req.Tier {
	case memTierWorking:
		// Working memory is an in-process key-value map with no search index.
		// Callers should iterate keys via MemoryGet or restructure data for
		// mission/longterm tiers.
		return nil, status.Error(codes.InvalidArgument,
			"working memory does not support search; use mission or longterm tier")

	case memTierMission:
		missionMem, err := s.resolveMissionMemory(ctx, req.WorkId, tenant)
		if err != nil {
			return nil, err
		}
		rawResults, err := missionMem.Search(ctx, req.Query, topK)
		if err != nil {
			s.logger.ErrorContext(ctx, "memory search: mission FTS failed",
				slog.String("tenant", tenant),
				slog.String("work_id", req.WorkId),
				slog.String("query", req.Query),
				slog.String("error", err.Error()),
			)
			return nil, status.Errorf(codes.Internal, "mission memory search failed: %v", err)
		}
		results := make([]*componentpb.MemoryEntry, 0, len(rawResults))
		for _, r := range rawResults {
			data, err := r.Item.MarshalValue()
			if err != nil {
				s.logger.WarnContext(ctx, "memory search: failed to serialize mission result; skipping",
					slog.String("tenant", tenant),
					slog.String("key", r.Item.Key),
					slog.String("error", err.Error()),
				)
				continue
			}
			results = append(results, &componentpb.MemoryEntry{
				Key:   r.Item.Key,
				Value: data,
				Score: float32(r.Score),
			})
		}
		s.logger.DebugContext(ctx, "memory search: mission FTS completed",
			slog.String("tenant", tenant),
			slog.String("work_id", req.WorkId),
			slog.String("query", req.Query),
			slog.Int("result_count", len(results)),
		)
		return &componentpb.MemorySearchResponse{Results: results}, nil

	case memTierLongTerm:
		rawResults, err := s.memory.LongTerm().Search(ctx, req.Query, topK, nil)
		if err != nil {
			s.logger.ErrorContext(ctx, "memory search: long-term search failed",
				slog.String("tenant", tenant),
				slog.String("query", req.Query),
				slog.String("error", err.Error()),
			)
			return nil, status.Errorf(codes.Internal, "long-term memory search failed: %v", err)
		}

		results := make([]*componentpb.MemoryEntry, 0, len(rawResults))
		for _, r := range rawResults {
			data, err := r.Item.MarshalValue()
			if err != nil {
				// Skip results that cannot be serialized rather than failing the
				// entire response — partial results are more useful than none.
				s.logger.WarnContext(ctx, "memory search: failed to serialize result; skipping",
					slog.String("tenant", tenant),
					slog.String("key", r.Item.Key),
					slog.String("error", err.Error()),
				)
				continue
			}
			results = append(results, &componentpb.MemoryEntry{
				Key:   r.Item.Key,
				Value: data,
				Score: float32(r.Score),
			})
		}

		s.logger.DebugContext(ctx, "memory search: long-term search completed",
			slog.String("tenant", tenant),
			slog.String("query", req.Query),
			slog.Int("result_count", len(results)),
		)

		return &componentpb.MemorySearchResponse{Results: results}, nil

	default:
		return nil, status.Errorf(codes.InvalidArgument, "unknown memory tier %q", req.Tier)
	}
}

// ---------------------------------------------------------------------------
// Plugin access RPCs
//
// These seven RPCs expose tenant-scoped plugin management: browsing the
// catalog, enabling/disabling plugins, updating configuration, retrieving
// masked config, testing connectivity, and listing tenant-owned records.
//
// All handlers follow the same guard pattern:
//  1. Extract tenant from context; return Unauthenticated if absent.
//  2. Return Unimplemented when pluginAccess is not wired.
//  3. Delegate to the PluginAccessStore and map sentinel errors to the
//     appropriate gRPC status codes.
// ---------------------------------------------------------------------------

// pluginAccessErrToStatus converts sentinel errors from PluginAccessStore to
// the appropriate gRPC status codes.
func pluginAccessErrToStatus(err error, pluginName string) error {
	switch {
	case errors.Is(err, ErrPluginNotEnabled):
		return status.Errorf(codes.NotFound, "plugin %q is not enabled for this tenant; enable it first", pluginName)
	case errors.Is(err, ErrPluginNotConfigured):
		return status.Errorf(codes.FailedPrecondition, "plugin %q is enabled but has no configuration stored", pluginName)
	default:
		return status.Errorf(codes.Internal, "plugin access operation failed: %v", err)
	}
}

// ListAvailablePlugins returns the full plugin catalog visible to the calling
// tenant, with each entry annotated with the tenant's enablement status.
func (s *ComponentServiceServer) ListAvailablePlugins(
	ctx context.Context,
	_ *componentpb.ListAvailablePluginsRequest,
) (*componentpb.ListAvailablePluginsResponse, error) {
	tenant := auth.TenantFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "missing tenant in context")
	}

	if s.pluginAccess == nil {
		return nil, status.Error(codes.Unimplemented, "plugin access store not yet wired on this server")
	}

	entries, err := s.pluginAccess.ListAvailablePlugins(ctx, tenant)
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
	tenant := auth.TenantFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "missing tenant in context")
	}

	if s.pluginAccess == nil {
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

	if err := s.pluginAccess.Enable(ctx, tenant, req.PluginName, cfg, tenant); err != nil {
		s.logger.ErrorContext(ctx, "enable plugin: failed",
			slog.String("tenant", tenant),
			slog.String("plugin_name", req.PluginName),
			slog.String("error", err.Error()),
		)
		return nil, pluginAccessErrToStatus(err, req.PluginName)
	}

	s.logger.InfoContext(ctx, "enable plugin: plugin enabled",
		slog.String("tenant", tenant),
		slog.String("plugin_name", req.PluginName),
	)

	if s.auditLog != nil {
		if err := s.auditLog.Log(ctx, "plugin.enable", "plugin", req.PluginName, nil); err != nil {
			s.logger.WarnContext(ctx, "audit log failed", "error", err)
		}
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
	tenant := auth.TenantFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "missing tenant in context")
	}

	if s.pluginAccess == nil {
		return nil, status.Error(codes.Unimplemented, "plugin access store not yet wired on this server")
	}

	if req.PluginName == "" {
		return nil, status.Error(codes.InvalidArgument, "plugin_name is required")
	}

	if err := s.pluginAccess.Disable(ctx, tenant, req.PluginName); err != nil {
		s.logger.ErrorContext(ctx, "disable plugin: failed",
			slog.String("tenant", tenant),
			slog.String("plugin_name", req.PluginName),
			slog.String("error", err.Error()),
		)
		return nil, pluginAccessErrToStatus(err, req.PluginName)
	}

	s.logger.InfoContext(ctx, "disable plugin: plugin disabled",
		slog.String("tenant", tenant),
		slog.String("plugin_name", req.PluginName),
	)

	if s.auditLog != nil {
		if err := s.auditLog.Log(ctx, "plugin.disable", "plugin", req.PluginName, nil); err != nil {
			s.logger.WarnContext(ctx, "audit log failed", "error", err)
		}
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
	tenant := auth.TenantFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "missing tenant in context")
	}

	if s.pluginAccess == nil {
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

	if err := s.pluginAccess.UpdateConfig(ctx, tenant, req.PluginName, cfg, tenant); err != nil {
		s.logger.ErrorContext(ctx, "update plugin config: failed",
			slog.String("tenant", tenant),
			slog.String("plugin_name", req.PluginName),
			slog.String("error", err.Error()),
		)
		return nil, pluginAccessErrToStatus(err, req.PluginName)
	}

	s.logger.InfoContext(ctx, "update plugin config: config updated",
		slog.String("tenant", tenant),
		slog.String("plugin_name", req.PluginName),
	)

	if s.auditLog != nil {
		if err := s.auditLog.Log(ctx, "plugin.config.update", "plugin", req.PluginName, nil); err != nil {
			s.logger.WarnContext(ctx, "audit log failed", "error", err)
		}
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
	tenant := auth.TenantFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "missing tenant in context")
	}

	if s.pluginAccess == nil {
		return nil, status.Error(codes.Unimplemented, "plugin access store not yet wired on this server")
	}

	if req.PluginName == "" {
		return nil, status.Error(codes.InvalidArgument, "plugin_name is required")
	}

	maskedCfg, err := s.pluginAccess.GetMaskedConfig(ctx, tenant, req.PluginName)
	if err != nil {
		s.logger.ErrorContext(ctx, "get plugin config: failed",
			slog.String("tenant", tenant),
			slog.String("plugin_name", req.PluginName),
			slog.String("error", err.Error()),
		)
		return nil, pluginAccessErrToStatus(err, req.PluginName)
	}

	cfgBytes, err := json.Marshal(maskedCfg)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to serialize masked config: %v", err)
	}

	// Include the schema so clients can render a config form without a second
	// round-trip. Missing schema is not an error — it is returned as an empty
	// string and the caller renders a generic key-value editor.
	schema, err := s.pluginAccess.GetConfigSchema(ctx, req.PluginName)
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
	tenant := auth.TenantFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "missing tenant in context")
	}

	if s.pluginAccess == nil {
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

	workItem := WorkItem{
		WorkType: "health_check",
		Payload:  []byte(req.ConfigJson),
		Context: map[string]string{
			"caller_tenant": tenant,
		},
	}

	workID, err := s.queue.Enqueue(ctx, "_system", "plugin", req.PluginName, workItem)
	if err != nil {
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
	tenant := auth.TenantFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "missing tenant in context")
	}

	if s.pluginAccess == nil {
		return nil, status.Error(codes.Unimplemented, "plugin access store not yet wired on this server")
	}

	records, err := s.pluginAccess.ListTenantPlugins(ctx, tenant)
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
