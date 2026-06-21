package harness

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/graphrag"
	"github.com/zeroroot-ai/sdk/auth"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// GraphReader is the narrow read-only projection of the GraphRAGProvider used
// by the compliance resource resolver. We accept this minimal interface so
// tests can supply a fake without pulling in the full provider surface and
// so future provider refactors do not cascade into this package.
type GraphReader interface {
	// QueryNodes performs an exact property-based node lookup within the
	// tenant's subgraph. Implementations must tenant-scope the query.
	QueryNodes(ctx context.Context, query graphrag.NodeQuery) ([]graphrag.GraphNode, error)
}

// ResourceResolution is the output of resolving a harness call into a
// compliance-signal resource triple. All fields are optional — the middleware
// stamps whatever is available.
type ResourceResolution struct {
	// ResourceType classifies the target (e.g., "tool:nmap", "llm:anthropic",
	// "memory:working", "host", "endpoint").
	ResourceType string

	// ResourceNodeID is the canonical graph node id for the target, if the
	// resolver was able to find it. Empty when lookup fails or is skipped.
	ResourceNodeID string

	// ResourceURI is the human-readable identifier (URL, host, model id,
	// memory key, etc.). Always populated when any identifying value is
	// available on the request.
	ResourceURI string
}

// ResourceResolver stamps (resource_type, resource_node_id, resource_uri)
// onto compliance signals via the dual-reference logic from
// docs/AUDIT-FEATURE.md Q7.
//
// Graph lookup failures are non-fatal by design — the resolver logs a warning
// and returns a partial ResourceResolution. Never block signal emission on
// graph availability.
type ResourceResolver struct {
	reader GraphReader
	logger *slog.Logger
}

// NewResourceResolver constructs a ResourceResolver with the given graph
// reader and logger. A nil reader is allowed (resolver will skip graph
// lookups and only stamp the URI) — useful for local/dev daemons that run
// without graphrag.
func NewResourceResolver(reader GraphReader, logger *slog.Logger) *ResourceResolver {
	if logger == nil {
		logger = slog.Default()
	}
	return &ResourceResolver{
		reader: reader,
		logger: logger.With("component", "compliance_resource_resolver"),
	}
}

// Resolve inspects a harness method call and returns the resource triple.
// The request argument is method-specific:
//
//   - CallToolProto: ToolCallTarget (name + category + proto request)
//   - Complete / CompleteWithTools / Stream / CompleteStructuredAny: LLMTarget
//     (slot; provider + model filled in by ResolveLLMResponse after the call)
//   - StoreNode: use ResolveGraphWrite(node) post-store
//   - QueryNodes: GraphReadTarget (node_type + node_id or property filter)
//   - Memory.Get/Set/Delete: MemoryTarget (tier + key)
//   - QueryPlugin: PluginTarget (name + method)
//   - DelegateToAgent: the sub-agent name (string)
//
// For anything the resolver cannot classify, ResourceType is set to the
// method name and ResourceURI is left empty.
func (r *ResourceResolver) Resolve(ctx context.Context, method HarnessMethod, request any) ResourceResolution {
	switch method {
	case MethodCallToolProto:
		return r.resolveToolCall(ctx, request)

	case MethodComplete, MethodCompleteWithTools, MethodStream,
		MethodCompleteStructuredAny, MethodCompleteStructuredAnyWithUsage:
		return r.resolveLLMCall(request)

	case MethodQueryPlugin:
		return r.resolvePluginQuery(request)

	case MethodDelegateToAgent:
		if name, ok := request.(string); ok {
			return ResourceResolution{
				ResourceType: "agent:" + name,
				ResourceURI:  name,
			}
		}
		return ResourceResolution{ResourceType: "agent"}

	case MethodSubmitFinding:
		return ResourceResolution{ResourceType: "finding"}

	case MethodGetFindings, MethodGetPreviousRunFindings, MethodGetAllRunFindings:
		if t, ok := request.(GraphReadTarget); ok {
			return r.resolveGraphRead(t)
		}
		return ResourceResolution{ResourceType: "finding"}

	default:
		return ResourceResolution{ResourceType: string(method)}
	}
}

// ToolCallTarget is the request shape for resolving a CallToolProto
// invocation. Middleware populates Name (always available from the call)
// and Category (optional — sourced from the tool descriptor); Request is
// the proto.Message being sent to the tool.
//
// Per Requirement 4.1, resource_type is stamped as "discovery:{category}"
// when Category is non-empty (e.g., "discovery:host", "discovery:endpoint"),
// falling back to "tool:{name}" when the category is not declared.
type ToolCallTarget struct {
	Name     string        // canonical tool name (e.g., "nmap")
	Category string        // optional taxonomy category (e.g., "host", "endpoint")
	Request  proto.Message // the tool's input proto
}

// toolCallRequest is kept as an alias for the tests and legacy callers that
// build the simpler (name, request) tuple. Prefer ToolCallTarget for new
// call sites.
type toolCallRequest = ToolCallTarget

// resolveToolCall extracts the target URL/host/identifier from the tool
// request proto by scanning well-known proto field names (target, url, host,
// identifier), then attempts a graph lookup to attach the node id.
//
// Lookup failures are non-fatal — we log a warning and return with only the
// URI stamped.
func (r *ResourceResolver) resolveToolCall(ctx context.Context, request any) ResourceResolution {
	tc, ok := request.(ToolCallTarget)
	if !ok {
		return ResourceResolution{ResourceType: "tool"}
	}

	var resourceType string
	if tc.Category != "" {
		// Per Requirement 4.1, use the tool's category for resource_type.
		resourceType = "discovery:" + tc.Category
	} else {
		resourceType = "tool:" + tc.Name
	}
	uri := extractTargetFromRequest(tc.Request)

	res := ResourceResolution{
		ResourceType: resourceType,
		ResourceURI:  uri,
	}
	if uri == "" || r.reader == nil {
		return res
	}

	// Attempt a tenant-scoped graph lookup for a node matching the URI.
	// The lookup is advisory — if it fails or returns nothing, we still
	// stamp the URI and proceed. auth.TenantStringFromContext falls back to the
	// system tenant when no tenant is set, so the scope is always non-empty.
	tenant := auth.TenantStringFromContext(ctx)
	res.ResourceNodeID = r.lookupNodeByURI(ctx, uri, tenant)
	return res
}

// lookupNodeByURI runs a best-effort graph query for a node whose url, host,
// or identifier matches the given URI within the tenant's subgraph. Returns
// the canonical node id of the first match, or "" if nothing is found or the
// query fails.
//
// Failures are logged at WARN but do not propagate — the resolver guarantees
// that a graph outage cannot block signal emission.
func (r *ResourceResolver) lookupNodeByURI(ctx context.Context, uri, tenant string) string {
	query := graphrag.NewNodeQuery().
		WithLimit(1).
		WithProperty("tenant_id", tenant)

	// Try URL first (endpoints), fall back to host, fall back to identifier.
	// Three cheap round-trips is still cheap compared to the harness call
	// latency being measured.
	for _, key := range []string{"url", "host", "identifier"} {
		q := *query
		q.Properties = map[string]any{
			"tenant_id": tenant,
			key:         uri,
		}
		nodes, err := r.reader.QueryNodes(ctx, q)
		if err != nil {
			r.logger.WarnContext(ctx, "graph lookup failed during resource resolution",
				slog.String("uri", uri),
				slog.String("property", key),
				slog.String("error", err.Error()),
			)
			return ""
		}
		if len(nodes) > 0 {
			return string(nodes[0].ID)
		}
	}
	return ""
}

// SlotBinding holds the resolved provider and model ID for a named LLM slot.
// It is stored in context under ctxKeySlotBindings so that the compliance
// resource resolver can produce a concrete "llm:{provider}" resource type
// for pre-call stamps, satisfying Requirement 8.1.
type SlotBinding struct {
	Provider string // e.g., "anthropic", "openai"
	ModelID  string // e.g., "claude-3-5-sonnet-20241022"
}

// ctxKeySlotBindingsType is the unexported type for the slot bindings context key.
type ctxKeySlotBindingsType struct{}

// ctxKeySlotBindings is the context key for map[string]SlotBinding.
// The harness factory stores slot bindings here at mission start.
var ctxKeySlotBindings = ctxKeySlotBindingsType{}

// ContextWithSlotBindings returns a new context carrying the supplied slot
// bindings. Call this from the harness factory after slot resolution.
func ContextWithSlotBindings(ctx context.Context, bindings map[string]SlotBinding) context.Context {
	return context.WithValue(ctx, ctxKeySlotBindings, bindings)
}

// SlotBindingsFromContext retrieves the slot bindings map from context.
// Returns nil if no bindings were stored.
func SlotBindingsFromContext(ctx context.Context) map[string]SlotBinding {
	v, _ := ctx.Value(ctxKeySlotBindings).(map[string]SlotBinding)
	return v
}

// LLMTarget is the request shape for resolving an LLM completion call.
// At pre-call time only Slot is known; the middleware calls ResolveLLMResponse
// after the completion returns to refine resource_type to "llm:{provider}"
// and resource_uri to the model id, per Requirement 4.7.
type LLMTarget struct {
	Slot     string // slot name declared by the agent (e.g., "primary")
	Provider string // optional — filled post-call by the middleware
	ModelID  string // optional — filled post-call by the middleware

	// Ctx carries the calling context so resolveLLMCall can look up
	// slot bindings for pre-call resolution.
	Ctx context.Context
}

// resolveLLMCall stamps resource_type and resource_uri for an LLM call.
//
// Resolution order for LLMTarget:
//  1. Provider and ModelID already set (post-call) → canonical llm:{provider} + modelID.
//  2. Slot bindings present in context for this slot → use binding (Requirement 8.1).
//  3. Fallback: "llm:slot:{name}" placeholder to be refined by ResolveLLMResponse.
func (r *ResourceResolver) resolveLLMCall(request any) ResourceResolution {
	switch v := request.(type) {
	case LLMTarget:
		if v.Provider != "" && v.ModelID != "" {
			return ResourceResolution{
				ResourceType: "llm:" + v.Provider,
				ResourceURI:  v.ModelID,
			}
		}
		// Look up slot binding in context.
		if v.Ctx != nil {
			if bindings := SlotBindingsFromContext(v.Ctx); bindings != nil {
				if b, ok := bindings[v.Slot]; ok {
					return ResourceResolution{
						ResourceType: "llm:" + b.Provider,
						ResourceURI:  b.ModelID,
					}
				}
			}
		}
		return ResourceResolution{
			ResourceType: "llm:slot:" + v.Slot,
			ResourceURI:  v.Slot,
		}
	case string:
		// Legacy path: raw slot name.
		return ResourceResolution{
			ResourceType: "llm:slot:" + v,
			ResourceURI:  v,
		}
	}
	return ResourceResolution{ResourceType: "llm"}
}

// ResolveLLMResponse refines a pre-call ResourceResolution for an LLM
// completion once the provider/model the slot resolved to are known.
// Called by the middleware from its completeSignal path after the inner
// Complete call returns. This is the mechanism that satisfies Requirement
// 4.7 — the resolver cannot produce llm:{provider} + model_id up front
// because slot → provider resolution is a runtime decision.
func (r *ResourceResolver) ResolveLLMResponse(provider, modelID string) ResourceResolution {
	return ResourceResolution{
		ResourceType: "llm:" + provider,
		ResourceURI:  modelID,
	}
}

// extractTargetFromRequest scans the proto message for a well-known target
// identifier field. It tries "target", "url", "host", "identifier" in that
// order and returns the first non-empty string it finds.
//
// Tool authors that use non-standard field names get no automatic lookup —
// that's intentional. The fallback is URI-only stamping, which still makes
// the signal queryable via resource_uri.
func extractTargetFromRequest(msg proto.Message) string {
	if msg == nil {
		return ""
	}
	r := msg.ProtoReflect()
	if r == nil || !r.IsValid() {
		return ""
	}

	// Precedence: target > url > host > identifier.
	for _, fieldName := range []string{"target", "url", "host", "identifier"} {
		fd := r.Descriptor().Fields().ByName(protoreflect.Name(fieldName))
		if fd == nil {
			continue
		}
		if fd.Kind() != protoreflect.StringKind {
			continue
		}
		v := r.Get(fd).String()
		if v != "" {
			return v
		}
	}

	// Secondary fallback: scan all string fields for something URL-shaped.
	// This catches tools whose schemas use "scan_target" or "host_url".
	var fallback string
	r.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if fd.Kind() != protoreflect.StringKind {
			return true
		}
		s := v.String()
		if s == "" {
			return true
		}
		name := string(fd.Name())
		if strings.Contains(name, "target") || strings.Contains(name, "url") || strings.Contains(name, "host") {
			fallback = s
			return false
		}
		return true
	})
	return fallback
}

// GraphReadTarget is the request shape for resolving a QueryNodes call.
// When NodeID is set, the resolver stamps both resource_node_id and
// resource_uri from it (Requirement 4.6). When only NodeType is known, the
// resolver stamps resource_type only.
type GraphReadTarget struct {
	NodeType string // e.g., "host", "endpoint", "finding"
	NodeID   string // optional — when the query is by specific id
}

// resolveGraphRead stamps the resource for a graph read (QueryNodes) per
// Requirement 4.6.
func (r *ResourceResolver) resolveGraphRead(t GraphReadTarget) ResourceResolution {
	res := ResourceResolution{ResourceType: t.NodeType}
	if t.NodeID != "" {
		res.ResourceNodeID = t.NodeID
		res.ResourceURI = t.NodeID
	}
	return res
}

// PluginTarget is the request shape for resolving a QueryPlugin call.
// The method field lets queries distinguish between "gitlab.list_projects"
// and "gitlab.create_issue" on a plugin.
type PluginTarget struct {
	Name   string
	Method string
}

// resolvePluginQuery stamps the resource for a plugin query.
func (r *ResourceResolver) resolvePluginQuery(request any) ResourceResolution {
	switch v := request.(type) {
	case PluginTarget:
		uri := v.Name
		if v.Method != "" {
			uri = v.Name + "." + v.Method
		}
		return ResourceResolution{
			ResourceType: "plugin:" + v.Name,
			ResourceURI:  uri,
		}
	case string:
		return ResourceResolution{
			ResourceType: "plugin:" + v,
			ResourceURI:  v,
		}
	}
	return ResourceResolution{ResourceType: "plugin"}
}

// ResolveGraphWrite stamps the resource for a graph write operation
// (StoreNode). Per Requirement 4.5, this is called POST-store by the
// middleware so that the node id returned by the loader is stamped onto
// resource_node_id. The middleware must pass the node after the store,
// not before.
func (r *ResourceResolver) ResolveGraphWrite(node graphrag.GraphNode) ResourceResolution {
	res := ResourceResolution{
		ResourceType: graphNodeTypeString(node),
	}
	if !node.ID.IsZero() {
		res.ResourceNodeID = string(node.ID)
		res.ResourceURI = string(node.ID)
	}
	return res
}

// graphNodeTypeString returns the first label of a graph node as a string,
// or a placeholder if no labels are set.
func graphNodeTypeString(node graphrag.GraphNode) string {
	if len(node.Labels) == 0 {
		return "node"
	}
	return fmt.Sprintf("%v", node.Labels[0])
}
