// Package metatool implements the two agent-facing meta-tools from ADR-0047
// facet 5: search_tools (discovery over the FGA-scoped connector catalog) and
// invoke_tool (deterministic id → PluginInvoke{plugin_name, method} dispatch).
//
// Binding thousands of MCP tools to the LLM as native function names does not
// scale and forbids structured ids, so at MCP scale the agent loop presents
// exactly two tools — search_tools and invoke_tool — and the daemon resolves the
// canonical id behind them. The id↔(plugin, method) mapping is owned solely by
// package toolid; this package invents no authz path of its own. invoke_tool
// dispatches through the existing QueryPlugin path, which enforces the
// can_invoke gate downstream exactly as a directly-bound call would; the
// determinism boundary (id → install → pinned schema → arg validation → FGA →
// call) is therefore preserved — only selection and argument fill are
// probabilistic, over a narrowed surface.
package metatool

import (
	"context"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/catalog"
	"github.com/zeroroot-ai/gibson/internal/toolid"
)

// PluginQuerier invokes a plugin method with JSON-object params and returns the
// JSON-decodable result. Satisfied by the daemon AgentHarness.QueryPlugin: the
// tenant is taken from the context and the can_invoke authorization is enforced
// inside that path, so invoke_tool adds no parallel authz of its own.
type PluginQuerier interface {
	QueryPlugin(ctx context.Context, name, method string, params map[string]any) (any, error)
}

// Searcher returns the ranked, authz-filtered, tenant-scoped catalog candidates
// for a query. Satisfied by *catalog.Engine.
type Searcher interface {
	Search(ctx context.Context, caller catalog.Caller, q catalog.Query) ([]catalog.Candidate, error)
}

// Handler resolves the two meta-tools onto the existing catalog and plugin-method
// machinery. It holds no state beyond its two collaborators and is safe for
// concurrent use if they are.
type Handler struct {
	search  Searcher
	querier PluginQuerier
}

// NewHandler constructs a Handler. Either collaborator may be nil; the
// corresponding meta-tool then fails closed with a configuration error rather
// than panicking, so a partially-wired daemon degrades loudly.
func NewHandler(search Searcher, querier PluginQuerier) *Handler {
	return &Handler{search: search, querier: querier}
}

// Search runs the discovery meta-tool, returning the narrowed candidate set the
// agent chooses from.
func (h *Handler) Search(ctx context.Context, caller catalog.Caller, q catalog.Query) ([]catalog.Candidate, error) {
	if h.search == nil {
		return nil, fmt.Errorf("metatool: searcher not configured")
	}
	return h.search.Search(ctx, caller, q)
}

// Invoke runs the invocation meta-tool: it decodes the canonical id and
// dispatches the chosen tool through the existing plugin-method path. args is the
// LLM-supplied argument object, passed through unchanged for the pinned-schema
// validation that QueryPlugin performs.
func (h *Handler) Invoke(ctx context.Context, id string, args map[string]any) (any, error) {
	if h.querier == nil {
		return nil, fmt.Errorf("metatool: plugin querier not configured")
	}
	tid, err := decodeID(id)
	if err != nil {
		return nil, err
	}
	name, method, ok := tid.PluginRef()
	if !ok {
		// native:<tool> primitives are not PluginInvoke targets; the daemon's
		// native dispatch path owns them and the native authz object is not yet
		// standardized (gibson#700), so invoke_tool declines them explicitly
		// rather than guessing a route.
		return nil, fmt.Errorf("metatool: native tool %q is not invocable via invoke_tool", id)
	}
	return h.querier.QueryPlugin(ctx, name, method, args)
}

// decodeID accepts the canonical colon form (mcp:<connector>:<tool>) that
// SearchTools results carry, and tolerates the flattened native-function form
// (mcp__<connector>__<tool>) for robustness, since an agent may echo back either
// the id it searched or the function name it was bound to.
func decodeID(id string) (toolid.ID, error) {
	if tid, err := toolid.Parse(id); err == nil {
		return tid, nil
	}
	tid, err := toolid.Unflatten(id)
	if err != nil {
		return toolid.ID{}, fmt.Errorf("metatool: %q is not a valid tool id (want mcp:<connector>:<tool> or native:<tool>): %w", id, err)
	}
	return tid, nil
}
