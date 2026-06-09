// Package metatool implements the two agent-facing meta-tools from ADR-0047
// facet 5: search_tools (discovery over the FGA-scoped connector catalog) and
// invoke_tool (deterministic id → PluginInvoke{plugin_name, method} dispatch).
//
// Binding thousands of MCP tools to the LLM as native function names does not
// scale and forbids structured ids, so at MCP scale the agent loop presents
// exactly two tools — search_tools and invoke_tool — and the daemon resolves the
// canonical id behind them. The id↔(plugin, method) mapping is owned solely by
// package toolid.
//
// Authorization: invoke_tool re-checks can_invoke with the *same* authorizer the
// catalog search uses, so "searchable == invocable" holds. This is not
// redundant — invoke_tool dispatches in-process via QueryPlugin, which does not
// pass through the per-plugin ext-authz gate, and a confused or hostile agent
// may pass an id it never obtained from search_tools. The determinism boundary
// (id → install → pinned schema → arg validation → FGA → call) is preserved;
// only selection and argument fill are probabilistic, over a narrowed surface.
package metatool

import (
	"context"
	"errors"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/catalog"
	"github.com/zeroroot-ai/gibson/internal/toolid"
)

// Reserved meta-tool names. These are presented to the LLM in place of the full
// tool set and are intercepted by the harness before normal tool dispatch.
const (
	SearchToolsName = "search_tools"
	InvokeToolName  = "invoke_tool"
)

// ErrUnauthorized is returned by Invoke when the caller may not invoke the
// requested tool. Callers map it to a permission-denied result.
var ErrUnauthorized = errors.New("metatool: not authorized to invoke tool")

// PluginQuerier invokes a plugin method with JSON-object params and returns the
// JSON-decodable result. Satisfied by the daemon AgentHarness.QueryPlugin.
type PluginQuerier interface {
	QueryPlugin(ctx context.Context, name, method string, params map[string]any) (any, error)
}

// Searcher returns the ranked, authz-filtered, tenant-scoped catalog candidates
// for a query. Satisfied by *catalog.Engine.
type Searcher interface {
	Search(ctx context.Context, caller catalog.Caller, q catalog.Query) ([]catalog.Candidate, error)
}

// Handler resolves the two meta-tools onto the existing catalog, authorizer, and
// plugin-method machinery. It holds no state beyond its collaborators and is safe
// for concurrent use if they are.
type Handler struct {
	search  Searcher
	authz   catalog.Authorizer
	querier PluginQuerier
}

// NewHandler constructs a Handler. Any collaborator may be nil; the dependent
// meta-tool then fails closed with a configuration error rather than panicking,
// so a partially-wired daemon degrades loudly.
func NewHandler(search Searcher, authz catalog.Authorizer, querier PluginQuerier) *Handler {
	return &Handler{search: search, authz: authz, querier: querier}
}

// Search runs the discovery meta-tool, returning the narrowed candidate set the
// agent chooses from.
func (h *Handler) Search(ctx context.Context, caller catalog.Caller, q catalog.Query) ([]catalog.Candidate, error) {
	if h.search == nil {
		return nil, fmt.Errorf("metatool: searcher not configured")
	}
	return h.search.Search(ctx, caller, q)
}

// Invoke runs the invocation meta-tool: decode the canonical id, re-check
// can_invoke, then dispatch through the existing plugin-method path. args is the
// LLM-supplied argument object, passed through unchanged for the pinned-schema
// validation QueryPlugin performs.
func (h *Handler) Invoke(ctx context.Context, caller catalog.Caller, id string, args map[string]any) (any, error) {
	if h.querier == nil || h.authz == nil {
		return nil, fmt.Errorf("metatool: invoke is not configured")
	}
	tid, err := decodeID(id)
	if err != nil {
		return nil, err
	}
	name, method, ok := tid.PluginRef()
	if !ok {
		// native:<tool> primitives are not PluginInvoke targets; the daemon's
		// native dispatch path owns them and the native authz object is not yet
		// standardized (gibson#700), so invoke_tool declines them explicitly.
		return nil, fmt.Errorf("metatool: native tool %q is not invocable via invoke_tool", id)
	}
	allowed, err := h.authz.CanExecute(ctx, caller, tid)
	if err != nil {
		return nil, fmt.Errorf("metatool: authorization check failed for %q: %w", id, err)
	}
	if !allowed {
		return nil, fmt.Errorf("%w: %s", ErrUnauthorized, id)
	}
	return h.querier.QueryPlugin(ctx, name, method, args)
}

// decodeID accepts the canonical colon form (mcp:<connector>:<tool>) that
// SearchTools results carry, and tolerates the flattened native-function form
// (mcp__<connector>__<tool>) an agent may echo back from a directly-bound name.
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
