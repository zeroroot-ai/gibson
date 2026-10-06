// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package metatool implements the two agent-facing meta-tools from ADR-0065:
// search_tools (discovery over the FGA-scoped connector catalog) and
// invoke_tool (deterministic id → dispatch). An mcp:<connector>:<tool> id goes
// to that connector through MCP; the daemon is the one MCP client. The
// harness sends a native:<tool> id to its tool call handler: the sandbox path
// or the work queue path.
//
// Binding thousands of MCP tools to the LLM as native function names does not
// scale and forbids structured ids, so at MCP scale the agent loop presents
// exactly two tools — search_tools and invoke_tool — and the daemon resolves the
// canonical id behind them. The id rules are owned solely by package toolid.
//
// Authorization: invoke_tool re-checks can_execute with the *same* authorizer the
// catalog search uses, so "searchable == invocable" holds. This is not
// redundant: the daemon makes the call itself, so no gateway check runs on
// it, and a confused or hostile agent may pass an id it never obtained from
// search_tools. The component that the check reads is the component that the
// call reaches.
package metatool

import (
	"context"
	"errors"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/engine/catalog"
	"github.com/zeroroot-ai/gibson/internal/engine/toolid"
)

// Reserved meta-tool names. These are presented to the LLM in place of the full
// tool set and are intercepted by the harness before normal tool dispatch.
const (
	SearchToolsName = "search_tools"
	InvokeToolName  = "invoke_tool"
)

// ErrNativeID is returned by Dispatch for a native:<tool> id. The harness
// sends a native id to its tool call handler, which owns the dispatch and the
// record of the call.
var ErrNativeID = errors.New("metatool: a native tool id goes to the tool call handler")

// ErrUnauthorized is returned by Invoke when the caller may not invoke the
// requested tool. Callers map it to a permission-denied result.
var ErrUnauthorized = errors.New("metatool: not authorized to invoke tool")

// ConnectorCaller calls one tool of one connector of a tenant through MCP
// and returns the JSON-decodable result. The daemon is the one MCP client
// (ADR-0065); component.ConnectorMCP satisfies this.
type ConnectorCaller interface {
	CallConnectorTool(ctx context.Context, tenant, connector, tool string, args map[string]any) (any, error)
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
	search     Searcher
	authz      catalog.Authorizer
	connectors ConnectorCaller
}

// NewHandler constructs a Handler. Any collaborator may be nil; the dependent
// meta-tool then fails closed with a configuration error rather than panicking,
// so a partially-wired daemon degrades loudly.
func NewHandler(search Searcher, authz catalog.Authorizer, connectors ConnectorCaller) *Handler {
	return &Handler{search: search, authz: authz, connectors: connectors}
}

// Search runs the discovery meta-tool, returning the narrowed candidate set the
// agent chooses from.
func (h *Handler) Search(ctx context.Context, caller catalog.Caller, q catalog.Query) ([]catalog.Candidate, error) {
	if h.search == nil {
		return nil, fmt.Errorf("metatool: searcher not configured")
	}
	return h.search.Search(ctx, caller, q)
}

// Invoke runs the invocation meta-tool for an mcp id: Authorize, then
// Dispatch.
func (h *Handler) Invoke(ctx context.Context, caller catalog.Caller, id string, args map[string]any) (any, error) {
	tid, err := h.Authorize(ctx, caller, id)
	if err != nil {
		return nil, err
	}
	return h.Dispatch(ctx, caller, tid, args)
}

// Authorize decodes the canonical id and re-checks can_execute (ADR-0067: on
// the connector component for an mcp tool, on the tool component for a
// native tool). A caller may pass an id that it never got from search_tools,
// so the check runs for each call.
func (h *Handler) Authorize(ctx context.Context, caller catalog.Caller, id string) (toolid.ID, error) {
	if h.authz == nil {
		return toolid.ID{}, errors.New("metatool: invoke is not configured")
	}
	tid, err := decodeID(id)
	if err != nil {
		return toolid.ID{}, err
	}
	allowed, err := h.authz.CanExecute(ctx, caller, tid)
	if err != nil {
		return toolid.ID{}, fmt.Errorf("metatool: authorization check failed for %q: %w", id, err)
	}
	if !allowed {
		return toolid.ID{}, fmt.Errorf("%w: %s", ErrUnauthorized, id)
	}
	return tid, nil
}

// Dispatch sends an authorized mcp:<connector>:<tool> id to that connector
// of the tenant of the caller. The object of the can_execute check in
// Authorize and the target of the call are the same component (ADR-0067).
// args is the LLM-supplied argument object, passed through unchanged. A
// native id returns ErrNativeID.
func (h *Handler) Dispatch(ctx context.Context, caller catalog.Caller, tid toolid.ID, args map[string]any) (any, error) {
	if tid.Source != toolid.SourceMCP {
		return nil, ErrNativeID
	}
	if h.connectors == nil {
		return nil, errors.New("metatool: the connector dispatch is not configured")
	}
	result, err := h.connectors.CallConnectorTool(ctx, caller.Tenant, tid.Connector, tid.Tool, args)
	if err != nil {
		return nil, fmt.Errorf("metatool: invoke %q: %w", tid.Canonical(), err)
	}
	return result, nil
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
