// Package catalog is the SearchTools query engine.
//
// Agents do not receive every tool as a native function (that neither scales to
// thousands of MCP connector tools nor fits the provider function-name limits).
// Instead they search the catalog and invoke by id. The Engine answers a search
// over a ToolLister — the tenant's live tools, sourced from the existing
// component registry and harness tool expansion — applies structured filters,
// and removes any tool the caller is not authorized to execute. Every returned
// candidate carries a canonical tool id (see internal/toolid) that decomposes to
// the existing (plugin_name, method) dispatch key.
//
// The Engine depends only on the narrow ToolLister and Authorizer interfaces, so
// it is unit-testable in isolation. See ADR-0047 facet 5.
package catalog

import (
	"context"
	"fmt"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/toolid"
)

// DefaultLimit caps a search that does not request its own limit.
const DefaultLimit = 20

// Caller identifies the principal performing a search.
type Caller struct {
	Subject string
	Tenant  string
}

// ToolEntry is a raw tool as enumerated from a backing store, before id
// assignment and authorization.
type ToolEntry struct {
	Source      toolid.Source
	Connector   string // connector/plugin name; empty for native primitives
	Tool        string // tool / method name
	Description string
	InputSchema []byte
}

// ToolLister enumerates a tenant's live tools. In production it is backed by the
// component registry plus the harness tool expansion; tests fake it.
type ToolLister interface {
	ListTools(ctx context.Context, tenant string) ([]ToolEntry, error)
}

// Authorizer reports whether a caller may execute a tool. In production it is
// backed by the FGA can_execute check; tests fake it.
type Authorizer interface {
	CanExecute(ctx context.Context, caller Caller, id toolid.ID) (bool, error)
}

// Candidate is an authorized, typed search result.
type Candidate struct {
	ID          string // canonical tool id
	Source      string
	Connector   string
	Tool        string
	Description string
	InputSchema []byte
}

// Query carries the agent's search request: free text plus structured filters.
type Query struct {
	// Text is a case-insensitive substring matched against the tool name and
	// description. Empty matches everything. (Semantic ranking is a later
	// enhancement; see ADR-0047.)
	Text string
	// Sources restricts results to the given sources. Empty means all.
	Sources []toolid.Source
	// Connector restricts results to a single connector instance. Empty means all.
	Connector string
	// Limit caps the candidate count. Zero uses DefaultLimit.
	Limit int
}

// Engine answers SearchTools queries over a ToolLister, authz-filtered.
type Engine struct {
	lister ToolLister
	authz  Authorizer
}

// NewEngine constructs an Engine.
func NewEngine(lister ToolLister, authz Authorizer) *Engine {
	return &Engine{lister: lister, authz: authz}
}

// Search returns the authorized, tenant-scoped, filtered candidate set.
//
// Order of operations per entry: the cheap structured filters run first; the
// per-tool authorization check runs last and is the security gate — a tool the
// caller cannot can_execute is never returned. Malformed raw entries (those that
// cannot form a valid id) are skipped, not surfaced.
func (e *Engine) Search(ctx context.Context, caller Caller, q Query) ([]Candidate, error) {
	entries, err := e.lister.ListTools(ctx, caller.Tenant)
	if err != nil {
		return nil, fmt.Errorf("catalog: list tools: %w", err)
	}

	limit := q.Limit
	if limit <= 0 {
		limit = DefaultLimit
	}

	out := make([]Candidate, 0, limit)
	for _, en := range entries {
		if !matchSource(q.Sources, en.Source) {
			continue
		}
		if q.Connector != "" && en.Connector != q.Connector {
			continue
		}
		if !matchText(q.Text, en) {
			continue
		}
		id, err := idFor(en)
		if err != nil {
			continue // skip malformed entries rather than fail the whole search
		}
		ok, err := e.authz.CanExecute(ctx, caller, id)
		if err != nil {
			return nil, fmt.Errorf("catalog: authz check %s: %w", id.Canonical(), err)
		}
		if !ok {
			continue
		}
		out = append(out, Candidate{
			ID:          id.Canonical(),
			Source:      string(en.Source),
			Connector:   en.Connector,
			Tool:        en.Tool,
			Description: en.Description,
			InputSchema: en.InputSchema,
		})
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

// idFor builds the canonical id for a raw entry.
func idFor(en ToolEntry) (toolid.ID, error) {
	switch en.Source {
	case toolid.SourceMCP:
		return toolid.ForMCP(en.Connector, en.Tool)
	case toolid.SourceNative:
		return toolid.ForNative(en.Tool)
	default:
		return toolid.ID{}, fmt.Errorf("catalog: unknown source %q", en.Source)
	}
}

// matchSource reports whether src passes the source filter (empty filter = all).
func matchSource(filter []toolid.Source, src toolid.Source) bool {
	if len(filter) == 0 {
		return true
	}
	for _, s := range filter {
		if s == src {
			return true
		}
	}
	return false
}

// matchText reports whether the entry matches the free-text filter (empty = all),
// case-insensitively against the tool name and description.
func matchText(text string, en ToolEntry) bool {
	if text == "" {
		return true
	}
	t := strings.ToLower(text)
	return strings.Contains(strings.ToLower(en.Tool), t) ||
		strings.Contains(strings.ToLower(en.Description), t)
}
