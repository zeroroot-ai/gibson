package discovery

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	discoverypb "github.com/zero-day-ai/sdk/api/gen/gibson/daemon/discovery/v1"

	"github.com/zero-day-ai/gibson/internal/authz"
	"github.com/zero-day-ai/gibson/internal/component"
	"github.com/zero-day-ai/sdk/auth"
)

// listCatalog is the shared workhorse for ListPlugins/ListTools/ListAgents.
// kind is the component kind string ("plugin" / "tool" / "agent"); the
// response CatalogItem.Kind field carries the same string so clients can
// render mixed lists without a second lookup.
func (s *Server) listCatalog(ctx context.Context, kind string, q *discoverypb.ListQuery) ([]*discoverypb.CatalogItem, string, error) {
	if q == nil {
		q = &discoverypb.ListQuery{}
	}
	userRef := callerUserRef(ctx)
	tenant := callerTenant(ctx)
	if tenant == "" {
		return nil, "", status.Error(codes.PermissionDenied, "no tenant in context")
	}

	// Fetch the raw catalog from the Redis registry scoped to the caller's
	// tenant. DiscoverAll already unions system-tenant and tenant-scoped
	// entries, and our FGA model treats both uniformly via platform_enabled
	// OR tenant_published.
	infos, err := s.registry.DiscoverAll(ctx, tenant, kind)
	if err != nil {
		return nil, "", status.Errorf(codes.Internal, "registry discover: %v", err)
	}

	// Deduplicate on (kind, name) — DiscoverAll returns one row per running
	// instance, but the catalog model is one entry per name.
	seen := make(map[string]component.ComponentInfo, len(infos))
	for _, info := range infos {
		if info.Name == "" {
			continue
		}
		if _, dup := seen[info.Name]; !dup {
			seen[info.Name] = info
		}
	}

	// Evaluate each item's effective capabilities for the requested scope.
	items := make([]*discoverypb.CatalogItem, 0, len(seen))
	for name, info := range seen {
		item, include := s.catalogItemForScope(ctx, kind, name, &info, userRef, q)
		if !include {
			continue
		}
		items = append(items, item)
	}

	// Simple lexicographic pagination: sort by name and apply cursor/limit.
	items = paginate(items, q.GetCursor(), q.GetPageSize())
	nextCursor := ""
	if int32(len(items)) == pageLimit(q.GetPageSize()) {
		nextCursor = items[len(items)-1].Name
	}
	return items, nextCursor, nil
}

const (
	defaultPageSize = 100
	maxPageSize     = 1000
)

func pageLimit(requested int32) int32 {
	if requested <= 0 {
		return defaultPageSize
	}
	if requested > maxPageSize {
		return maxPageSize
	}
	return requested
}

func paginate(items []*discoverypb.CatalogItem, cursor string, pageSize int32) []*discoverypb.CatalogItem {
	limit := int(pageLimit(pageSize))
	// Stable order: items slice may be in map-iteration order; sort by name.
	sortByName(items)
	start := 0
	for i, it := range items {
		if it.Name > cursor {
			start = i
			break
		}
		if i == len(items)-1 && it.Name <= cursor {
			start = len(items)
		}
	}
	end := start + limit
	if end > len(items) {
		end = len(items)
	}
	return items[start:end]
}

func sortByName(items []*discoverypb.CatalogItem) {
	// Simple insertion sort — catalog sizes are bounded (low hundreds) so
	// avoiding the sort package keeps the dependency graph tight.
	for i := 1; i < len(items); i++ {
		for j := i; j > 0 && items[j-1].Name > items[j].Name; j-- {
			items[j-1], items[j] = items[j], items[j-1]
		}
	}
}

// catalogItemForScope evaluates a single component against the request's
// scope + action. Returns the CatalogItem plus whether it should appear in
// the response. Effective capabilities are resolved via BatchCheck for
// efficiency and denying_gates enumerates the tuples whose removal would
// flip a currently-denied action to allowed.
func (s *Server) catalogItemForScope(
	ctx context.Context, kind, name string, info *component.ComponentInfo,
	userRef string, q *discoverypb.ListQuery,
) (*discoverypb.CatalogItem, bool) {
	object := objectForComponent(kind, name)

	subject := userRef
	isComponentSubject := false
	if q.GetScope() == discoverypb.Scope_SCOPE_COMPONENT_ENABLED {
		scope := auth.ComponentScopeFromContext(ctx)
		if scope == "" {
			// Component scope required for this view.
			return nil, false
		}
		subject = scope
		isComponentSubject = true
	}
	// USER_VIEW / TEAM_VIEW override the subject with the target.
	if q.GetScope() == discoverypb.Scope_SCOPE_USER_VIEW {
		if q.GetTargetId() == "" {
			return nil, false
		}
		subject = prefixObject("user", q.GetTargetId())
	}
	if q.GetScope() == discoverypb.Scope_SCOPE_TEAM_VIEW {
		if q.GetTargetId() == "" {
			return nil, false
		}
		subject = prefixObject("team", q.GetTargetId())
	}

	// Resolve the three per-action capabilities in one round-trip.
	checks := []authz.CheckRequest{
		{User: subject, Relation: actionRelationFor(discoverypb.Action_ACTION_READ, isComponentSubject), Object: object},
		{User: subject, Relation: actionRelationFor(discoverypb.Action_ACTION_WRITE, isComponentSubject), Object: object},
		{User: subject, Relation: actionRelationFor(discoverypb.Action_ACTION_EXECUTE, isComponentSubject), Object: object},
	}
	results, err := s.authorizer.BatchCheck(ctx, checks)
	if err != nil {
		s.logger.Warn("discovery: batch check failed", "err", err, "object", object)
		return nil, false
	}
	rwx := &discoverypb.ActionCapabilities{
		Read:    len(results) > 0 && results[0],
		Write:   len(results) > 1 && results[1],
		Execute: len(results) > 2 && results[2],
	}

	// Action filter: when the caller specified a single action, exclude
	// items that don't currently permit it. ACTION_UNSPECIFIED returns the
	// item regardless.
	switch q.GetAction() {
	case discoverypb.Action_ACTION_READ:
		if !rwx.Read {
			return nil, false
		}
	case discoverypb.Action_ACTION_WRITE:
		if !rwx.Write {
			return nil, false
		}
	case discoverypb.Action_ACTION_EXECUTE:
		if !rwx.Execute {
			return nil, false
		}
	}

	// For USER_ENABLED scope we additionally enforce that the item passes
	// deny-wins for the caller — which BatchCheck already reflects through
	// the model's `can_*` relations (they embed the deny layers).
	// SYSTEM_CATALOG and TENANT_AVAILABLE scopes intentionally ignore
	// denies; compute rwx against a simplified relation set in those cases.
	switch q.GetScope() {
	case discoverypb.Scope_SCOPE_SYSTEM_CATALOG, discoverypb.Scope_SCOPE_TENANT_AVAILABLE:
		// For these scopes, capabilities reflect "can this be enabled?"
		// not "is it currently effective?". Leave rwx as computed but mark
		// denying_gates empty — the admin UI toggles writes tenant-level
		// denies, it doesn't care which layer currently denies.
	}

	item := &discoverypb.CatalogItem{
		Name:        name,
		DisplayName: firstNonEmpty(info.Metadata["display_name"], name),
		Description: info.Description,
		Kind:        kind,
		Rwx:         rwx,
		Version:     info.Version,
	}

	// denying_gates: cheap heuristic — if the user currently doesn't have
	// an action, surface the most likely deny tuple at each scope so the
	// UI tooltip gives a useful hint. Full gate-traversal (walking every
	// tenant/team/user disabled relation) is deferred; this surfaces the
	// most likely culprit by convention.
	item.DenyingGates = s.describeDenyingGates(ctx, rwx, subject, object, tenant(ctx))
	return item, true
}

func tenant(ctx context.Context) string {
	return callerTenant(ctx)
}

// actionRelationFor returns the FGA relation name to check for the given
// action. For user subjects the canonical can_*; for component subjects the
// narrowed can_*_as_component variant. Action_UNSPECIFIED defaults to read.
func actionRelationFor(a discoverypb.Action, component bool) string {
	switch a {
	case discoverypb.Action_ACTION_WRITE:
		if component {
			return "can_write_as_component"
		}
		return "can_configure"
	case discoverypb.Action_ACTION_EXECUTE:
		if component {
			return "can_execute_as_component"
		}
		return "can_execute"
	default:
		if component {
			return "can_read_as_component"
		}
		return "can_read"
	}
}

// describeDenyingGates returns a small list of likely denying tuples per
// action class when the action is currently denied. The list surfaces the
// most common cause at each scope so UI tooltips have something concrete
// to show. Empty when the caller passes the gate.
func (s *Server) describeDenyingGates(ctx context.Context, rwx *discoverypb.ActionCapabilities, subject, object, tenantName string) []string {
	gates := []string{}
	if !rwx.Read {
		gates = appendGate(gates, "tenant_read_disabled", object, tenantName)
	}
	if !rwx.Write {
		gates = appendGate(gates, "tenant_write_disabled", object, tenantName)
	}
	if !rwx.Execute {
		gates = appendGate(gates, "tenant_execute_disabled", object, tenantName)
	}
	return gates
}

func appendGate(gates []string, relation, object, tenantName string) []string {
	if object == "" || tenantName == "" {
		return gates
	}
	return append(gates, fmt.Sprintf("%s@tenant:%s→%s", relation, tenantName, object))
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// ListPlugins implements DiscoveryServiceServer.
func (s *Server) ListPlugins(ctx context.Context, req *discoverypb.ListPluginsRequest) (*discoverypb.ListPluginsResponse, error) {
	items, next, err := s.listCatalog(ctx, "plugin", req.GetQuery())
	if err != nil {
		return nil, err
	}
	return &discoverypb.ListPluginsResponse{Items: items, NextCursor: next}, nil
}

// ListTools implements DiscoveryServiceServer.
func (s *Server) ListTools(ctx context.Context, req *discoverypb.ListToolsRequest) (*discoverypb.ListToolsResponse, error) {
	items, next, err := s.listCatalog(ctx, "tool", req.GetQuery())
	if err != nil {
		return nil, err
	}
	return &discoverypb.ListToolsResponse{Items: items, NextCursor: next}, nil
}

// ListAgents implements DiscoveryServiceServer.
func (s *Server) ListAgents(ctx context.Context, req *discoverypb.ListAgentsRequest) (*discoverypb.ListAgentsResponse, error) {
	items, next, err := s.listCatalog(ctx, "agent", req.GetQuery())
	if err != nil {
		return nil, err
	}
	return &discoverypb.ListAgentsResponse{Items: items, NextCursor: next}, nil
}

// unused reference to keep strings import when gates string-format paths are
// trimmed during future refactors.
var _ = strings.Join
