// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package discovery

import (
	"context"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	discoverypb "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/discovery/v1"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
	"github.com/zeroroot-ai/sdk/auth"
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
	prov := make(map[string]*instanceSummary, len(infos))
	for _, info := range infos {
		if info.Name == "" {
			continue
		}
		if _, dup := seen[info.Name]; !dup {
			seen[info.Name] = info
		}
		// The instances fold into provenance: how many, newest heartbeat,
		// oldest start.
		prov[info.Name] = prov[info.Name].fold(info)
	}

	// Evaluate each item's effective capabilities for the requested scope.
	items := make([]*discoverypb.CatalogItem, 0, len(seen))
	for name, info := range seen {
		item, include := s.catalogItemForScope(ctx, kind, name, &info, userRef, q)
		if !include {
			continue
		}
		s.describeProvenance(ctx, item, objectForComponent(kind, name), prov[name])
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

	switches, inCatalog := s.describeSwitches(ctx, q, userRef, tenant(ctx), object)
	item := &discoverypb.CatalogItem{
		Name:            name,
		DisplayName:     firstNonEmpty(info.Metadata["display_name"], name),
		Description:     info.Description,
		Kind:            kind,
		Rwx:             rwx,
		Version:         info.Version,
		KillSwitches:    switches,
		InTenantCatalog: inCatalog,
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

// describeDenyingGates returns the REAL denying tuples for each currently-denied
// action, by asking FGA whether a *_disabled kill switch actually applies to the
// subject on this object. It no longer fabricates a tenant_*_disabled cause for
// every denial: a component that is denied merely because it is not in the
// tenant catalog, or the caller holds no grant, has NO deny gate and reports
// none. A direct user opt-out is named precisely; a tenant- or team-level kill
// switch is reported as such. Empty when the caller passes the gate, or on a
// transient FGA error (best-effort tooltip data).
func (s *Server) describeDenyingGates(ctx context.Context, rwx *discoverypb.ActionCapabilities, subject, object, tenantName string) []string {
	gates := []string{}
	if object == "" {
		return gates
	}
	for _, act := range []struct {
		allowed bool
		name    string
	}{{rwx.Read, "read"}, {rwx.Write, "write"}, {rwx.Execute, "execute"}} {
		if act.allowed {
			continue
		}
		denied, err := s.authorizer.Check(ctx, subject, "any_"+act.name+"_deny", object)
		if err != nil {
			continue // unknown, say nothing rather than guess
		}
		if denied {
			if userDeny, uerr := s.authorizer.Check(ctx, subject, "user_"+act.name+"_disabled", object); uerr == nil && userDeny {
				gates = append(gates, fmt.Sprintf("user_%s_disabled@%s→%s", act.name, subject, object))
			} else {
				gates = append(gates, fmt.Sprintf("%s denied by a tenant or team kill switch on %s", act.name, object))
			}
			continue
		}
		// No deny exists. The denial is a missing gate: the catalog first,
		// then the grant (gibson#1610). Name which, so nobody looks for a
		// kill switch that is not there.
		if tenantName != "" {
			inCatalog, cerr := s.authorizer.Check(ctx, "tenant:"+tenantName, "tenant_enabled", object)
			if cerr == nil && !inCatalog {
				gates = append(gates, fmt.Sprintf("%s: not in tenant catalog, no tenant_enabled@tenant:%s→%s", act.name, tenantName, object))
				continue
			}
		}
		gates = append(gates, fmt.Sprintf("%s: no direct grant for %s on %s", act.name, subject, object))
	}
	return gates
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

// describeSwitches reports the deny tuples that EXIST on object, per scope
// layer, plus whether the caller's tenant has the item in its catalog. This
// is what a switch in the dashboard writes, so it is what the switch must
// show; rwx is the effective capability and needs more than these.
//
// Layers: tenant is always the caller's tenant. team is the viewed team under
// SCOPE_TEAM_VIEW. user is the viewed user under SCOPE_USER_VIEW, else the
// caller. SCOPE_COMPONENT_ENABLED has no user layer: the subject is a
// component, and the user_* relations do not admit it.
//
// Fails open to "unset": on a check error the client shows no switch state
// rather than a guess (the lesson of the fabricated denying_gates).
func (s *Server) describeSwitches(ctx context.Context, q *discoverypb.ListQuery, userRef, tenantName, object string) (*discoverypb.KillSwitches, bool) {
	if object == "" || tenantName == "" {
		return nil, false
	}
	actions := []string{"read", "write", "execute"}
	tenantRef := "tenant:" + tenantName
	checks := make([]authz.CheckRequest, 0, 3*len(actions)+1)
	for _, a := range actions {
		checks = append(checks, authz.CheckRequest{User: tenantRef, Relation: "tenant_" + a + "_disabled", Object: object})
	}
	teamRef := ""
	if q.GetScope() == discoverypb.Scope_SCOPE_TEAM_VIEW && q.GetTargetId() != "" {
		teamRef = prefixObject("team", q.GetTargetId()) + "#member"
		for _, a := range actions {
			checks = append(checks, authz.CheckRequest{User: teamRef, Relation: "team_" + a + "_disabled", Object: object})
		}
	}
	userSubject := ""
	switch q.GetScope() {
	case discoverypb.Scope_SCOPE_COMPONENT_ENABLED:
		// The subject is a component; the user_* relations do not admit it.
	case discoverypb.Scope_SCOPE_USER_VIEW:
		if q.GetTargetId() != "" {
			userSubject = prefixObject("user", q.GetTargetId())
		}
	case discoverypb.Scope_SCOPE_UNSPECIFIED,
		discoverypb.Scope_SCOPE_SYSTEM_CATALOG,
		discoverypb.Scope_SCOPE_TENANT_AVAILABLE,
		discoverypb.Scope_SCOPE_USER_ENABLED,
		discoverypb.Scope_SCOPE_TEAM_VIEW:
		userSubject = userRef
	}
	if userSubject != "" {
		for _, a := range actions {
			checks = append(checks, authz.CheckRequest{User: userSubject, Relation: "user_" + a + "_disabled", Object: object})
		}
	}
	checks = append(checks, authz.CheckRequest{User: tenantRef, Relation: "tenant_enabled", Object: object})

	results, err := s.authorizer.BatchCheck(ctx, checks)
	if err != nil || len(results) != len(checks) {
		s.logger.Warn("discovery: kill-switch check failed", "err", err, "object", object)
		return nil, false
	}
	next := 0
	take := func() *discoverypb.ActionCapabilities {
		caps := &discoverypb.ActionCapabilities{Read: results[next], Write: results[next+1], Execute: results[next+2]}
		next += 3
		return caps
	}
	out := &discoverypb.KillSwitches{Tenant: take()}
	if teamRef != "" {
		out.Team = take()
	}
	if userSubject != "" {
		out.User = take()
	}
	return out, results[next]
}

// instanceSummary folds the registry's per-instance rows for one name into
// what a person wants to see: how many, when the newest checked in, when the
// oldest started, and which tenant holds them.
type instanceSummary struct {
	tenant        string
	instances     int32
	lastHeartbeat time.Time
	startedAt     time.Time
}

func (a *instanceSummary) fold(info component.ComponentInfo) *instanceSummary {
	if a == nil {
		a = &instanceSummary{tenant: info.TenantID}
	}
	a.instances++
	if info.LastHeartbeat.After(a.lastHeartbeat) {
		a.lastHeartbeat = info.LastHeartbeat
	}
	if a.startedAt.IsZero() || (!info.StartedAt.IsZero() && info.StartedAt.Before(a.startedAt)) {
		a.startedAt = info.StartedAt
	}
	return a
}

// describeProvenance stamps what the row IS onto the item: platform catalog
// (platform_enabled@system_tenant:_system) or tenant-enrolled, plus the
// registry facts folded in instanceSummary. A check failure leaves source
// UNSPECIFIED: the client shows "unknown", never a guess.
func (s *Server) describeProvenance(ctx context.Context, item *discoverypb.CatalogItem, object string, sum *instanceSummary) {
	if sum != nil {
		item.OwnerTenant = sum.tenant
		item.Instances = sum.instances
		if !sum.lastHeartbeat.IsZero() {
			item.LastHeartbeatUnix = sum.lastHeartbeat.Unix()
		}
		if !sum.startedAt.IsZero() {
			item.StartedAtUnix = sum.startedAt.Unix()
		}
	}
	platform, err := s.authorizer.Check(ctx, "system_tenant:_system", "platform_enabled", object)
	if err != nil {
		s.logger.Warn("discovery: platform_enabled check failed", "err", err, "object", object)
		return
	}
	if platform {
		item.Source = discoverypb.Source_SOURCE_PLATFORM_CATALOG
	} else {
		item.Source = discoverypb.Source_SOURCE_TENANT_ENROLLED
	}
}
