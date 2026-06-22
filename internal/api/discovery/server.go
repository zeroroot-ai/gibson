// Package discovery implements the gRPC handlers backing
// gibson.daemon.discovery.v1.DiscoveryService. Every handler is read-only
// and enforces tenant isolation via the standard FgaAuthzInterceptor plus
// the explicit scope+action logic in each List* handler.
//
// The service is the single substrate for:
//   - opensource/adk/cmd/gibson-mcp (Claude Code's MCP discovery tools)
//   - the dashboard's in-flight migration away from
//     app/api/components/permissions/route.ts (the bridge that fail-opens
//     to enabled=true for every visible catalog item)
//   - any future gibson CLI
//
// Spec: agent-authoring-and-tenant-entitlements R1, R6.
package discovery

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	discoverypb "github.com/zeroroot-ai/gibson/internal/daemon/api/gibson/daemon/discovery/v1"

	"github.com/zeroroot-ai/gibson/internal/authz"
	"github.com/zeroroot-ai/gibson/internal/component"
	"github.com/zeroroot-ai/sdk/auth"
)

// Server implements discoverypb.DiscoveryServiceServer.
type Server struct {
	discoverypb.UnimplementedDiscoveryServiceServer

	authorizer authz.Authorizer
	registry   component.ComponentRegistry
	logger     *slog.Logger
}

// NewServer builds a DiscoveryServer wired to the injected dependencies.
// The server is registered onto the main gRPC server by daemon.Start.
func NewServer(az authz.Authorizer, reg component.ComponentRegistry, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		authorizer: az,
		registry:   reg,
		logger:     logger,
	}
}

// callerUserRef extracts the FGA user reference for the authenticated caller.
// Empty on unauthenticated contexts (which should not reach these handlers
// since the interceptor denies non-authenticated RPCs before dispatch).
func callerUserRef(ctx context.Context) string {
	id, err := auth.IdentityFromContext(ctx)
	if err != nil || id.Subject == "" {
		return ""
	}
	return "user:" + id.Subject
}

func callerTenant(ctx context.Context) string {
	return auth.TenantStringFromContext(ctx)
}

// WhoAmI reports the authenticated caller's identity, their active tenant,
// the list of teams they belong to, and a summary of their FGA relations so
// clients (MCP, dashboard, future CLI) can introspect without reimplementing
// the joins.
func (s *Server) WhoAmI(ctx context.Context, _ *discoverypb.WhoAmIRequest) (*discoverypb.WhoAmIResponse, error) {
	id, err := auth.IdentityFromContext(ctx)
	if err != nil || id.Subject == "" {
		return nil, status.Error(codes.Unauthenticated, "no identity in context")
	}

	userRef := "user:" + id.Subject
	activeTenant := callerTenant(ctx)

	// Tenant membership: ask FGA which tenants have this user as `member`.
	tenantIDs, err := s.authorizer.ListObjects(ctx, userRef, "member", "tenant")
	if err != nil {
		s.logger.Warn("discovery: whoami: ListObjects tenants failed", "err", err)
		tenantIDs = nil
	}

	// Team membership.
	teamIDs, err := s.authorizer.ListObjects(ctx, userRef, "member", "team")
	if err != nil {
		s.logger.Warn("discovery: whoami: ListObjects teams failed", "err", err)
		teamIDs = nil
	}

	// Compose a relations summary. For v1 we report tenant membership and
	// team membership; richer introspection (admin vs member per tenant)
	// can be added later by parallel ListObjects calls on other relations.
	relations := make([]string, 0, len(tenantIDs)+len(teamIDs))
	for _, t := range tenantIDs {
		relations = append(relations, prefixObject("tenant", t)+"#member")
	}
	for _, t := range teamIDs {
		relations = append(relations, prefixObject("team", t)+"#member")
	}

	resp := &discoverypb.WhoAmIResponse{
		UserId:         id.Subject,
		ActiveTenant:   activeTenant,
		Tenants:        prefixAll("tenant", tenantIDs),
		Teams:          prefixAll("team", teamIDs),
		Relations:      relations,
		IsAgentAuth:    id.Issuer == "capability-grant",
		ComponentScope: auth.ComponentScopeFromContext(ctx),
	}
	return resp, nil
}

// prefixObject returns "<type>:<id>" unless id already carries the prefix.
// Keeps the wire format stable even if Authorizer implementations return
// fully-qualified or bare ids (OpenFGA normalises, but other backends may
// not; belt-and-braces).
func prefixObject(typ, id string) string {
	if id == "" {
		return ""
	}
	if strings.Contains(id, ":") {
		return id
	}
	return typ + ":" + id
}

func prefixAll(typ string, ids []string) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = prefixObject(typ, id)
	}
	return out
}

// objectForComponent returns the FGA object string for a named component of
// the given kind. All three kinds share the `component` type in FGA; the
// kind prefix is encoded into the object id so listings can filter.
func objectForComponent(kind, name string) string {
	return fmt.Sprintf("component:%s/%s", kind, name)
}

// splitKindName inverts objectForComponent. Returns ("", "") for malformed
// ids so callers can skip silently.
func splitKindName(obj string) (kind, name string) {
	const prefix = "component:"
	if !strings.HasPrefix(obj, prefix) {
		return "", ""
	}
	rest := strings.TrimPrefix(obj, prefix)
	slash := strings.IndexByte(rest, '/')
	if slash < 0 {
		return "", ""
	}
	return rest[:slash], rest[slash+1:]
}
