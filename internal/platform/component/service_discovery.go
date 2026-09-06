// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"sort"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/catalog"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// Component discovery for off-cluster components (gibson#1186 slice A).
//
// ListTools and ListAgents answer "what can I reach?" for a component that
// authenticates with a CG-JWT and holds no work item. They are served from the
// dependencies the service already owns:
//
//   - registry — the Redis component registry, constructor-required. The same
//     one CallTool resolves against (see CallTool's registry.Discover), so a
//     caller can only list a tool it could actually call. A separate lister
//     would be free to drift from that.
//   - authorizer — wired unconditionally by the daemon.
//
// Tools go through catalog.Engine, exactly as HarnessCallbackService.SearchTools
// does (internal/engine/harness/callback_searchtools.go). That reuses the
// per-method expansion of CatalogToolLister — a plugin contributes one entry per
// method, carrying the method description and input schema — and applies the
// same per-tool FGA gate. Matching the harness is deliberate: discovery
// semantics should not differ by which surface asked.
//
// The one substitution is the caller. The harness derives it from run authz
// state ("user:"+UserID); off-cluster there is no run, so the caller is the
// component principal, which ext-authz has already placed in the identity as a
// typed FGA ref ("agent_principal:<id>"). The FGA model accepts that subject:
// component.direct_execute lists agent_principal/tool_principal/plugin_principal
// directly, and tenant.member accepts them too, so `member from owner` also
// resolves (see internal/platform/authz/model.fga).

// ListTools returns the tools this tenant's caller may execute.
//
// Results reflect live, heartbeating registry instances — a registered but
// currently-down tool is not listed. For a caller that is about to invoke one,
// live-only is the useful answer.
func (s *ComponentServiceServer) ListTools(
	ctx context.Context,
	_ *componentpb.ListToolsRequest,
) (*componentpb.ListToolsResponse, error) {
	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" {
		return nil, status.Errorf(codes.Unauthenticated, "missing tenant in context")
	}
	caller, err := s.catalogCaller(ctx, tenant)
	if err != nil {
		return nil, err
	}
	if s.authorizer == nil {
		return nil, status.Errorf(codes.Unimplemented, "authorizer not configured")
	}

	engine := catalog.NewEngine(
		NewCatalogToolLister(s.registry),
		catalog.NewFGAAuthorizer(s.authorizer),
	)

	// Empty Query matches everything; the engine still applies the per-tool
	// authorization gate to each entry.
	candidates, err := engine.Search(ctx, caller, catalog.Query{Limit: maxDiscoveryResults})
	if err != nil {
		s.logger.ErrorContext(ctx, "list tools: catalog search failed",
			"tenant", tenant, "error", err)
		return nil, status.Errorf(codes.Internal, "list tools: %v", err)
	}

	tools := make([]*componentpb.ToolDescriptorProto, 0, len(candidates))
	for _, c := range candidates {
		tools = append(tools, &componentpb.ToolDescriptorProto{
			// The canonical tool id ("native:nmap", "mcp:gitlab:search") is what
			// CallTool expects, so it — not the bare method name — is the name a
			// caller must round-trip.
			Name:        c.ID,
			Description: c.Description,
			// Source and connector are the only structured facets the catalog
			// carries; surfacing them as tags lets a caller filter without
			// parsing the id.
			Tags: candidateTags(c),
		})
	}

	s.logger.DebugContext(ctx, "list tools: completed",
		"tenant", tenant, "count", len(tools))
	return &componentpb.ListToolsResponse{Tools: tools}, nil
}

// ListAgents returns the agents registered in this tenant.
//
// Agents are not tools, so they are not in the catalog engine (CatalogToolLister
// skips kind=="agent" by design). They come straight from the registry, with the
// same per-component FGA gate applied so discovery cannot reveal an agent the
// caller may not execute.
func (s *ComponentServiceServer) ListAgents(
	ctx context.Context,
	_ *componentpb.ListAgentsRequest,
) (*componentpb.ListAgentsResponse, error) {
	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" {
		return nil, status.Errorf(codes.Unauthenticated, "missing tenant in context")
	}
	caller, err := s.catalogCaller(ctx, tenant)
	if err != nil {
		return nil, err
	}
	if s.authorizer == nil {
		return nil, status.Errorf(codes.Unimplemented, "authorizer not configured")
	}

	instances, err := s.registry.DiscoverAll(ctx, tenant, "agent")
	if err != nil {
		s.logger.ErrorContext(ctx, "list agents: registry discovery failed",
			"tenant", tenant, "error", err)
		return nil, status.Errorf(codes.Internal, "list agents: %v", err)
	}

	// One registry entry per live instance; an agent running three replicas must
	// still appear once.
	seen := make(map[string]struct{}, len(instances))
	agents := make([]*componentpb.AgentDescriptorProto, 0, len(instances))
	for _, inst := range instances {
		if inst.Name == systemComponentName {
			continue // the synthetic client backplane is not a fleet agent
		}
		if _, dup := seen[inst.Name]; dup {
			continue
		}

		allowed, checkErr := s.authorizer.Check(ctx, caller.Subject, "can_execute", authz.ComponentObject(authz.KindAgent, inst.Name))
		if checkErr != nil {
			// A failed check must not leak the agent. Log and skip.
			s.logger.WarnContext(ctx, "list agents: authz check failed; omitting agent",
				"tenant", tenant, "agent", inst.Name, "error", checkErr)
			continue
		}
		if !allowed {
			continue
		}

		seen[inst.Name] = struct{}{}
		agents = append(agents, &componentpb.AgentDescriptorProto{
			Name:        inst.Name,
			Version:     inst.Version,
			Description: inst.Description,
			// Capabilities and target types are carried in registration metadata;
			// absent keys yield empty slices rather than nil surprises.
			Capabilities: metadataList(inst.Metadata, "capabilities"),
			TargetTypes:  metadataList(inst.Metadata, "target_types"),
		})
	}

	sort.Slice(agents, func(i, j int) bool { return agents[i].Name < agents[j].Name })

	s.logger.DebugContext(ctx, "list agents: completed",
		"tenant", tenant, "count", len(agents))
	return &componentpb.ListAgentsResponse{Agents: agents}, nil
}

// maxDiscoveryResults bounds a single discovery response. The catalog engine
// applies its own default when this is zero; an explicit cap keeps a tenant with
// a very large connector catalog from returning an unbounded list to an agent
// that must fit it in a prompt.
const maxDiscoveryResults = 200

// systemComponentName is the synthetic client/mission backplane object. It is
// deliberately excluded from catalog enumerations (see the CatalogFanout note in
// internal/infra/reconciler/catalog_fanout.go) and must stay out of discovery.
const systemComponentName = "_system"

// catalogCaller builds the catalog caller from the request identity.
//
// ext-authz places a typed FGA principal ref in Identity.Subject for a COMPONENT
// caller ("agent_principal:<id>"), which is exactly what the FGA check wants, so
// it is used verbatim — no prefixing.
func (s *ComponentServiceServer) catalogCaller(ctx context.Context, tenant string) (catalog.Caller, error) {
	id, err := auth.IdentityFromContext(ctx)
	if err != nil || id.Subject == "" {
		return catalog.Caller{}, status.Errorf(codes.Unauthenticated,
			"caller identity unavailable; discovery requires an authenticated principal")
	}
	return catalog.Caller{Subject: id.Subject, Tenant: tenant}, nil
}

// candidateTags renders the catalog's structured facets as descriptor tags.
func candidateTags(c catalog.Candidate) []string {
	tags := []string{"source:" + c.Source}
	if c.Connector != "" {
		tags = append(tags, "connector:"+c.Connector)
	}
	return tags
}

// metadataList reads a comma-separated registration metadata value. Registration
// metadata is map[string]string on the wire, so list-valued fields arrive joined.
func metadataList(md map[string]string, key string) []string {
	raw := md[key]
	if raw == "" {
		return nil
	}
	out := make([]string, 0, 4)
	for _, field := range strings.Split(raw, ",") {
		if f := strings.TrimSpace(field); f != "" {
			out = append(out, f)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
