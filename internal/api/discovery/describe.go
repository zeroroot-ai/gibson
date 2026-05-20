package discovery

import (
	"context"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	discoverypb "github.com/zero-day-ai/platform-sdk/gen/gibson/daemon/discovery/v1"

	"github.com/zero-day-ai/gibson/internal/component"
)

// DescribePlugin returns rich metadata + method descriptors for a named
// plugin. Called by gibson-mcp's describe_plugin tool to give Claude the
// exact JSON Schemas it needs to code-generate harness.QueryPlugin call
// sites.
//
// Note (v1): until the component registry carries method descriptors
// alongside ComponentInfo (deferred to a later spec), we return the top-
// level plugin metadata plus an empty methods[]. Claude falls back to
// reading the plugin's documentation from its GitHub repo in that case.
func (s *Server) DescribePlugin(ctx context.Context, req *discoverypb.DescribePluginRequest) (*discoverypb.DescribePluginResponse, error) {
	info, rwx, gates, err := s.lookupSingle(ctx, "plugin", req.GetName())
	if err != nil {
		return nil, err
	}
	return &discoverypb.DescribePluginResponse{
		Name:         info.Name,
		DisplayName:  firstNonEmpty(info.Metadata["display_name"], info.Name),
		Description:  info.Description,
		Version:      info.Version,
		Methods:      []*discoverypb.MethodDescriptor{}, // see note above
		Rwx:          rwx,
		DenyingGates: gates,
	}, nil
}

// DescribeTool returns the tool's proto input/output types plus action
// class so Claude can generate harness.CallToolProto calls that compile
// against the tool's published wire types.
func (s *Server) DescribeTool(ctx context.Context, req *discoverypb.DescribeToolRequest) (*discoverypb.DescribeToolResponse, error) {
	info, rwx, gates, err := s.lookupSingle(ctx, "tool", req.GetName())
	if err != nil {
		return nil, err
	}
	return &discoverypb.DescribeToolResponse{
		Name:        info.Name,
		DisplayName: firstNonEmpty(info.Metadata["display_name"], info.Name),
		Description: info.Description,
		Version:     info.Version,
		// InputProto/OutputProto live on sandboxed ComponentInfo only;
		// non-sandboxed tools leave these empty and Claude falls back to
		// the tool's own proto repo.
		InputProtoType:                   info.Metadata["input_proto_type"],
		OutputProtoType:                  info.OutputProtoType,
		ReservesField_100DiscoveryResult: true, // convention; all in-tree tools comply
		ActionClass:                      firstNonEmpty(info.Metadata["action_class"], "execute"),
		Rwx:                              rwx,
		DenyingGates:                     gates,
	}, nil
}

// DescribeAgent returns the agent's LLM slot requirements + its requested
// permissions so the dashboard's install dialog can pre-populate the
// per-action approval checklist.
func (s *Server) DescribeAgent(ctx context.Context, req *discoverypb.DescribeAgentRequest) (*discoverypb.DescribeAgentResponse, error) {
	info, rwx, gates, err := s.lookupSingle(ctx, "agent", req.GetName())
	if err != nil {
		return nil, err
	}
	// Slots and requested_permissions are not yet stored on ComponentInfo
	// — they would come from the agent's component.yaml manifest. The
	// install flow pulls these from the manifest directly; this handler
	// surfaces what the registry already knows (name, version, rwx).
	return &discoverypb.DescribeAgentResponse{
		Name:                 info.Name,
		DisplayName:          firstNonEmpty(info.Metadata["display_name"], info.Name),
		Description:          info.Description,
		Version:              info.Version,
		LlmSlots:             []string{},
		RequestedPermissions: []*discoverypb.PermissionRequest{},
		Rwx:                  rwx,
		DenyingGates:         gates,
	}, nil
}

// lookupSingle fetches a single component by (kind, name) plus computes the
// caller's effective capabilities. Used by the three Describe* handlers.
func (s *Server) lookupSingle(ctx context.Context, kind, name string) (*component.ComponentInfo, *discoverypb.ActionCapabilities, []string, error) {
	if name == "" {
		return nil, nil, nil, status.Error(codes.InvalidArgument, "name required")
	}
	tenant := callerTenant(ctx)
	instances, err := s.registry.Discover(ctx, tenant, kind, name)
	if err != nil {
		return nil, nil, nil, status.Errorf(codes.Internal, "registry: %v", err)
	}
	if len(instances) == 0 {
		return nil, nil, nil, status.Errorf(codes.NotFound, "%s %q not found", kind, name)
	}
	info := instances[0]

	// Re-use the per-item scope evaluation from list.go with a synthetic
	// USER_ENABLED query.
	userRef := callerUserRef(ctx)
	q := &discoverypb.ListQuery{Scope: discoverypb.Scope_SCOPE_USER_ENABLED}
	item, ok := s.catalogItemForScope(ctx, kind, name, &info, userRef, q)
	if !ok || item == nil {
		// Caller has no effective access; but describing is a read-only
		// curiosity, so we still return metadata with rwx={false,false,false}.
		return &info, &discoverypb.ActionCapabilities{}, nil, nil
	}
	return &info, item.Rwx, item.DenyingGates, nil
}

// ListLLMSlots returns the union of slot shapes the caller's tenant can
// satisfy via its BYOK LLM providers. v1 returns an empty list — the
// daemon's LLM provider registry does not yet expose a per-slot
// satisfaction query, so the dashboard falls back to rendering the
// provider list from component.yaml slot declarations.
func (s *Server) ListLLMSlots(ctx context.Context, _ *discoverypb.ListLLMSlotsRequest) (*discoverypb.ListLLMSlotsResponse, error) {
	// Placeholder until the LLM provider registry grows a
	// SatisfySlot(requirements) surface. Returning an empty list is safe:
	// validate_component simply doesn't emit slot_errors for now.
	return &discoverypb.ListLLMSlotsResponse{Slots: []*discoverypb.SlotInfo{}}, nil
}

// ListReportSurfaces enumerates the output conventions an agent can emit.
// v1 hardcodes the two real surfaces (Finding, Workspace) so the Claude
// CLAUDE.md has stable examples; a future task extends this to include a
// first-class Report surface when the daemon grows one.
func (s *Server) ListReportSurfaces(ctx context.Context, _ *discoverypb.ListReportSurfacesRequest) (*discoverypb.ListReportSurfacesResponse, error) {
	return &discoverypb.ListReportSurfacesResponse{
		Surfaces: []*discoverypb.ReportSurface{
			{
				Kind:        "finding",
				Description: "Structured vulnerability/observation record. Primary output of security-oriented agents. Serialized as gibson.types.v1.Finding.",
				SchemaJson:  "{}", // reference to SDK proto; full schema retrieval deferred
			},
			{
				Kind:        "workspace",
				Description: "Free-form Markdown or file-based output written via harness.Workspace().Write. Appropriate for narrative/exec-style reports.",
				SchemaJson:  "{}",
			},
		},
	}, nil
}

// suppress unused var lint when gates generation is trimmed later.
var _ = fmt.Sprintf
