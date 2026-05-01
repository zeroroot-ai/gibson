// Package identity implements gibson.identity.v1.IdentityService — the
// daemon's "what can I do?" RPC. WhoAmI returns the calling principal's
// effective component-level FGA grants, plugin invocation grants, and
// active capability grants in a single round trip.
//
// Spec: component-bootstrap-e2e Requirement 10.
package identity

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identitypb "github.com/zero-day-ai/sdk/api/gen/gibson/identity/v1"
	"github.com/zero-day-ai/sdk/auth"

	"github.com/zero-day-ai/gibson/internal/authz"
)

// truncationCap is the safety bound on per-action grant enumeration.
// A principal with more component_*_enabled tuples than this is unusual
// and the response is marked truncated rather than enumerating all of
// them. The dashboard surfaces the truncation flag as a UI warning.
const truncationCap = 1000

// PrincipalLookup resolves a principal_id ("agent_principal:<uuid>" /
// "tool_principal:<uuid>" / "plugin_principal:<uuid>") to its tenant
// and human-readable name. The daemon's TenantAdminService persists
// these records; this interface is the narrow read surface IdentityServer
// needs without coupling to the larger admin store.
type PrincipalLookup interface {
	// Resolve returns the principal's tenant_id, name, and kind. If the
	// principal is not found, returns ErrPrincipalNotFound.
	Resolve(ctx context.Context, principalID string) (PrincipalRecord, error)
}

// PrincipalRecord is the minimal projection of a registered principal.
type PrincipalRecord struct {
	PrincipalID string
	TenantID    string
	Name        string
	Kind        identitypb.PrincipalKind
}

// ErrPrincipalNotFound is returned by PrincipalLookup.Resolve when the
// requested principal does not exist.
var ErrPrincipalNotFound = errors.New("principal not found")

// IdentityServer implements identitypb.IdentityServiceServer.
type IdentityServer struct {
	identitypb.UnimplementedIdentityServiceServer

	authorizer authz.Authorizer
	lookup     PrincipalLookup
	logger     *slog.Logger
}

// Config groups the constructor's required dependencies.
type Config struct {
	Authorizer authz.Authorizer
	Lookup     PrincipalLookup
	Logger     *slog.Logger
}

// NewServer constructs an IdentityServer. Authorizer and Lookup are
// required; Logger defaults to slog.Default when nil.
func NewServer(cfg Config) (*IdentityServer, error) {
	if cfg.Authorizer == nil {
		return nil, errors.New("identity: Authorizer is required")
	}
	if cfg.Lookup == nil {
		return nil, errors.New("identity: Lookup is required")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &IdentityServer{
		authorizer: cfg.Authorizer,
		lookup:     cfg.Lookup,
		logger:     logger,
	}, nil
}

// WhoAmI returns the caller's effective FGA grants. When
// target_principal_id is set, the caller MUST be tenant_admin on the
// target's tenant — otherwise PermissionDenied. Identity is derived
// from ext-authz-emitted headers, never from the request body.
func (s *IdentityServer) WhoAmI(ctx context.Context, req *identitypb.WhoAmIRequest) (*identitypb.WhoAmIResponse, error) {
	callerID, err := auth.IdentityFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "no identity in context")
	}
	callerTenant := auth.TenantStringFromContext(ctx)
	if callerTenant == "" {
		return nil, status.Error(codes.PermissionDenied, "no tenant in context")
	}

	// Resolve target — either the caller themselves or an explicit
	// principal the caller is asking about.
	var target PrincipalRecord
	if req.GetTargetPrincipalId() == "" {
		target = PrincipalRecord{
			PrincipalID: callerID.Subject,
			TenantID:    callerTenant,
			Name:        callerID.Subject,
			Kind:        kindFromPrincipalID(callerID.Subject),
		}
	} else {
		// Admin variant — caller MUST be tenant_admin on the target's
		// tenant. We resolve the target first to discover its tenant,
		// then check.
		t, lookupErr := s.lookup.Resolve(ctx, req.GetTargetPrincipalId())
		if errors.Is(lookupErr, ErrPrincipalNotFound) {
			return nil, status.Errorf(codes.NotFound, "principal not found: %s", req.GetTargetPrincipalId())
		}
		if lookupErr != nil {
			s.logger.ErrorContext(ctx, "identity: lookup failed",
				slog.String("principal_id", req.GetTargetPrincipalId()),
				slog.String("error", lookupErr.Error()),
			)
			return nil, status.Error(codes.Internal, "principal lookup failed")
		}
		// Ext-authz already verified the caller is admin of THEIR tenant
		// (tenant_from_identity deriver). We additionally require the
		// target be in the caller's tenant — cross-tenant inspection is
		// not allowed.
		if t.TenantID != callerTenant {
			s.logger.WarnContext(ctx, "identity: cross-tenant WhoAmI rejected",
				slog.String("caller_tenant", callerTenant),
				slog.String("target_tenant", t.TenantID),
			)
			return nil, status.Error(codes.PermissionDenied,
				"target principal is not in your tenant")
		}
		target = t
	}

	componentGrants, truncatedComp, err := s.collectComponentGrants(ctx, target)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list component grants: %v", err)
	}

	pluginGrants, truncatedPlug, err := s.collectPluginGrants(ctx, target)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list plugin grants: %v", err)
	}

	resp := &identitypb.WhoAmIResponse{
		PrincipalId:     target.PrincipalID,
		Kind:            target.Kind,
		Name:            target.Name,
		TenantId:        target.TenantID,
		ComponentGrants: componentGrants,
		PluginGrants:    pluginGrants,
		// active_capability_grants intentionally empty until the
		// CG-JWT reader is wired into IdentityServer. Tracked as a
		// follow-up task in component-bootstrap-e2e Phase 2.
		ActiveCapabilityGrants: nil,
		Truncated:              truncatedComp || truncatedPlug,
	}
	return resp, nil
}

// collectComponentGrants enumerates the principal's per-action grants
// on the `component` FGA type. For each of the three relations
// (component_read_enabled / component_write_enabled /
// component_execute_enabled), we ListObjects to find every component
// the principal has been granted that action on.
func (s *IdentityServer) collectComponentGrants(ctx context.Context, target PrincipalRecord) ([]*identitypb.ComponentGrantEffective, bool, error) {
	type relSpec struct {
		fga    string
		setter func(*identitypb.ComponentGrantEffective)
	}
	rels := []relSpec{
		{"component_read_enabled", func(g *identitypb.ComponentGrantEffective) { g.CanRead = true }},
		{"component_write_enabled", func(g *identitypb.ComponentGrantEffective) { g.CanConfigure = true }},
		{"component_execute_enabled", func(g *identitypb.ComponentGrantEffective) { g.CanExecute = true }},
	}

	user := target.PrincipalID

	byRef := make(map[string]*identitypb.ComponentGrantEffective)
	truncated := false
	for _, r := range rels {
		objects, err := s.authorizer.ListObjects(ctx, user, r.fga, "component")
		if err != nil {
			s.logger.WarnContext(ctx, "identity: ListObjects failed; continuing",
				slog.String("user", user),
				slog.String("relation", r.fga),
				slog.String("error", err.Error()),
			)
			// Treat as "no grants for this relation"; do not abort the
			// whole listing, the partial answer is still useful.
			continue
		}
		for _, obj := range objects {
			entry, ok := byRef[obj]
			if !ok {
				if len(byRef) >= truncationCap {
					truncated = true
					continue
				}
				entry = &identitypb.ComponentGrantEffective{
					ComponentRef: obj,
					Sources: []*identitypb.GrantSource{{
						Kind: identitypb.GrantSource_KIND_DIRECT,
					}},
				}
				byRef[obj] = entry
			}
			r.setter(entry)
		}
	}

	out := make([]*identitypb.ComponentGrantEffective, 0, len(byRef))
	for _, v := range byRef {
		out = append(out, v)
	}
	return out, truncated, nil
}

// collectPluginGrants enumerates the principal's plugin invocation
// grants. By the FGA model, agent_principals are excluded from
// plugin.can_invoke; this method short-circuits to empty for AGENT
// targets.
func (s *IdentityServer) collectPluginGrants(ctx context.Context, target PrincipalRecord) ([]*identitypb.PluginGrantEffective, bool, error) {
	if target.Kind == identitypb.PrincipalKind_PRINCIPAL_KIND_AGENT {
		return nil, false, nil
	}
	objects, err := s.authorizer.ListObjects(ctx, target.PrincipalID, "can_invoke", "plugin")
	if err != nil {
		return nil, false, fmt.Errorf("list plugin can_invoke: %w", err)
	}
	if len(objects) > truncationCap {
		objects = objects[:truncationCap]
	}
	out := make([]*identitypb.PluginGrantEffective, 0, len(objects))
	for _, obj := range objects {
		out = append(out, &identitypb.PluginGrantEffective{
			PluginRef: obj,
			Sources: []*identitypb.GrantSource{{
				Kind: identitypb.GrantSource_KIND_DIRECT,
			}},
		})
	}
	return out, len(objects) >= truncationCap, nil
}

// FGALookup is a PrincipalLookup implementation backed by the daemon's
// FGA Authorizer. It resolves a principal to its tenant by querying
// the `belongs_to` relation written at agent-identity creation time
// (see internal/daemon/api/tenant_admin_create.go).
//
// This avoids coupling the identity service to the IdP-side service-
// account store; the FGA tuple is the daemon's source of truth for
// "what tenant does this principal belong to?".
type FGALookup struct {
	Authorizer authz.Authorizer
}

// Resolve returns the principal's tenant_id and kind. Name is set to
// principal_id since FGA does not store display names; consumers that
// need a friendly name should fall through to the IdP store.
func (f *FGALookup) Resolve(ctx context.Context, principalID string) (PrincipalRecord, error) {
	if f.Authorizer == nil {
		return PrincipalRecord{}, errors.New("identity: FGALookup.Authorizer is nil")
	}
	objects, err := f.Authorizer.ListObjects(ctx, principalID, "belongs_to", "tenant")
	if err != nil {
		return PrincipalRecord{}, fmt.Errorf("identity: FGALookup ListObjects: %w", err)
	}
	if len(objects) == 0 {
		return PrincipalRecord{}, ErrPrincipalNotFound
	}
	tenantID := strings.TrimPrefix(objects[0], "tenant:")
	return PrincipalRecord{
		PrincipalID: principalID,
		TenantID:    tenantID,
		Name:        principalID,
		Kind:        kindFromPrincipalID(principalID),
	}, nil
}

// kindFromPrincipalID extracts a PrincipalKind from a principal_id
// prefix. Used for self-WhoAmI when we do not call the lookup.
func kindFromPrincipalID(principalID string) identitypb.PrincipalKind {
	switch {
	case strings.HasPrefix(principalID, "agent_principal:"):
		return identitypb.PrincipalKind_PRINCIPAL_KIND_AGENT
	case strings.HasPrefix(principalID, "tool_principal:"):
		return identitypb.PrincipalKind_PRINCIPAL_KIND_TOOL
	case strings.HasPrefix(principalID, "plugin_principal:"):
		return identitypb.PrincipalKind_PRINCIPAL_KIND_PLUGIN
	default:
		return identitypb.PrincipalKind_PRINCIPAL_KIND_UNSPECIFIED
	}
}
