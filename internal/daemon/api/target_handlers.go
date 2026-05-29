package api

import (
	"context"
	"errors"
	"strings"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	daemonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"
	targetpb "github.com/zeroroot-ai/sdk/api/gen/gibson/target/v1"
	"github.com/zeroroot-ai/sdk/auth"

	"github.com/zeroroot-ai/gibson/internal/target"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// CreateTarget registers a new target for the calling tenant and returns its
// server-minted UUID. Any id supplied on the request is ignored.
func (s *DaemonServer) CreateTarget(ctx context.Context, req *daemonpb.CreateTargetRequest) (*daemonpb.CreateTargetResponse, error) {
	if s.targetService == nil {
		return nil, status_grpc.Error(codes.Unavailable, "target service not initialized")
	}
	tenantID := auth.TenantStringFromContext(ctx)
	if tenantID == "" {
		return nil, status_grpc.Error(codes.Internal, "CreateTarget: no tenant in context")
	}
	created, err := s.targetService.Create(ctx, tenantID, fromProtoTarget(req.GetTarget()))
	if err != nil {
		return nil, mapTargetError(err)
	}
	p, err := toProtoTarget(created)
	if err != nil {
		return nil, err
	}
	return &daemonpb.CreateTargetResponse{TargetId: created.ID.String(), Target: p}, nil
}

// GetTarget returns a single target by UUID, scoped to the caller's tenant.
func (s *DaemonServer) GetTarget(ctx context.Context, req *daemonpb.GetTargetRequest) (*daemonpb.GetTargetResponse, error) {
	if s.targetService == nil {
		return nil, status_grpc.Error(codes.Unavailable, "target service not initialized")
	}
	tenantID := auth.TenantStringFromContext(ctx)
	if tenantID == "" {
		return nil, status_grpc.Error(codes.Internal, "GetTarget: no tenant in context")
	}
	got, err := s.targetService.Get(ctx, tenantID, req.GetTargetId())
	if err != nil {
		return nil, mapTargetError(err)
	}
	p, err := toProtoTarget(got)
	if err != nil {
		return nil, err
	}
	return &daemonpb.GetTargetResponse{Target: p}, nil
}

// ListTargets returns the caller tenant's targets, narrowed by TargetFilter.
func (s *DaemonServer) ListTargets(ctx context.Context, req *daemonpb.ListTargetsRequest) (*daemonpb.ListTargetsResponse, error) {
	if s.targetService == nil {
		return nil, status_grpc.Error(codes.Unavailable, "target service not initialized")
	}
	tenantID := auth.TenantStringFromContext(ctx)
	if tenantID == "" {
		return nil, status_grpc.Error(codes.Internal, "ListTargets: no tenant in context")
	}
	targets, err := s.targetService.List(ctx, tenantID, protoTargetFilter(req.GetFilter()))
	if err != nil {
		return nil, mapTargetError(err)
	}
	out := make([]*targetpb.Target, 0, len(targets))
	for _, t := range targets {
		p, err := toProtoTarget(t)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return &daemonpb.ListTargetsResponse{Targets: out}, nil
}

// UpdateTarget replaces a target's metadata. The id is the lookup key and is
// never changed; ownership and creation time are preserved.
func (s *DaemonServer) UpdateTarget(ctx context.Context, req *daemonpb.UpdateTargetRequest) (*daemonpb.UpdateTargetResponse, error) {
	if s.targetService == nil {
		return nil, status_grpc.Error(codes.Unavailable, "target service not initialized")
	}
	tenantID := auth.TenantStringFromContext(ctx)
	if tenantID == "" {
		return nil, status_grpc.Error(codes.Internal, "UpdateTarget: no tenant in context")
	}
	updated, err := s.targetService.Update(ctx, tenantID, fromProtoTarget(req.GetTarget()))
	if err != nil {
		return nil, mapTargetError(err)
	}
	p, err := toProtoTarget(updated)
	if err != nil {
		return nil, err
	}
	return &daemonpb.UpdateTargetResponse{Target: p}, nil
}

// DeleteTarget removes a target by UUID, scoped to the caller's tenant.
func (s *DaemonServer) DeleteTarget(ctx context.Context, req *daemonpb.DeleteTargetRequest) (*daemonpb.DeleteTargetResponse, error) {
	if s.targetService == nil {
		return nil, status_grpc.Error(codes.Unavailable, "target service not initialized")
	}
	tenantID := auth.TenantStringFromContext(ctx)
	if tenantID == "" {
		return nil, status_grpc.Error(codes.Internal, "DeleteTarget: no tenant in context")
	}
	if err := s.targetService.Delete(ctx, tenantID, req.GetTargetId()); err != nil {
		return nil, mapTargetError(err)
	}
	return &daemonpb.DeleteTargetResponse{Success: true}, nil
}

// --- proto <-> types conversion -------------------------------------------

func toProtoTarget(t *types.Target) (*targetpb.Target, error) {
	if t == nil {
		return nil, nil
	}
	p := &targetpb.Target{
		Id:           t.ID.String(),
		Name:         t.Name,
		Type:         t.Type,
		Provider:     t.Provider.String(),
		Model:        t.Model,
		Capabilities: t.Capabilities,
		AuthType:     t.AuthType.String(),
		Status:       t.Status.String(),
		Description:  t.Description,
		Tags:         t.Tags,
		Timeout:      int32(t.Timeout),
		Url:          t.URL,
		Headers:      t.Headers,
	}
	if t.CredentialID != nil {
		p.CredentialId = t.CredentialID.String()
	}
	if len(t.Connection) > 0 {
		conn, err := structpb.NewStruct(t.Connection)
		if err != nil {
			return nil, status_grpc.Errorf(codes.InvalidArgument, "invalid connection: %v", err)
		}
		p.Connection = conn
	}
	if len(t.Config) > 0 {
		cfg, err := structpb.NewStruct(t.Config)
		if err != nil {
			return nil, status_grpc.Errorf(codes.InvalidArgument, "invalid config: %v", err)
		}
		p.Config = cfg
	}
	if !t.CreatedAt.IsZero() {
		p.CreatedAt = timestamppb.New(t.CreatedAt)
	}
	if !t.UpdatedAt.IsZero() {
		p.UpdatedAt = timestamppb.New(t.UpdatedAt)
	}
	return p, nil
}

// fromProtoTarget maps wire metadata into a types.Target. ID is carried through
// (the Update lookup key); TenantID is never read from the wire — the service
// stamps it from the caller's identity.
func fromProtoTarget(p *targetpb.Target) *types.Target {
	if p == nil {
		return nil
	}
	t := &types.Target{
		ID:           types.ID(p.GetId()),
		Name:         p.GetName(),
		Type:         p.GetType(),
		Provider:     types.Provider(p.GetProvider()),
		Model:        p.GetModel(),
		Capabilities: p.GetCapabilities(),
		AuthType:     types.AuthType(p.GetAuthType()),
		Status:       types.TargetStatus(p.GetStatus()),
		Description:  p.GetDescription(),
		Tags:         p.GetTags(),
		Timeout:      int(p.GetTimeout()),
		URL:          p.GetUrl(),
		Headers:      p.GetHeaders(),
	}
	if cid := p.GetCredentialId(); cid != "" {
		if id, err := types.ParseID(cid); err == nil {
			t.CredentialID = &id
		}
	}
	if p.GetConnection() != nil {
		t.Connection = p.GetConnection().AsMap()
	}
	if p.GetConfig() != nil {
		t.Config = p.GetConfig().AsMap()
	}
	return t
}

func protoTargetFilter(f *targetpb.TargetFilter) *types.TargetFilter {
	if f == nil {
		return nil
	}
	out := &types.TargetFilter{
		Tags:   f.GetTags(),
		Limit:  int(f.GetLimit()),
		Offset: int(f.GetOffset()),
	}
	if p := f.GetProvider(); p != "" {
		prov := types.Provider(p)
		out.Provider = &prov
	}
	if ty := f.GetType(); ty != "" {
		typ := ty
		out.Type = &typ
	}
	if st := f.GetStatus(); st != "" {
		status := types.TargetStatus(st)
		out.Status = &status
	}
	return out
}

// mapTargetError translates target service sentinels into gRPC status codes.
func mapTargetError(err error) error {
	switch {
	case errors.Is(err, target.ErrNotFound):
		return status_grpc.Error(codes.NotFound, "target not found")
	case errors.Is(err, target.ErrInvalidID):
		return status_grpc.Errorf(codes.InvalidArgument, "%v", err)
	case errors.Is(err, target.ErrTargetRequired):
		return status_grpc.Errorf(codes.InvalidArgument, "%v", err)
	case errors.Is(err, target.ErrTenantRequired):
		return status_grpc.Error(codes.Internal, "no tenant in context")
	case err != nil && strings.Contains(err.Error(), "validation"):
		// Store-level validation (missing endpoint, bad provider, etc.) is a
		// caller error, not an internal fault — surface it as InvalidArgument
		// with the message so the dashboard/CLI can show what to fix.
		return status_grpc.Errorf(codes.InvalidArgument, "%v", err)
	default:
		return preserveStatus(err, "target operation failed")
	}
}
