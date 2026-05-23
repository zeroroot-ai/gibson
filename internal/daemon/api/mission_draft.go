// Package api — mission_draft.go wires the four mission-draft RPCs
// (Save, List, Get, Delete) on TenantAdminService to the Redis-backed
// missiondraft.Store. The store is wired via WithMissionDraftStore at
// daemon construction time (internal/daemon/grpc.go).
//
// Spec: mission-draft-dashboard-wiring.
package api

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zero-day-ai/gibson/internal/missiondraft"
	tenantv1 "github.com/zero-day-ai/platform-sdk/gen/gibson/tenant/v1"
	"github.com/zero-day-ai/sdk/auth"
)

// SaveMissionDraft persists a mission YAML draft for the calling tenant.
// When req.DraftId is empty a new draft is created and its ID returned;
// otherwise the existing draft is overwritten.
func (s *DaemonServer) SaveMissionDraft(ctx context.Context, req *tenantv1.SaveMissionDraftRequest) (*tenantv1.SaveMissionDraftResponse, error) {
	if s.missionDraftStore == nil {
		return nil, status_grpc.Error(codes.Unavailable, "mission draft store is not configured")
	}

	tenantID := req.GetTenantId()
	if tenantID == "" {
		tenantID = auth.TenantStringFromContext(ctx)
	}
	if tenantID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id is required")
	}
	if err := s.requireTenantAdmin(ctx, tenantID); err != nil {
		return nil, err
	}

	draftID, err := s.missionDraftStore.Save(ctx, tenantID, req.GetName(), req.GetCueSource(), req.GetDraftId())
	if err != nil {
		return nil, status_grpc.Errorf(codes.Internal, "save mission draft: %v", err)
	}
	return &tenantv1.SaveMissionDraftResponse{DraftId: draftID}, nil
}

// ListMissionDrafts returns all saved mission drafts for the calling tenant
// ordered by update time descending. YAML content is omitted from list
// responses; use GetMissionDraft to fetch a single draft's full content.
func (s *DaemonServer) ListMissionDrafts(ctx context.Context, req *tenantv1.ListMissionDraftsRequest) (*tenantv1.ListMissionDraftsResponse, error) {
	if s.missionDraftStore == nil {
		return nil, status_grpc.Error(codes.Unavailable, "mission draft store is not configured")
	}

	tenantID := req.GetTenantId()
	if tenantID == "" {
		tenantID = auth.TenantStringFromContext(ctx)
	}
	if tenantID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id is required")
	}
	if err := s.requireTenantAdmin(ctx, tenantID); err != nil {
		return nil, err
	}

	drafts, err := s.missionDraftStore.List(ctx, tenantID)
	if err != nil {
		return nil, status_grpc.Errorf(codes.Internal, "list mission drafts: %v", err)
	}

	out := make([]*tenantv1.MissionDraft, 0, len(drafts))
	for _, d := range drafts {
		out = append(out, &tenantv1.MissionDraft{
			Id:        d.ID,
			Name:      d.Name,
			CreatedAt: d.CreatedAt,
			UpdatedAt: d.UpdatedAt,
		})
	}
	return &tenantv1.ListMissionDraftsResponse{Drafts: out}, nil
}

// GetMissionDraft fetches a single saved draft including its YAML content.
// Returns codes.NotFound when no draft with that ID exists for the tenant.
func (s *DaemonServer) GetMissionDraft(ctx context.Context, req *tenantv1.GetMissionDraftRequest) (*tenantv1.GetMissionDraftResponse, error) {
	if s.missionDraftStore == nil {
		return nil, status_grpc.Error(codes.Unavailable, "mission draft store is not configured")
	}

	tenantID := req.GetTenantId()
	if tenantID == "" {
		tenantID = auth.TenantStringFromContext(ctx)
	}
	if tenantID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id is required")
	}
	if req.GetDraftId() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "draft_id is required")
	}
	if err := s.requireTenantAdmin(ctx, tenantID); err != nil {
		return nil, err
	}

	d, err := s.missionDraftStore.Get(ctx, tenantID, req.GetDraftId())
	if err != nil {
		if errors.Is(err, missiondraft.ErrDraftNotFound) {
			return nil, status_grpc.Error(codes.NotFound, "draft not found")
		}
		return nil, status_grpc.Errorf(codes.Internal, "get mission draft: %v", err)
	}
	return &tenantv1.GetMissionDraftResponse{
		Draft: &tenantv1.MissionDraftFull{
			Id:        d.ID,
			Name:      d.Name,
			CreatedAt: d.CreatedAt,
			UpdatedAt: d.UpdatedAt,
			CueSource: d.YAML,
		},
	}, nil
}

// DeleteMissionDraft removes a saved draft. Idempotent: deleting a missing
// draft returns OK (the underlying Redis DEL is a no-op on missing keys).
func (s *DaemonServer) DeleteMissionDraft(ctx context.Context, req *tenantv1.DeleteMissionDraftRequest) (*tenantv1.DeleteMissionDraftResponse, error) {
	if s.missionDraftStore == nil {
		return nil, status_grpc.Error(codes.Unavailable, "mission draft store is not configured")
	}

	tenantID := req.GetTenantId()
	if tenantID == "" {
		tenantID = auth.TenantStringFromContext(ctx)
	}
	if tenantID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id is required")
	}
	if req.GetDraftId() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "draft_id is required")
	}
	if err := s.requireTenantAdmin(ctx, tenantID); err != nil {
		return nil, err
	}

	if err := s.missionDraftStore.Delete(ctx, tenantID, req.GetDraftId()); err != nil {
		return nil, status_grpc.Errorf(codes.Internal, "delete mission draft: %v", err)
	}
	return &tenantv1.DeleteMissionDraftResponse{}, nil
}
