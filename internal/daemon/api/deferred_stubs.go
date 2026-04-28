// Package api — deferred_stubs.go contains handlers for RPCs that are
// defined in the proto but have deferred implementations.
//
// Each handler returns codes.Unimplemented with a message that identifies
// the deferred owner. These handlers ensure that proto registration is
// complete while clearly signalling "not yet implemented" to callers.
//
// Per admin-services-completion spec disposition table:
//   - DEFER-WITH-OWNER RPCs have their proto on the correct new service
//     and their call sites removed from the dashboard; the implementation
//     ships in a future spec with the named owner.
//
// Stubs that have existing Redis-backed implementations (ListAuditEvents,
// ListConversations, GetConversation, ListAlerts, MarkAlertRead,
// MarkAllAlertsRead) are in their respective handler files; they are NOT
// listed here because they already return real data.
package api

import (
	"context"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	tenantv1 "github.com/zero-day-ai/gibson/internal/daemon/api/gibson/tenant/v1"
)

// ---------------------------------------------------------------------------
// TenantAdminService — DEFER stubs
// ---------------------------------------------------------------------------

// ExportFindings is a DEFER stub.
// Owner: <owner-pending> — findings export feature.
func (s *DaemonServer) ExportFindings(_ context.Context, _ *tenantv1.ExportFindingsRequest) (*tenantv1.ExportFindingsResponse, error) {
	return nil, status_grpc.Error(codes.Unimplemented, "ExportFindings: not yet implemented — pending findings-export feature delivery")
}

// SaveMissionDraft is a DEFER stub.
// Owner: <owner-pending> — mission YAML editor draft persistence.
func (s *DaemonServer) SaveMissionDraft(_ context.Context, _ *tenantv1.SaveMissionDraftRequest) (*tenantv1.SaveMissionDraftResponse, error) {
	return nil, status_grpc.Error(codes.Unimplemented, "SaveMissionDraft: not yet implemented — pending mission-yaml-editor spec delivery")
}

// ListMissionDrafts is a DEFER stub.
// Owner: <owner-pending> — mission YAML editor draft persistence.
func (s *DaemonServer) ListMissionDrafts(_ context.Context, _ *tenantv1.ListMissionDraftsRequest) (*tenantv1.ListMissionDraftsResponse, error) {
	return nil, status_grpc.Error(codes.Unimplemented, "ListMissionDrafts: not yet implemented — pending mission-yaml-editor spec delivery")
}
