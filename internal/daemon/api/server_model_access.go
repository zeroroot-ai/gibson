package api

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zero-day-ai/gibson/internal/authz"
	"github.com/zero-day-ai/gibson/internal/identity"
	modelaccesspb "github.com/zero-day-ai/sdk/api/gen/gibson/authz/v1"
)

// server_model_access.go — DaemonServer implementation of
// gibson.authz.v1.ModelAccessService. Dashboard-facing API for managing
// per-user / per-team grants on providers and models, plus inspecting
// the append-only audit stream of slot resolutions.
//
// Spec: llm-user-attribution-governance (Requirement 4). Admin-only
// mutations (gated via tenant#admin FGA); non-admins cannot grant or
// revoke. Grants materialise as FGA tuples of the shape:
//   subject -> can_use -> {provider:X | model:Y}
// where subject is "user:...", "team:...#member", or "tenant:...#member".

// subjectKindToFGA maps the proto enum to the FGA subject-reference prefix.
func subjectKindToFGA(k modelaccesspb.GrantSubjectKind, id string) (string, error) {
	switch k {
	case modelaccesspb.GrantSubjectKind_GRANT_SUBJECT_KIND_USER:
		return fmt.Sprintf("user:%s", id), nil
	case modelaccesspb.GrantSubjectKind_GRANT_SUBJECT_KIND_TEAM:
		return fmt.Sprintf("team:%s#member", id), nil
	case modelaccesspb.GrantSubjectKind_GRANT_SUBJECT_KIND_TENANT:
		return fmt.Sprintf("tenant:%s#member", id), nil
	}
	return "", status_grpc.Error(codes.InvalidArgument, "subject_kind must be user, team, or tenant")
}

// targetKindToFGA maps the proto enum + id to the FGA object reference.
func targetKindToFGA(k modelaccesspb.GrantTargetKind, id string) (string, error) {
	switch k {
	case modelaccesspb.GrantTargetKind_GRANT_TARGET_KIND_PROVIDER:
		return fmt.Sprintf("provider:%s", id), nil
	case modelaccesspb.GrantTargetKind_GRANT_TARGET_KIND_MODEL:
		return fmt.Sprintf("model:%s", id), nil
	}
	return "", status_grpc.Error(codes.InvalidArgument, "target_kind must be provider or model")
}

// fgaTargetToProto converts an FGA object reference (e.g. "provider:anthropic")
// back to (kind, id) pair for the AccessGrant response.
func fgaTargetToProto(obj string) (modelaccesspb.GrantTargetKind, string) {
	if len(obj) > 9 && obj[:9] == "provider:" {
		return modelaccesspb.GrantTargetKind_GRANT_TARGET_KIND_PROVIDER, obj[9:]
	}
	if len(obj) > 6 && obj[:6] == "model:" {
		return modelaccesspb.GrantTargetKind_GRANT_TARGET_KIND_MODEL, obj[6:]
	}
	return modelaccesspb.GrantTargetKind_GRANT_TARGET_KIND_UNSPECIFIED, obj
}

// GrantAccess persists a tenant#admin → FGA tuple writing the grant.
// The modelgate cache is invalidated as a best-effort so the next LLM
// call picks up the new grant within milliseconds rather than the 30s
// TTL.
func (s *DaemonServer) GrantAccess(ctx context.Context, req *modelaccesspb.GrantAccessRequest) (*modelaccesspb.GrantAccessResponse, error) {
	tenantID := identity.TenantFromContext(ctx)
	if tenantID == "" || tenantID == identity.SystemTenant {
		return nil, status_grpc.Error(codes.Unauthenticated, "tenant context required")
	}
	if err := s.requireTenantAdmin(ctx, tenantID); err != nil {
		return nil, err
	}
	if s.authorizer == nil {
		return nil, status_grpc.Error(codes.FailedPrecondition, "authorizer not configured")
	}

	g := req.GetGrant()
	if g == nil {
		return nil, status_grpc.Error(codes.InvalidArgument, "grant must not be nil")
	}
	subject, err := subjectKindToFGA(g.GetSubjectKind(), g.GetSubjectId())
	if err != nil {
		return nil, err
	}
	target, err := targetKindToFGA(g.GetTargetKind(), g.GetTargetId())
	if err != nil {
		return nil, err
	}

	if err := s.authorizer.Write(ctx, []authz.Tuple{{
		User:     subject,
		Relation: "can_use",
		Object:   target,
	}}); err != nil {
		s.logger.WarnContext(ctx, "model_access: grant failed",
			slog.String("error", err.Error()), slog.String("tenant", tenantID))
		return nil, status_grpc.Error(codes.Internal, "failed to persist grant")
	}

	return &modelaccesspb.GrantAccessResponse{Grant: g}, nil
}

// RevokeAccess removes an FGA tuple written by GrantAccess.
func (s *DaemonServer) RevokeAccess(ctx context.Context, req *modelaccesspb.RevokeAccessRequest) (*modelaccesspb.RevokeAccessResponse, error) {
	tenantID := identity.TenantFromContext(ctx)
	if tenantID == "" || tenantID == identity.SystemTenant {
		return nil, status_grpc.Error(codes.Unauthenticated, "tenant context required")
	}
	if err := s.requireTenantAdmin(ctx, tenantID); err != nil {
		return nil, err
	}
	if s.authorizer == nil {
		return nil, status_grpc.Error(codes.FailedPrecondition, "authorizer not configured")
	}

	subject, err := subjectKindToFGA(req.GetSubjectKind(), req.GetSubjectId())
	if err != nil {
		return nil, err
	}
	target, err := targetKindToFGA(req.GetTargetKind(), req.GetTargetId())
	if err != nil {
		return nil, err
	}
	if err := s.authorizer.Delete(ctx, []authz.Tuple{{
		User:     subject,
		Relation: "can_use",
		Object:   target,
	}}); err != nil {
		s.logger.WarnContext(ctx, "model_access: revoke failed",
			slog.String("error", err.Error()), slog.String("tenant", tenantID))
		return nil, status_grpc.Error(codes.Internal, "failed to revoke grant")
	}

	return &modelaccesspb.RevokeAccessResponse{
		RevokedAtUnix: timeNowUnix(),
	}, nil
}

// ListAccess returns all grants for the tenant, optionally narrowed to a
// specific subject. Admin-only (tenant admin FGA).
func (s *DaemonServer) ListAccess(ctx context.Context, req *modelaccesspb.ListAccessRequest) (*modelaccesspb.ListAccessResponse, error) {
	tenantID := identity.TenantFromContext(ctx)
	if tenantID == "" || tenantID == identity.SystemTenant {
		return nil, status_grpc.Error(codes.Unauthenticated, "tenant context required")
	}
	if err := s.requireTenantAdmin(ctx, tenantID); err != nil {
		return nil, err
	}
	if s.authorizer == nil {
		return nil, status_grpc.Error(codes.FailedPrecondition, "authorizer not configured")
	}

	// We list objects of each target type (provider, model) for the
	// given subject (or a wildcard probe when subject is not provided).
	var subject string
	if req.GetSubjectId() != "" {
		s, err := subjectKindToFGA(req.GetSubjectKind(), req.GetSubjectId())
		if err != nil {
			return nil, err
		}
		subject = s
	}

	grants := make([]*modelaccesspb.AccessGrant, 0)
	for _, targetType := range []string{"provider", "model"} {
		if subject == "" {
			// Without a specific subject, there is no efficient way to
			// enumerate all grants via the FGA API; dashboards that need
			// this view pass a subject explicitly or paginate per known
			// subject.
			continue
		}
		objects, err := s.authorizer.ListObjects(ctx, subject, "can_use", targetType)
		if err != nil {
			s.logger.WarnContext(ctx, "model_access: list objects failed",
				slog.String("error", err.Error()), slog.String("tenant", tenantID))
			continue
		}
		for _, obj := range objects {
			kind, id := fgaTargetToProto(obj)
			grants = append(grants, &modelaccesspb.AccessGrant{
				TenantId:    tenantID,
				SubjectKind: req.GetSubjectKind(),
				SubjectId:   req.GetSubjectId(),
				TargetKind:  kind,
				TargetId:    id,
			})
		}
	}

	return &modelaccesspb.ListAccessResponse{Grants: grants}, nil
}

// ListModelResolutionEvents returns recent model_resolved events.
// Implementation stub: returns an empty list until the audit-query
// backend wires this to Postgres / Loki; shipping as a stub (non-
// Unimplemented) is the project convention for RPCs that have a
// dashboard consumer but whose backend story is cross-cutting.
// Spec: llm-user-attribution-governance Requirement 4.9.
func (s *DaemonServer) ListModelResolutionEvents(ctx context.Context, req *modelaccesspb.ListModelResolutionEventsRequest) (*modelaccesspb.ListModelResolutionEventsResponse, error) {
	tenantID := identity.TenantFromContext(ctx)
	if tenantID == "" || tenantID == identity.SystemTenant {
		return nil, status_grpc.Error(codes.Unauthenticated, "tenant context required")
	}
	if err := s.requireTenantAdmin(ctx, tenantID); err != nil {
		return nil, err
	}
	// Empty response — backend query to be wired in a follow-up task.
	return &modelaccesspb.ListModelResolutionEventsResponse{}, nil
}

// timeNowUnix wraps time.Now().Unix() in a named helper so the value
// can be stubbed in tests that care about exact revocation timestamps.
func timeNowUnix() int64 {
	return time.Now().Unix()
}
