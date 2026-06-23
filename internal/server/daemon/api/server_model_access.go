package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
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
func subjectKindToFGA(k tenantv1.GrantSubjectKind, id string) (string, error) {
	switch k {
	case tenantv1.GrantSubjectKind_GRANT_SUBJECT_KIND_USER:
		return fmt.Sprintf("user:%s", id), nil
	case tenantv1.GrantSubjectKind_GRANT_SUBJECT_KIND_TEAM:
		return fmt.Sprintf("team:%s#member", id), nil
	case tenantv1.GrantSubjectKind_GRANT_SUBJECT_KIND_TENANT:
		return fmt.Sprintf("tenant:%s#member", id), nil
	}
	return "", status_grpc.Error(codes.InvalidArgument, "subject_kind must be user, team, or tenant")
}

// targetKindToFGA maps the proto enum + id to the FGA object reference.
func targetKindToFGA(k tenantv1.GrantTargetKind, id string) (string, error) {
	switch k {
	case tenantv1.GrantTargetKind_GRANT_TARGET_KIND_PROVIDER:
		return fmt.Sprintf("provider:%s", id), nil
	case tenantv1.GrantTargetKind_GRANT_TARGET_KIND_MODEL:
		return fmt.Sprintf("model:%s", id), nil
	}
	return "", status_grpc.Error(codes.InvalidArgument, "target_kind must be provider or model")
}

// fgaTargetToProto converts an FGA object reference (e.g. "provider:anthropic")
// back to (kind, id) pair for the AccessGrant response.
func fgaTargetToProto(obj string) (tenantv1.GrantTargetKind, string) {
	if len(obj) > 9 && obj[:9] == "provider:" {
		return tenantv1.GrantTargetKind_GRANT_TARGET_KIND_PROVIDER, obj[9:]
	}
	if len(obj) > 6 && obj[:6] == "model:" {
		return tenantv1.GrantTargetKind_GRANT_TARGET_KIND_MODEL, obj[6:]
	}
	return tenantv1.GrantTargetKind_GRANT_TARGET_KIND_UNSPECIFIED, obj
}

// GrantAccess persists a tenant#admin → FGA tuple writing the grant.
// The modelgate cache is invalidated as a best-effort so the next LLM
// call picks up the new grant within milliseconds rather than the 30s
// TTL.
func (s *DaemonServer) GrantAccess(ctx context.Context, req *tenantv1.GrantAccessRequest) (*tenantv1.GrantAccessResponse, error) {
	tenantID := auth.TenantStringFromContext(ctx)
	if tenantID == "" || tenantID == auth.SystemTenantString {
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

	// Invalidate modelgate's in-process cache so the next slot
	// resolution sees the new grant immediately. Non-blocking —
	// absent invalidator means grants take effect at the cache's
	// TTL boundary (30s worst-case).
	if s.modelGateInvalidator != nil {
		s.modelGateInvalidator.InvalidateCache()
	}

	return &tenantv1.GrantAccessResponse{Grant: g}, nil
}

// RevokeAccess removes an FGA tuple written by GrantAccess.
func (s *DaemonServer) RevokeAccess(ctx context.Context, req *tenantv1.RevokeAccessRequest) (*tenantv1.RevokeAccessResponse, error) {
	tenantID := auth.TenantStringFromContext(ctx)
	if tenantID == "" || tenantID == auth.SystemTenantString {
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

	// Invalidate modelgate's in-process cache so the revoke takes
	// effect on the next call rather than waiting for the TTL.
	if s.modelGateInvalidator != nil {
		s.modelGateInvalidator.InvalidateCache()
	}

	return &tenantv1.RevokeAccessResponse{
		RevokedAtUnix: timeNowUnix(),
	}, nil
}

// ListAccess returns all grants for the tenant, optionally narrowed to a
// specific subject. Admin-only (tenant admin FGA).
func (s *DaemonServer) ListAccess(ctx context.Context, req *tenantv1.ListAccessRequest) (*tenantv1.ListAccessResponse, error) {
	tenantID := auth.TenantStringFromContext(ctx)
	if tenantID == "" || tenantID == auth.SystemTenantString {
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

	grants := make([]*tenantv1.AccessGrant, 0)
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
			grants = append(grants, &tenantv1.AccessGrant{
				TenantId:    tenantID,
				SubjectKind: req.GetSubjectKind(),
				SubjectId:   req.GetSubjectId(),
				TargetKind:  kind,
				TargetId:    id,
			})
		}
	}

	return &tenantv1.ListAccessResponse{Grants: grants}, nil
}

// ListModelResolutionEvents returns recent model_resolved events.
// Backed by the audit.Query wired via WithAuditQuery. When the audit
// backend is not configured (e.g., no dashboard Postgres) the RPC
// returns an empty response rather than failing — dashboard callers
// render "no events in range" cleanly.
// Spec: llm-user-attribution-governance Requirement 4.9.
func (s *DaemonServer) ListModelResolutionEvents(ctx context.Context, req *tenantv1.ListModelResolutionEventsRequest) (*tenantv1.ListModelResolutionEventsResponse, error) {
	tenantID := auth.TenantStringFromContext(ctx)
	if tenantID == "" || tenantID == auth.SystemTenantString {
		return nil, status_grpc.Error(codes.Unauthenticated, "tenant context required")
	}
	if err := s.requireTenantAdmin(ctx, tenantID); err != nil {
		return nil, err
	}
	if s.auditQuery == nil {
		return &tenantv1.ListModelResolutionEventsResponse{}, nil
	}

	filters := audit.Filters{
		Action:  "model_resolved",
		ActorID: req.GetUserId(),
	}
	if sec := req.GetStartTimeUnix(); sec > 0 {
		t := time.Unix(sec, 0)
		filters.Since = &t
	}
	if sec := req.GetEndTimeUnix(); sec > 0 {
		t := time.Unix(sec, 0)
		filters.Until = &t
	}

	// Hard cap the dashboard page at 500 rows; operators who need more
	// paginate by narrowing the time range.
	rows, _, err := s.auditQuery.List(ctx, tenantID, filters, 500, 0)
	if err != nil {
		s.logger.WarnContext(ctx, "model_access: audit query failed",
			slog.String("error", err.Error()), slog.String("tenant", tenantID))
		return &tenantv1.ListModelResolutionEventsResponse{}, nil
	}

	events := make([]*tenantv1.ModelResolutionEvent, 0, len(rows))
	for _, r := range rows {
		ev := &tenantv1.ModelResolutionEvent{
			TenantId:      r.TenantID,
			UserId:        r.ActorID,
			TimestampUnix: r.CreatedAt.Unix(),
		}
		// target_id is of the form "provider/model" — split on the
		// slash. Events from other sources (none today — model_resolved
		// is emitted only by audit.EmitModelResolved) are tolerated.
		if slash := strings.IndexByte(r.TargetID, '/'); slash > 0 {
			ev.ChosenProvider = r.TargetID[:slash]
			ev.ChosenModel = r.TargetID[slash+1:]
		}
		// Unmarshal the slot-resolution metadata embedded in the event
		// to recover fields not captured by the base Event shape.
		if len(r.Metadata) > 0 {
			var meta audit.ModelResolutionEvent
			if err := json.Unmarshal(r.Metadata, &meta); err == nil {
				ev.MissionId = meta.MissionID
				ev.RunId = meta.RunID
				ev.AgentId = meta.AgentID
				ev.SlotName = meta.SlotName
				// Slot filter narrows client-side so we don't over-engineer the SQL.
				if req.GetSlotName() != "" && meta.SlotName != req.GetSlotName() {
					continue
				}
			}
		}
		events = append(events, ev)
	}
	return &tenantv1.ListModelResolutionEventsResponse{Events: events}, nil
}

// timeNowUnix wraps time.Now().Unix() in a named helper so the value
// can be stubbed in tests that care about exact revocation timestamps.
func timeNowUnix() int64 {
	return time.Now().Unix()
}
