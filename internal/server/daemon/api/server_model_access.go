// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/llm/modelgate"
	"github.com/zeroroot-ai/gibson/internal/engine/llm/providers"
	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/pagetoken"
	"github.com/zeroroot-ai/gibson/internal/platform/providerconfig"
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

// subjectKindToFGA maps the proto enum to the FGA subject reference.
//
// callerTenant is the tenant resolved from the ext-authz context, never from
// the request. Team FGA object ids are tenant-namespaced (authz.TeamObject,
// gibson#1231), so the team subject has to be built from the caller's own
// tenant: taking the bare `team:<id>` a caller sends would address a global
// object no team RPC creates any more, and would silently write a grant
// nothing can ever resolve. authz.TeamObject also rejects an id carrying a
// separator, a type prefix or a userset marker — the id is caller-supplied and
// lands inside an FGA reference.
func subjectKindToFGA(callerTenant string, k tenantv1.GrantSubjectKind, id string) (string, error) {
	switch k {
	case tenantv1.GrantSubjectKind_GRANT_SUBJECT_KIND_USER:
		// The form of the user's tuples (principal.FGAUser): a SPIFFE id
		// without its scheme, so the gate can match the grant.
		return "user:" + strings.TrimPrefix(id, "spiffe://"), nil
	case tenantv1.GrantSubjectKind_GRANT_SUBJECT_KIND_TEAM:
		obj, err := authz.TeamObject(callerTenant, id)
		if err != nil {
			return "", status_grpc.Errorf(codes.InvalidArgument, "subject_id: %v", err)
		}
		return obj + "#member", nil
	case tenantv1.GrantSubjectKind_GRANT_SUBJECT_KIND_TENANT:
		// The tenant subject is always the caller's own tenant. The id in the
		// request may repeat it or be empty. Any other value is refused: it
		// would name another tenant's members (hosted#358).
		if id != "" && id != callerTenant {
			return "", status_grpc.Error(codes.InvalidArgument, "subject_id: a tenant grant names the caller's own tenant")
		}
		return modelgate.TenantMembers(callerTenant), nil
	}
	return "", status_grpc.Error(codes.InvalidArgument, "subject_kind must be user, team, or tenant")
}

// targetKindToFGA maps the proto enum + id to the FGA object reference in the
// caller's tenant namespace (authz.ProviderObject, authz.ModelObject). The
// tenant comes from the authenticated context, so a grant can name only the
// caller's own providers and models.
func targetKindToFGA(callerTenant string, k tenantv1.GrantTargetKind, id string) (string, error) {
	var (
		obj string
		err error
	)
	switch k {
	case tenantv1.GrantTargetKind_GRANT_TARGET_KIND_PROVIDER:
		obj, err = authz.ProviderObject(callerTenant, id)
	case tenantv1.GrantTargetKind_GRANT_TARGET_KIND_MODEL:
		obj, err = authz.ModelObject(callerTenant, id)
	default:
		return "", status_grpc.Error(codes.InvalidArgument, "target_kind must be provider or model")
	}
	if err != nil {
		return "", status_grpc.Errorf(codes.InvalidArgument, "target_id: %v", err)
	}
	return obj, nil
}

// fgaTargetToProto converts an FGA object reference in the caller's tenant
// namespace back to the (kind, id) pair of the AccessGrant response. It
// reports false for an object outside that namespace, which the caller skips.
func fgaTargetToProto(callerTenant, obj string) (tenantv1.GrantTargetKind, string, bool) {
	typ, name, ok := authz.ModelAccessNameFromObject(callerTenant, obj)
	if !ok {
		return tenantv1.GrantTargetKind_GRANT_TARGET_KIND_UNSPECIFIED, "", false
	}
	if typ == "provider" {
		return tenantv1.GrantTargetKind_GRANT_TARGET_KIND_PROVIDER, name, true
	}
	return tenantv1.GrantTargetKind_GRANT_TARGET_KIND_MODEL, name, true
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
	subject, err := subjectKindToFGA(tenantID, g.GetSubjectKind(), g.GetSubjectId())
	if err != nil {
		return nil, err
	}
	target, err := targetKindToFGA(tenantID, g.GetTargetKind(), g.GetTargetId())
	if err != nil {
		return nil, err
	}
	// A grant must name something the gate can ask about. The gate names a
	// provider by the name of its registered provider and a model by a model of
	// such a provider. A grant on free text matches nothing, and the dashboard
	// would show it as granted. RevokeAccess does not check, so an old row can
	// still be removed.
	if err := s.checkGrantTarget(ctx, tenantID, g.GetTargetKind(), g.GetTargetId()); err != nil {
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

	subject, err := subjectKindToFGA(tenantID, req.GetSubjectKind(), req.GetSubjectId())
	if err != nil {
		return nil, err
	}
	target, err := targetKindToFGA(tenantID, req.GetTargetKind(), req.GetTargetId())
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

	return &tenantv1.RevokeAccessResponse{}, nil
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
	// A tenant subject needs no id: it is the caller's own tenant, and its
	// grants include the default grant of each provider (hosted#358).
	var subject string
	if req.GetSubjectId() != "" || req.GetSubjectKind() == tenantv1.GrantSubjectKind_GRANT_SUBJECT_KIND_TENANT {
		s, err := subjectKindToFGA(tenantID, req.GetSubjectKind(), req.GetSubjectId())
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
			kind, id, ok := fgaTargetToProto(tenantID, obj)
			if !ok {
				// A subject can hold grants in another tenant's namespace, or
				// a legacy global grant. Neither is this tenant's to list.
				continue
			}
			grants = append(grants, &tenantv1.AccessGrant{
				TenantId:    tenantID,
				SubjectKind: req.GetSubjectKind(),
				SubjectId:   req.GetSubjectId(),
				TargetKind:  kind,
				TargetId:    id,
			})
		}
	}

	// The key of a grant is its target. A subject holds one grant for each
	// target, so the key is unique in the list.
	page, err := pageOf(s.pageKeys, "tenant-access", req.GetPageSize(), req.GetPageToken(), tenantID,
		req.GetSubjectKind().String(), req.GetSubjectId())
	if err != nil {
		return nil, err
	}
	pos := func(g *tenantv1.AccessGrant) string { return g.GetTargetKind().String() + "/" + g.GetTargetId() }
	slices.SortFunc(grants, func(a, b *tenantv1.AccessGrant) int { return strings.Compare(pos(a), pos(b)) })
	grants, last, more := pagetoken.KeysetPage(grants, pos, page.after, page.hasAfter, page.limit)
	return &tenantv1.ListAccessResponse{Grants: grants, NextPageToken: page.next(last, more)}, nil
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

	page, err := pageOf(s.pageKeys, "tenant-model-resolution-events", req.GetPageSize(), req.GetPageToken(), tenantID,
		req.GetUserId(), req.GetSlotName(),
		strconv.FormatInt(req.GetStartTimeUnix(), 10), strconv.FormatInt(req.GetEndTimeUnix(), 10))
	if err != nil {
		return nil, err
	}
	// The position is the audit.Position of the last row. The audit query reads
	// it back, so the page does not use KeysetPage.
	after := page.after
	limit := page.limit
	// The slot filter reads the metadata of each row, so it runs here and not
	// in SQL. A selective slot makes a page cost several reads. Each page reads
	// at most maxResolutionBatches batches, and a page that is short carries a
	// token to go on.
	events := make([]*tenantv1.ModelResolutionEvent, 0, limit)
	lastPos, more := "", false
	for batch := 0; batch < maxResolutionBatches && len(events) < limit; batch++ {
		rows, hasMore, err := s.auditQuery.ListAfter(ctx, tenantID, filters, after, limit)
		if err != nil {
			// An empty page with no token reads as the end of the list, so a
			// read error is an error.
			s.logger.WarnContext(ctx, "model_access: audit query failed",
				slog.String("error", err.Error()), slog.String("tenant", tenantID))
			return nil, status_grpc.Error(codes.Unavailable, "audit log is not available; try again")
		}
		more = hasMore
		for i, r := range rows {
			ev, keep := resolutionEvent(r, req.GetSlotName())
			if !keep {
				lastPos = audit.Position(r)
				continue
			}
			events = append(events, ev)
			lastPos = audit.Position(r)
			if len(events) == limit {
				more = more || i < len(rows)-1
				break
			}
		}
		if !more || len(rows) == 0 {
			break
		}
		after = lastPos
	}

	return &tenantv1.ListModelResolutionEventsResponse{Events: events, NextPageToken: page.next(lastPos, more)}, nil
}

// maxResolutionBatches bounds the audit reads of one ListModelResolutionEvents
// page.
const maxResolutionBatches = 10

// resolutionEvent converts one audit row to a wire event. keep is false when
// the row does not match the slot filter.
func resolutionEvent(r audit.PgEntry, slotFilter string) (ev *tenantv1.ModelResolutionEvent, keep bool) {
	ev = &tenantv1.ModelResolutionEvent{
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
			if slotFilter != "" && meta.SlotName != slotFilter {
				return nil, false
			}
		}
	}
	return ev, true
}

// timeNowUnix wraps time.Now().Unix() in a named helper so the value
// can be stubbed in tests that care about exact revocation timestamps.
func timeNowUnix() int64 {
	return time.Now().Unix()
}

// grantListTimeout is the one total deadline for the live model lists that
// checkGrantTarget asks for, however many providers the tenant has.
var grantListTimeout = 10 * time.Second

// chatConfig reports whether a provider config of the tenant can serve chat: it
// is enabled, its type is not embedding-only, and it declares the chat
// capability or declares none (the legacy chat-only default).
func chatConfig(c *providerconfig.ProviderConfig) bool {
	if !c.Enabled || isEmbeddingOnlyType(c.Type) {
		return false
	}
	if len(c.Capabilities) == 0 {
		return true
	}
	return slices.Contains(c.Capabilities, providerconfig.CapabilityChat)
}

// checkGrantTarget refuses a grant target that matches no chat provider or chat
// model of the tenant. A provider target must be the type of an enabled,
// chat-capable provider config of the tenant. That type is the provider name
// that the gate uses. A model target must be the default model of such a config,
// or a chat model that the live list of such a provider names.
func (s *DaemonServer) checkGrantTarget(ctx context.Context, tenantID string, kind tenantv1.GrantTargetKind, id string) error {
	if s.providerConfig == nil {
		return status_grpc.Error(codes.FailedPrecondition, "provider store is not configured")
	}
	all, err := s.providerConfig.List(ctx, tenantID)
	if err != nil {
		return toGRPCProviderError("list providers", err)
	}
	configs := make([]*providerconfig.ProviderConfig, 0, len(all))
	for _, c := range all {
		if chatConfig(c) {
			configs = append(configs, c)
		}
	}
	switch kind {
	case tenantv1.GrantTargetKind_GRANT_TARGET_KIND_PROVIDER:
		for _, c := range configs {
			if string(c.Type) == id {
				return nil
			}
		}
		return status_grpc.Errorf(codes.InvalidArgument,
			"target_id: %q is not a chat provider with an enabled config of the tenant", id)
	case tenantv1.GrantTargetKind_GRANT_TARGET_KIND_MODEL:
		for _, c := range configs {
			if c.DefaultModel == id {
				return nil
			}
		}
		if s.anyProviderListsModel(ctx, tenantID, configs, id) {
			return nil
		}
		return status_grpc.Errorf(codes.InvalidArgument,
			"target_id: %q is not a chat model of an enabled provider of the tenant", id)
	case tenantv1.GrantTargetKind_GRANT_TARGET_KIND_UNSPECIFIED:
		return status_grpc.Error(codes.InvalidArgument, "target_kind must be provider or model")
	}
	return status_grpc.Error(codes.InvalidArgument, "target_kind must be provider or model")
}

// anyProviderListsModel asks the live model list of every config at once, under
// one deadline for all of them. It reports whether any list names the model as a
// chat model. A provider that cannot be built or listed names none.
func (s *DaemonServer) anyProviderListsModel(
	ctx context.Context, tenantID string, configs []*providerconfig.ProviderConfig, model string,
) bool {
	if len(configs) == 0 {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, grantListTimeout)
	defer cancel()
	found := make(chan bool, len(configs))
	for _, c := range configs {
		go func() { found <- s.providerListsModel(ctx, tenantID, c, model) }()
	}
	for range configs {
		if <-found {
			return true
		}
	}
	return false
}

// providerListsModel reports whether the live model list of the provider names
// the model as a chat model. A model with the embedding feature and no chat
// feature is not a chat model.
func (s *DaemonServer) providerListsModel(ctx context.Context, tenantID string, c *providerconfig.ProviderConfig, model string) bool {
	dec, err := s.providerConfig.Resolve(ctx, tenantID, c.Name)
	if err != nil {
		return false
	}
	factory := s.providerFactory
	if factory == nil {
		factory = providers.NewProvider
	}
	prov, err := factory(s.withEgressPolicy(decryptedConfigToLLMConfig(dec, "")))
	if err != nil {
		return false
	}
	models, err := prov.Models(ctx)
	if err != nil {
		return false
	}
	for _, m := range models {
		if m.Name == model {
			return !slices.Contains(m.Features, "embedding") || slices.Contains(m.Features, "chat")
		}
	}
	return false
}
