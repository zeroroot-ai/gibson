// Package admin — grants_admin.go
//
// GrantsAdminServer implements gibson.admin.v1.GrantsAdminService — the
// dashboard's read-only inspector for active capability grants. Pairs with
// secrets_admin.go (secrets), plugin_admin.go (plugin installs), and
// tenant_admin.go (broker config).
//
// CG-JWTs are minted and revoked daemon-internally during mission dispatch;
// this admin surface is read-only in v1. Explicit revocation surfaces are a
// future spec.
//
// Spec: secrets-tenant-lifecycle Requirement 8.1, Requirement 4.
package admin

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	capabilityv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/capability/v1"
	identitypb "github.com/zeroroot-ai/sdk/api/gen/gibson/identity/v1"
	"github.com/zeroroot-ai/sdk/auth"

	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/identity"
)

// GrantInfo is the dashboard-shaped view of one active capability grant.
// It mirrors the proto wire-shape but uses native Go types for the
// timestamp fields. The production wiring populates this from the daemon's
// grant store (in-memory or Redis-backed).
type GrantInfo struct {
	JTI                string
	RecipientInstallID string
	RecipientClass     string // "agent" | "tool" | "plugin"
	RecipientName      string
	AllowedRPCs        []string
	MissionID          string
	TaskID             string
	IssuedAt           time.Time
	ExpiresAt          time.Time
}

// CapabilityGrantsReader is the narrow read-side contract this handler
// uses against the daemon's grant tracker. The production wiring is
// either a wrapper over the in-memory grant tracker or — when the
// audit-pipeline-backed Redis store lands — a query against that.
type CapabilityGrantsReader interface {
	// ListActive returns active grants for the tenant. The handler
	// applies any further filtering (recipient class, RPC, near-expiry)
	// in Go.
	ListActive(ctx context.Context, tenant auth.TenantID) ([]GrantInfo, error)
}

// GrantsAdminServer implements tenantv1.GrantsServiceServer (ADR-0039).
type GrantsAdminServer struct {
	tenantv1.UnimplementedGrantsServiceServer

	reader CapabilityGrantsReader

	// authorizer is used by Write/DeleteAgentGrants to write FGA tuples.
	// May be nil for read-only deployments; the write RPCs return
	// Unimplemented when nil.
	authorizer authz.Authorizer

	// lookup resolves target_principal_id to its tenant for the
	// cross-tenant guard in Write/DeleteAgentGrants. May be nil for
	// read-only deployments.
	lookup identity.PrincipalLookup

	// auditWriter emits agent_grant_added / agent_grant_removed events.
	// May be nil; writes succeed without an audit trail when not wired
	// (a warning is logged so the lack-of-audit is observable).
	auditWriter *audit.Writer

	logger *slog.Logger
	now    func() time.Time
}

// GrantsAdminConfig groups the constructor's required dependencies.
type GrantsAdminConfig struct {
	// Reader is required for ListActiveGrants. Pass a no-op reader
	// if the deployment does not surface CG-JWT inspection.
	Reader CapabilityGrantsReader

	// Authorizer is required for WriteAgentGrants / DeleteAgentGrants.
	// May be nil if the dashboard-side write surface is not enabled.
	Authorizer authz.Authorizer

	// Lookup resolves target principals for the cross-tenant guard.
	// Required when Authorizer is set.
	Lookup identity.PrincipalLookup

	// AuditWriter, when set, receives one event per successful grant
	// write or delete. When nil, writes proceed but audit is logged-only.
	AuditWriter *audit.Writer

	Logger *slog.Logger
	Now    func() time.Time
}

// NewGrantsAdminServer constructs a GrantsAdminServer. Reader is required.
// Authorizer + Lookup are required together to enable the write RPCs.
func NewGrantsAdminServer(cfg GrantsAdminConfig) (*GrantsAdminServer, error) {
	if cfg.Reader == nil {
		return nil, errors.New("grants admin: Reader is required")
	}
	if (cfg.Authorizer != nil) != (cfg.Lookup != nil) {
		return nil, errors.New("grants admin: Authorizer and Lookup must be supplied together")
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &GrantsAdminServer{
		reader:      cfg.Reader,
		authorizer:  cfg.Authorizer,
		lookup:      cfg.Lookup,
		auditWriter: cfg.AuditWriter,
		logger:      logger,
		now:         now,
	}, nil
}

// nearExpiryWindow is the window inside which a grant is highlighted as
// nearing expiry per Requirement 4.1. The dashboard renders these rows
// with a warning class.
const nearExpiryWindow = 5 * time.Minute

// ListActiveGrants returns active capability grants for the tenant
// resolved from identity, optionally filtered by recipient class, RPC,
// and near-expiry.
func (s *GrantsAdminServer) ListActiveGrants(ctx context.Context, req *tenantv1.ListActiveGrantsRequest) (*tenantv1.ListActiveGrantsResponse, error) {
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "no tenant in context")
	}

	grants, err := s.reader.ListActive(ctx, tenant)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list active grants: %v", err)
	}

	now := s.now()

	// Apply filters in Go.
	classFilter := req.GetRecipientClassFilter()
	rpcFilter := req.GetRpcFilter()
	nearOnly := req.GetIncludeNearExpiryOnly()

	out := make([]*capabilityv1.CapabilityGrantInfo, 0, len(grants))
	for _, g := range grants {
		// Defense-in-depth: skip expired grants the reader may still return.
		if !g.ExpiresAt.IsZero() && !g.ExpiresAt.After(now) {
			continue
		}

		nearExpiry := false
		if !g.ExpiresAt.IsZero() && g.ExpiresAt.Sub(now) <= nearExpiryWindow {
			nearExpiry = true
		}

		if nearOnly && !nearExpiry {
			continue
		}

		class := classFromString(g.RecipientClass)
		if classFilter != capabilityv1.RecipientClass_RECIPIENT_CLASS_UNSPECIFIED && class != classFilter {
			continue
		}

		if rpcFilter != "" && !containsString(g.AllowedRPCs, rpcFilter) {
			continue
		}

		out = append(out, &capabilityv1.CapabilityGrantInfo{
			Jti:                g.JTI,
			RecipientInstallId: g.RecipientInstallID,
			RecipientClass:     class,
			RecipientName:      g.RecipientName,
			AllowedRpcs:        g.AllowedRPCs,
			MissionId:          g.MissionID,
			TaskId:             g.TaskID,
			IssuedAtUnix:       g.IssuedAt.Unix(),
			ExpiresAtUnix:      g.ExpiresAt.Unix(),
			NearExpiry:         nearExpiry,
		})
	}

	// Sort: near-expiry first (dashboard renders them at top), then by
	// expires_at ascending.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].GetNearExpiry() != out[j].GetNearExpiry() {
			return out[i].GetNearExpiry()
		}
		return out[i].GetExpiresAtUnix() < out[j].GetExpiresAtUnix()
	})

	// Apply pagination.
	limit := int(req.GetLimit())
	if limit <= 0 {
		limit = 100
	}
	offset := int(req.GetOffset())
	if offset < 0 {
		offset = 0
	}
	total := int32(len(out))
	if offset >= len(out) {
		out = out[:0]
	} else {
		end := offset + limit
		if end > len(out) {
			end = len(out)
		}
		out = out[offset:end]
	}

	return &tenantv1.ListActiveGrantsResponse{
		Grants: out,
		Total:  total,
	}, nil
}

// classFromString maps the lowercase string class label to the proto enum.
func classFromString(s string) capabilityv1.RecipientClass {
	switch s {
	case "agent":
		return capabilityv1.RecipientClass_RECIPIENT_CLASS_AGENT
	case "tool":
		return capabilityv1.RecipientClass_RECIPIENT_CLASS_TOOL
	case "plugin":
		return capabilityv1.RecipientClass_RECIPIENT_CLASS_PLUGIN
	default:
		return capabilityv1.RecipientClass_RECIPIENT_CLASS_UNSPECIFIED
	}
}

// containsString reports whether s appears in xs (exact match).
func containsString(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// allowedRelations is the set of FGA relations Write/DeleteAgentGrants
// will accept. Anything else is InvalidArgument before any tuple is
// touched.
var allowedRelations = map[string]struct{}{
	"can_read":      {},
	"can_configure": {},
	"can_execute":   {},
	"can_invoke":    {},
}

// WriteAgentGrants additively writes per-action FGA tuples for a target
// agent / tool principal. Idempotent: tuples that already exist count as
// already_present rather than failing.
//
// Spec: component-bootstrap-e2e Requirement 9.
func (s *GrantsAdminServer) WriteAgentGrants(ctx context.Context, req *tenantv1.WriteAgentGrantsRequest) (*tenantv1.WriteAgentGrantsResponse, error) {
	if s.authorizer == nil || s.lookup == nil {
		return nil, status.Error(codes.Unimplemented, "agent-grant write surface not enabled")
	}

	target, callerTenant, err := s.validateTargetAndTenant(ctx, req.GetTargetPrincipalId())
	if err != nil {
		return nil, err
	}

	if err := validateGrantTuples(req.GetGrants(), target.Kind); err != nil {
		return nil, err
	}

	// Two-pass idempotency: build the FGA tuples first, dedupe against
	// already-present via Check, then Write only the missing ones.
	tuples := make([]authz.Tuple, 0, len(req.GetGrants()))
	for _, g := range req.GetGrants() {
		tuples = append(tuples, authz.Tuple{
			User:     target.PrincipalID,
			Relation: g.GetRelation(),
			Object:   g.GetObject(),
		})
	}

	checks := make([]authz.CheckRequest, len(tuples))
	for i, t := range tuples {
		checks[i] = authz.CheckRequest{User: t.User, Relation: t.Relation, Object: t.Object}
	}
	results, err := s.authorizer.BatchCheck(ctx, checks)
	if err != nil {
		s.logger.ErrorContext(ctx, "grants admin: BatchCheck failed",
			slog.String("target", target.PrincipalID),
			slog.String("error", err.Error()),
		)
		return nil, status.Errorf(codes.Internal, "batch check existing tuples: %v", err)
	}

	var toWrite []authz.Tuple
	alreadyPresent := int32(0)
	for i, present := range results {
		if present {
			alreadyPresent++
			continue
		}
		toWrite = append(toWrite, tuples[i])
	}

	if len(toWrite) > 0 {
		if err := s.authorizer.Write(ctx, toWrite); err != nil {
			s.logger.ErrorContext(ctx, "grants admin: write tuples failed",
				slog.String("target", target.PrincipalID),
				slog.Int("count", len(toWrite)),
				slog.String("error", err.Error()),
			)
			return nil, status.Errorf(codes.Internal, "write tuples: %v", err)
		}
	}

	s.emitGrantAudit(ctx, callerTenant, target.PrincipalID, "agent_grant_added", toWrite)

	return &tenantv1.WriteAgentGrantsResponse{
		Written:        int32(len(toWrite)),
		AlreadyPresent: alreadyPresent,
	}, nil
}

// DeleteAgentGrants removes per-action FGA tuples. Idempotent: tuples
// that do not exist count as not_present.
//
// Spec: component-bootstrap-e2e Requirement 9.
func (s *GrantsAdminServer) DeleteAgentGrants(ctx context.Context, req *tenantv1.DeleteAgentGrantsRequest) (*tenantv1.DeleteAgentGrantsResponse, error) {
	if s.authorizer == nil || s.lookup == nil {
		return nil, status.Error(codes.Unimplemented, "agent-grant write surface not enabled")
	}

	target, callerTenant, err := s.validateTargetAndTenant(ctx, req.GetTargetPrincipalId())
	if err != nil {
		return nil, err
	}

	if err := validateGrantTuples(req.GetGrants(), target.Kind); err != nil {
		return nil, err
	}

	tuples := make([]authz.Tuple, 0, len(req.GetGrants()))
	for _, g := range req.GetGrants() {
		tuples = append(tuples, authz.Tuple{
			User:     target.PrincipalID,
			Relation: g.GetRelation(),
			Object:   g.GetObject(),
		})
	}

	checks := make([]authz.CheckRequest, len(tuples))
	for i, t := range tuples {
		checks[i] = authz.CheckRequest{User: t.User, Relation: t.Relation, Object: t.Object}
	}
	results, err := s.authorizer.BatchCheck(ctx, checks)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "batch check existing tuples: %v", err)
	}

	var toDelete []authz.Tuple
	notPresent := int32(0)
	for i, present := range results {
		if !present {
			notPresent++
			continue
		}
		toDelete = append(toDelete, tuples[i])
	}

	if len(toDelete) > 0 {
		if err := s.authorizer.Delete(ctx, toDelete); err != nil {
			return nil, status.Errorf(codes.Internal, "delete tuples: %v", err)
		}
	}

	s.emitGrantAudit(ctx, callerTenant, target.PrincipalID, "agent_grant_removed", toDelete)

	return &tenantv1.DeleteAgentGrantsResponse{
		Deleted:    int32(len(toDelete)),
		NotPresent: notPresent,
	}, nil
}

// validateTargetAndTenant resolves target_principal_id and enforces the
// caller-and-target-share-a-tenant guard. Returns the target record and
// the caller's tenant (which equals the target's tenant on success).
func (s *GrantsAdminServer) validateTargetAndTenant(ctx context.Context, targetID string) (identity.PrincipalRecord, string, error) {
	if targetID == "" {
		return identity.PrincipalRecord{}, "", status.Error(codes.InvalidArgument, "target_principal_id is required")
	}
	callerTenant := auth.TenantStringFromContext(ctx)
	if callerTenant == "" {
		return identity.PrincipalRecord{}, "", status.Error(codes.PermissionDenied, "no tenant in context")
	}

	target, err := s.lookup.Resolve(ctx, targetID)
	if errors.Is(err, identity.ErrPrincipalNotFound) {
		return identity.PrincipalRecord{}, "", status.Errorf(codes.NotFound, "principal not found: %s", targetID)
	}
	if err != nil {
		s.logger.ErrorContext(ctx, "grants admin: principal lookup failed",
			slog.String("target", targetID),
			slog.String("error", err.Error()),
		)
		return identity.PrincipalRecord{}, "", status.Error(codes.Internal, "principal lookup failed")
	}
	if target.TenantID != callerTenant {
		s.logger.WarnContext(ctx, "grants admin: cross-tenant grant write rejected",
			slog.String("caller_tenant", callerTenant),
			slog.String("target_tenant", target.TenantID),
		)
		return identity.PrincipalRecord{}, "", status.Error(codes.PermissionDenied,
			"target principal is not in your tenant")
	}
	return target, callerTenant, nil
}

// validateGrantTuples enforces:
//   - non-empty grants slice (empty is allowed but trivially no-op;
//     callers shouldn't send it but we tolerate it)
//   - relation in the allow-list
//   - object is non-empty
//   - if relation == "can_invoke", target's kind MUST be TOOL (FGA model
//     excludes agent_principal from plugin.can_invoke)
func validateGrantTuples(grants []*tenantv1.GrantTuple, targetKind identitypb.PrincipalKind) error {
	for i, g := range grants {
		if strings.TrimSpace(g.GetObject()) == "" {
			return status.Errorf(codes.InvalidArgument, "grants[%d].object is required", i)
		}
		if _, ok := allowedRelations[g.GetRelation()]; !ok {
			return status.Errorf(codes.InvalidArgument,
				"grants[%d].relation %q not allowed; must be one of can_read, can_configure, can_execute, can_invoke",
				i, g.GetRelation())
		}
		if g.GetRelation() == "can_invoke" && targetKind != identitypb.PrincipalKind_PRINCIPAL_KIND_TOOL {
			return status.Errorf(codes.InvalidArgument,
				"grants[%d].relation can_invoke is only valid when target kind is TOOL (got %s); the FGA model excludes agent_principal from plugin.can_invoke",
				i, targetKind.String())
		}
	}
	return nil
}

// emitGrantAudit records one audit event per tuple written or deleted.
// When the writer is nil, the event is structured-logged instead so the
// trail is still observable in operator logs.
func (s *GrantsAdminServer) emitGrantAudit(ctx context.Context, tenant, target, action string, tuples []authz.Tuple) {
	callerID, _ := auth.IdentityFromContext(ctx)
	for _, t := range tuples {
		md, _ := json.Marshal(map[string]any{
			"target_principal_id": target,
			"object":              t.Object,
			"relation":            t.Relation,
		})
		evt := audit.Event{
			TenantID:   tenant,
			ActorID:    callerID.Subject,
			ActorType:  "user",
			Action:     action,
			TargetType: "agent_grant",
			TargetID:   target,
			Decision:   "allow",
			Metadata:   md,
		}
		if s.auditWriter != nil {
			s.auditWriter.Log(evt)
			continue
		}
		s.logger.InfoContext(ctx, "grants admin: audit event (no writer wired)",
			slog.String("action", action),
			slog.String("actor", callerID.Subject),
			slog.String("target", target),
			slog.String("object", t.Object),
			slog.String("relation", t.Relation),
		)
	}
}
