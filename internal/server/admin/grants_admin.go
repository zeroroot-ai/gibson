// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

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
	"fmt"
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
	"github.com/zeroroot-ai/gibson/internal/platform/pagetoken"
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

// GrantsAdminServer implements tenantv1.GrantsServiceServer (ADR-0058).
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
	auditWriter audit.DurableWriter

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
	AuditWriter audit.DurableWriter

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

	// Apply pagination (ADR-0028, rule 3).
	offset, limit, err := pagetoken.Window(req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	total := len(out)
	if offset >= total {
		out = out[:0]
	} else {
		out = out[offset:min(offset+limit, total)]
	}

	return &tenantv1.ListActiveGrantsResponse{
		Grants:        out,
		Total:         pagetoken.Int32(total),
		NextPageToken: pagetoken.Next(offset, limit, len(out), total),
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

// grantTuples builds the FGA tuple of each grant for the target principal.
//
// A request names the action: can_read, can_configure, can_execute or
// can_invoke. The first three are computed relations in the FGA model, and a
// computed relation takes no tuple. The tuple goes on the relation that
// authz.GrantTupleRelation gives, which is the matching direct_ relation.
// validateGrantTuples runs first, so each action here has a tuple relation.
func grantTuples(target string, grants []*tenantv1.GrantTuple) []authz.Tuple {
	tuples := make([]authz.Tuple, 0, len(grants))
	for _, g := range grants {
		relation, _ := authz.GrantTupleRelation(g.GetRelation())
		tuples = append(tuples, authz.Tuple{
			User:     target,
			Relation: relation,
			Object:   g.GetObject(),
		})
	}
	return tuples
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

	callerIdentity, identityErr := auth.IdentityFromContext(ctx)
	if identityErr != nil || callerIdentity.Subject == "" {
		return nil, status.Errorf(codes.PermissionDenied, "no identity in context")
	}
	callerRef := "user:" + callerIdentity.Subject

	// Caller-access intersection check: a caller may only forward an action
	// on an object that the caller already holds themselves. The check uses
	// the action that the request names (can_read, can_configure,
	// can_execute, can_invoke). For a component that is the computed
	// relation, so the tenant catalog and the deny relations apply to the
	// caller. The tuple for the recipient goes on the direct_ relation.
	//
	// validateTargetAndTenant above only binds the RECIPIENT to the caller's
	// tenant — it says nothing about whether the caller can reach the
	// requested OBJECT. Without this check, any caller with WriteAgentGrants
	// access could grant an agent/tool principal in their own tenant access
	// to an arbitrary caller-supplied component/plugin object, including one
	// the caller has no access to at all. Spec: identity-assertion-gaps
	// finding 4.
	callerChecks := make([]authz.CheckRequest, len(req.GetGrants()))
	for i, g := range req.GetGrants() {
		callerChecks[i] = authz.CheckRequest{User: callerRef, Relation: g.GetRelation(), Object: g.GetObject()}
	}
	callerHasAccess, err := s.authorizer.BatchCheck(ctx, callerChecks)
	if err != nil {
		s.logger.ErrorContext(ctx, "grants admin: caller-access BatchCheck failed",
			slog.String("caller", callerRef),
			slog.String("target", target.PrincipalID),
			slog.String("error", err.Error()),
		)
		return nil, status.Errorf(codes.Internal, "batch check caller access: %v", err)
	}
	for i, allowed := range callerHasAccess {
		if !allowed {
			s.logger.WarnContext(ctx, "grants admin: caller-access intersection failed",
				slog.String("caller", callerRef),
				slog.String("target", target.PrincipalID),
				slog.String("relation", req.GetGrants()[i].GetRelation()),
				slog.String("object", req.GetGrants()[i].GetObject()),
			)
			return nil, status.Errorf(codes.PermissionDenied,
				"caller does not have %s access on %s", req.GetGrants()[i].GetRelation(), req.GetGrants()[i].GetObject())
		}
	}

	// Two-pass idempotency: build the FGA tuples first, dedupe against
	// already-present via Check, then Write only the missing ones.
	tuples := grantTuples(target.PrincipalID, req.GetGrants())

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

	actor, ok := grantActor(ctx)
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "no caller identity in context")
	}
	if err := s.recordGrantAudit(ctx, actor, callerTenant, target.PrincipalID, "agent_grant_added", toWrite); err != nil {
		return nil, status.Error(codes.Unavailable, "the audit record of the grant change could not be written; nothing changed")
	}
	if len(toWrite) > 0 {
		if err := s.authorizer.Write(ctx, toWrite); err != nil {
			s.recordGrantFailure(ctx, actor, callerTenant, target.PrincipalID, "agent_grant_added", toWrite)
			s.logger.ErrorContext(ctx, "grants admin: write tuples failed",
				slog.String("target", target.PrincipalID),
				slog.Int("count", len(toWrite)),
				slog.String("error", err.Error()),
			)
			return nil, status.Errorf(codes.Internal, "write tuples: %v", err)
		}
	}

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

	// The same tuples that WriteAgentGrants writes: on the direct_ relation
	// for a component action.
	tuples := grantTuples(target.PrincipalID, req.GetGrants())

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

	actor, ok := grantActor(ctx)
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "no caller identity in context")
	}
	if err := s.recordGrantAudit(ctx, actor, callerTenant, target.PrincipalID, "agent_grant_removed", toDelete); err != nil {
		return nil, status.Error(codes.Unavailable, "the audit record of the grant change could not be written; nothing changed")
	}
	if len(toDelete) > 0 {
		if err := s.authorizer.Delete(ctx, toDelete); err != nil {
			s.recordGrantFailure(ctx, actor, callerTenant, target.PrincipalID, "agent_grant_removed", toDelete)
			return nil, status.Errorf(codes.Internal, "delete tuples: %v", err)
		}
	}

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
		return identity.PrincipalRecord{}, "", errPrincipalUnavailable
	}
	if err != nil {
		s.logger.ErrorContext(ctx, "grants admin: principal lookup failed",
			slog.String("target", targetID),
			slog.String("error", err.Error()),
		)
		return identity.PrincipalRecord{}, "", status.Error(codes.Internal, "principal lookup failed")
	}
	if target.TenantID != callerTenant {
		// Logged, not told. The operator needs to know a cross-tenant write
		// was attempted; the caller must not learn that the id resolved.
		s.logger.WarnContext(ctx, "grants admin: cross-tenant grant write rejected",
			slog.String("caller_tenant", callerTenant),
			slog.String("target_tenant", target.TenantID),
		)
		return identity.PrincipalRecord{}, "", errPrincipalUnavailable
	}
	return target, callerTenant, nil
}

// errPrincipalUnavailable is the single answer for "this principal id is not
// one you can act on", covering both "no such principal anywhere" and "it
// exists, in another tenant".
//
// Separate answers made this RPC an existence oracle (GHSA-9q4v-xwmv-gg26).
// Principal ids are guessable enough to enumerate, and a caller who can tell
// NotFound from PermissionDenied can walk the id space and learn which
// principals exist across the whole install — how many another tenant runs,
// when they appear, whether a specific id is in use — without ever holding a
// grant on one. The information is in the DIFFERENCE between the two replies,
// so the fix is to have only one. It is deliberately shared, not duplicated:
// the two call sites cannot drift apart again.
//
// NotFound is the surviving code because it is the truthful answer to the
// question the caller is entitled to ask ("can I address this principal?") and
// carries no claim about anything outside the caller's tenant. The message
// omits the id: echoing it back changes nothing about what the caller knows,
// but it keeps the two replies byte-identical.
var errPrincipalUnavailable = status.Error(codes.NotFound, "principal not found")

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
		if _, ok := authz.GrantTupleRelation(g.GetRelation()); !ok {
			return status.Errorf(codes.InvalidArgument,
				"grants[%d].relation %q not allowed; must be one of %s",
				i, g.GetRelation(), strings.Join(authz.GrantActions(), ", "))
		}
		if g.GetRelation() == "can_invoke" && targetKind != identitypb.PrincipalKind_PRINCIPAL_KIND_TOOL {
			return status.Errorf(codes.InvalidArgument,
				"grants[%d].relation can_invoke is only valid when target kind is TOOL (got %s); the FGA model excludes agent_principal from plugin.can_invoke",
				i, targetKind.String())
		}
	}
	return nil
}

// grantActor is the subject of the caller, the actor of a grant change.
func grantActor(ctx context.Context) (string, bool) {
	id, err := auth.IdentityFromContext(ctx)
	if err != nil || id.Subject == "" {
		return "", false
	}
	return id.Subject, true
}

// grantAuditEvents builds one audit event per tuple written or deleted.
func grantAuditEvents(actor, tenant, target, action, decision string, tuples []authz.Tuple) []audit.Event {
	out := make([]audit.Event, 0, len(tuples))
	for _, t := range tuples {
		md, _ := json.Marshal(map[string]any{
			"target_principal_id": target,
			"object":              t.Object,
			"relation":            t.Relation,
		})
		out = append(out, audit.Event{
			TenantID:   tenant,
			ActorID:    actor,
			ActorType:  "user",
			Action:     action,
			TargetType: "agent_grant",
			TargetID:   target,
			Decision:   decision,
			Metadata:   md,
		})
	}
	return out
}

// recordGrantAudit writes the audit record of each tuple durably, BEFORE the
// grant change takes effect. The change fails when a record cannot be
// written, so no grant change exists without its record (gibson#676).
// When the writer is nil, the events are structured-logged instead.
func (s *GrantsAdminServer) recordGrantAudit(ctx context.Context, actor, tenant, target, action string, tuples []authz.Tuple) error {
	for _, evt := range grantAuditEvents(actor, tenant, target, action, "allow", tuples) {
		if s.auditWriter == nil {
			s.logger.InfoContext(ctx, "grants admin: audit event (no writer wired)",
				slog.String("action", action),
				slog.String("actor", evt.ActorID),
				slog.String("target", target),
			)
			continue
		}
		if err := s.auditWriter.WriteSync(ctx, evt); err != nil {
			return fmt.Errorf("grants admin: audit record of %s: %w", action, err)
		}
	}
	return nil
}

// recordGrantFailure records that a grant change failed after its audit
// record was written.
func (s *GrantsAdminServer) recordGrantFailure(ctx context.Context, actor, tenant, target, action string, tuples []authz.Tuple) {
	if s.auditWriter != nil {
		for _, evt := range grantAuditEvents(actor, tenant, target, action, "deny", tuples) {
			if err := s.auditWriter.WriteSync(ctx, evt); err != nil {
				s.logger.ErrorContext(ctx, "grants admin: the failure record could not be written",
					slog.String("action", action), slog.String("error", err.Error()))
			}
		}
	}
}
