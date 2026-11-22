// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	"github.com/zeroroot-ai/gibson/internal/platform/componentcatalog"
	"github.com/zeroroot-ai/gibson/internal/platform/loopgrantstore"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// Audit names of a loop grant change. The actor of the record is the admin, so
// the record names the grantor (gibson#1612).
const (
	loopGrantAuditGrant    = "loop_grant.grant"
	loopGrantAuditRevoke   = "loop_grant.revoke"
	loopGrantAuditResource = "loop_grant"
)

var loopGrantAgentPattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

// LoopGrantAudit is the part of the audit logger that the service uses.
type LoopGrantAudit interface {
	Record(ctx context.Context, action, resource, resourceID string, details map[string]any) (string, error)
}

var _ LoopGrantAudit = (*audit.AuditLogger)(nil)

// LoopGrantService serves gibson.tenant.v1.LoopGrantService (gibson#1612). A
// tenant admin gives the members of a catalog agent a loop grant. The harness
// reads the grant at each member tool call.
type LoopGrantService struct {
	tenantv1.UnimplementedLoopGrantServiceServer

	store loopgrantstore.Store
	audit LoopGrantAudit
	// agents finds a catalog agent. The daemon passes componentcatalog.LookupAgent.
	agents func(id string) (componentcatalog.AgentEntry, bool)
	// harnessCalls are the harness calls that a grant may hold.
	harnessCalls []string
}

// NewLoopGrantService returns the service. Each argument is required.
func NewLoopGrantService(
	store loopgrantstore.Store, auditLog LoopGrantAudit,
	agents func(id string) (componentcatalog.AgentEntry, bool), grantableHarnessCalls []string,
) (*LoopGrantService, error) {
	if store == nil || auditLog == nil || agents == nil {
		return nil, errors.New("api: LoopGrantService needs a store, the audit logger and the agent catalog")
	}
	return &LoopGrantService{store: store, audit: auditLog, agents: agents, harnessCalls: grantableHarnessCalls}, nil
}

func loopGrantTenant(ctx context.Context, rpc string) (string, error) {
	tenantID, ok := auth.TenantFromContext(ctx)
	if !ok || tenantID.IsZero() {
		return "", status_grpc.Error(codes.PermissionDenied, rpc+": missing tenant in context")
	}
	return tenantID.String(), nil
}

func loopGrantStatus(rpc string, err error) error {
	var notProvisioned *datapool.NotProvisionedError
	if errors.As(err, &notProvisioned) {
		return status_grpc.Error(codes.NotFound, rpc+": the tenant has no loop grant store")
	}
	return status_grpc.Error(codes.Internal, rpc+": "+err.Error())
}

func loopGrantProto(g loopgrantstore.Grant) *tenantv1.LoopGrant {
	return &tenantv1.LoopGrant{
		Id: g.ID, AgentName: g.AgentName, ToolClasses: g.ToolClasses, HarnessCalls: g.HarnessCalls,
		Grantor: g.Grantor, GrantedAt: timestamppb.New(g.GrantedAt),
	}
}

// GrantLoop gives the members of one catalog agent a loop grant. The manifest of
// the agent is the ceiling: a class that it does not name in loopGrant.classes is
// refused. The audit record is written after the store, with the admin as actor.
func (s *LoopGrantService) GrantLoop(ctx context.Context, req *tenantv1.GrantLoopRequest) (*tenantv1.GrantLoopResponse, error) {
	const rpc = "GrantLoop"
	tenant, err := loopGrantTenant(ctx, rpc)
	if err != nil {
		return nil, err
	}
	id, err := auth.IdentityFromContext(ctx)
	if err != nil || id.Subject == "" {
		return nil, status_grpc.Error(codes.Unauthenticated, rpc+": the grantor has no identity")
	}
	name := req.GetAgentName()
	if !loopGrantAgentPattern.MatchString(name) {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "%s: %q is not a valid agent name", rpc, name)
	}
	agent, ok := s.agents(name)
	if !ok {
		return nil, status_grpc.Errorf(codes.NotFound, "%s: the catalog has no agent %q", rpc, name)
	}
	if len(agent.MemberCommand) == 0 {
		return nil, status_grpc.Errorf(codes.FailedPrecondition, "%s: agent %q cannot run as a member", rpc, name)
	}
	for _, c := range req.GetToolClasses() {
		if !slices.Contains(componentcatalog.ConnectorClasses, c) {
			return nil, status_grpc.Errorf(codes.InvalidArgument, "%s: %q is not a tool class", rpc, c)
		}
		if !slices.Contains(agent.LoopGrantClasses, c) {
			return nil, status_grpc.Errorf(codes.PermissionDenied,
				"%s: the manifest of agent %q does not name the class %q in loopGrant.classes", rpc, name, c)
		}
	}
	for _, c := range req.GetHarnessCalls() {
		if !slices.Contains(s.harnessCalls, c) {
			return nil, status_grpc.Errorf(codes.InvalidArgument, "%s: %q is not a grantable harness call (%s)",
				rpc, c, strings.Join(s.harnessCalls, ", "))
		}
	}
	if len(req.GetToolClasses()) == 0 && len(req.GetHarnessCalls()) == 0 {
		return nil, status_grpc.Error(codes.InvalidArgument, rpc+": a loop grant names a tool class or a harness call")
	}
	g, err := s.store.Put(ctx, tenant, loopgrantstore.Grant{
		ID: uuid.NewString(), AgentName: name, ToolClasses: dedupe(req.GetToolClasses()),
		HarnessCalls: dedupe(req.GetHarnessCalls()), Grantor: id.Subject,
	})
	if err != nil {
		return nil, loopGrantStatus(rpc, err)
	}
	if _, err := s.audit.Record(ctx, loopGrantAuditGrant, loopGrantAuditResource, name, map[string]any{
		"loop_grant_id": g.ID, "grantor": g.Grantor, "tool_classes": g.ToolClasses, "harness_calls": g.HarnessCalls,
	}); err != nil {
		// The grant exists and no record names it. Remove it, so no grant
		// stands without its record.
		if derr := s.store.Delete(ctx, tenant, name); derr != nil {
			return nil, status_grpc.Error(codes.Internal, rpc+": the audit record failed and the grant stays: "+derr.Error())
		}
		return nil, status_grpc.Error(codes.Unavailable, rpc+": the audit record could not be written")
	}
	return &tenantv1.GrantLoopResponse{Grant: loopGrantProto(*g)}, nil
}

// RevokeLoop removes the loop grant of an agent. It is idempotent.
func (s *LoopGrantService) RevokeLoop(ctx context.Context, req *tenantv1.RevokeLoopRequest) (*tenantv1.RevokeLoopResponse, error) {
	const rpc = "RevokeLoop"
	tenant, err := loopGrantTenant(ctx, rpc)
	if err != nil {
		return nil, err
	}
	if _, err := auth.IdentityFromContext(ctx); err != nil {
		return nil, status_grpc.Error(codes.Unauthenticated, rpc+": the caller has no identity")
	}
	name := req.GetAgentName()
	if !loopGrantAgentPattern.MatchString(name) {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "%s: %q is not a valid agent name", rpc, name)
	}
	prior, gerr := s.store.Get(ctx, tenant, name)
	if gerr != nil && !errors.Is(gerr, loopgrantstore.ErrNotFound) {
		return nil, loopGrantStatus(rpc, gerr)
	}
	if err := s.store.Delete(ctx, tenant, name); err != nil {
		return nil, loopGrantStatus(rpc, err)
	}
	details := map[string]any{}
	if prior != nil {
		details["loop_grant_id"] = prior.ID
		details["grantor"] = prior.Grantor
	}
	if _, err := s.audit.Record(ctx, loopGrantAuditRevoke, loopGrantAuditResource, name, details); err != nil {
		return nil, status_grpc.Error(codes.Unavailable, rpc+": the grant is removed and its audit record could not be written")
	}
	return &tenantv1.RevokeLoopResponse{}, nil
}

// ListLoopGrants returns each loop grant of the tenant of the caller.
func (s *LoopGrantService) ListLoopGrants(ctx context.Context, _ *tenantv1.ListLoopGrantsRequest) (*tenantv1.ListLoopGrantsResponse, error) {
	const rpc = "ListLoopGrants"
	tenant, err := loopGrantTenant(ctx, rpc)
	if err != nil {
		return nil, err
	}
	grants, err := s.store.List(ctx, tenant)
	if err != nil {
		return nil, loopGrantStatus(rpc, err)
	}
	out := &tenantv1.ListLoopGrantsResponse{Grants: make([]*tenantv1.LoopGrant, 0, len(grants))}
	for _, g := range grants {
		out.Grants = append(out.Grants, loopGrantProto(g))
	}
	return out, nil
}

func dedupe(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}
