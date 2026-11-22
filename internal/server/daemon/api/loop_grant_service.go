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
	"github.com/zeroroot-ai/gibson/internal/platform/pagetoken"
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

// loopGrantMemberPattern is the shape of a bank member id. It is a conservative
// check of the input. The bank store decides if the member exists.
var loopGrantMemberPattern = regexp.MustCompile(`^[A-Za-z0-9][-A-Za-z0-9_.]{0,127}$`)

// ErrLoopMemberNotFound is what a LoopGrantMembers answers for a member that the
// tenant does not have.
var ErrLoopMemberNotFound = errors.New("api: the tenant has no such bank member")

// LoopGrantMembers reads the agent of a bank member of a tenant. The daemon backs
// it with the bank store. The store reads the database of the tenant, so a member
// of another tenant is not found.
type LoopGrantMembers interface {
	AgentOfMember(ctx context.Context, tenant, memberID string) (agentName string, err error)
}

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
	// members reads the agent of a bank member.
	members LoopGrantMembers
	// agents finds a catalog agent. The daemon passes componentcatalog.LookupAgent.
	agents func(id string) (componentcatalog.AgentEntry, bool)
	// harnessCalls are the harness calls that a grant may hold.
	harnessCalls []string
	// pageKeys derives the signer of the page tokens of ListLoopGrants.
	pageKeys *pagetoken.Keys
}

// NewLoopGrantService returns the service. Each argument is required.
func NewLoopGrantService(
	store loopgrantstore.Store, members LoopGrantMembers, auditLog LoopGrantAudit,
	agents func(id string) (componentcatalog.AgentEntry, bool), grantableHarnessCalls []string, pageKeys *pagetoken.Keys,
) (*LoopGrantService, error) {
	if store == nil || members == nil || auditLog == nil || agents == nil || pageKeys == nil {
		return nil, errors.New(
			"api: LoopGrantService needs a store, the bank members, the audit logger, the agent catalog and the page keys")
	}
	return &LoopGrantService{
		store: store, members: members, audit: auditLog, agents: agents, harnessCalls: grantableHarnessCalls, pageKeys: pageKeys,
	}, nil
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
		Id: g.ID, MemberId: g.MemberID, AgentName: g.AgentName, ToolClasses: g.ToolClasses, HarnessCalls: g.HarnessCalls,
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
	memberID := req.GetMemberId()
	if !loopGrantMemberPattern.MatchString(memberID) {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "%s: %q is not a valid member id", rpc, memberID)
	}
	name, err := s.members.AgentOfMember(ctx, tenant, memberID)
	if errors.Is(err, ErrLoopMemberNotFound) {
		return nil, status_grpc.Errorf(codes.NotFound, "%s: the tenant has no bank member %q", rpc, memberID)
	}
	if err != nil {
		return nil, loopGrantStatus(rpc, err)
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
	// The prior grant of the member, so a failed audit write restores it and
	// does not delete a grant that worked.
	prior, perr := s.store.Get(ctx, tenant, memberID)
	if perr != nil && !errors.Is(perr, loopgrantstore.ErrNotFound) {
		return nil, loopGrantStatus(rpc, perr)
	}
	g, err := s.store.Put(ctx, tenant, loopgrantstore.Grant{
		ID: uuid.NewString(), MemberID: memberID, AgentName: name, ToolClasses: dedupe(req.GetToolClasses()),
		HarnessCalls: dedupe(req.GetHarnessCalls()), Grantor: id.Subject,
	})
	if err != nil {
		return nil, loopGrantStatus(rpc, err)
	}
	if _, err := s.audit.Record(ctx, loopGrantAuditGrant, loopGrantAuditResource, memberID, map[string]any{
		"loop_grant_id": g.ID, "grantor": g.Grantor, "agent": name,
		"tool_classes": g.ToolClasses, "harness_calls": g.HarnessCalls,
	}); err != nil {
		// No grant stands without its record. The prior grant comes back, or the
		// row goes when there was none.
		var rerr error
		if prior != nil {
			_, rerr = s.store.Put(ctx, tenant, *prior)
		} else {
			rerr = s.store.Delete(ctx, tenant, memberID)
		}
		if rerr != nil {
			return nil, status_grpc.Error(codes.Internal, rpc+": the audit record failed and the grant could not be restored: "+rerr.Error())
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
	if id, err := auth.IdentityFromContext(ctx); err != nil || id.Subject == "" {
		return nil, status_grpc.Error(codes.Unauthenticated, rpc+": the caller has no identity")
	}
	memberID := req.GetMemberId()
	if !loopGrantMemberPattern.MatchString(memberID) {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "%s: %q is not a valid member id", rpc, memberID)
	}
	prior, gerr := s.store.Get(ctx, tenant, memberID)
	if gerr != nil && !errors.Is(gerr, loopgrantstore.ErrNotFound) {
		return nil, loopGrantStatus(rpc, gerr)
	}
	if err := s.store.Delete(ctx, tenant, memberID); err != nil {
		return nil, loopGrantStatus(rpc, err)
	}
	details := map[string]any{}
	if prior != nil {
		details["loop_grant_id"] = prior.ID
		details["grantor"] = prior.Grantor
	}
	if _, err := s.audit.Record(ctx, loopGrantAuditRevoke, loopGrantAuditResource, memberID, details); err != nil {
		return nil, status_grpc.Error(codes.Unavailable, rpc+": the grant is removed and its audit record could not be written")
	}
	return &tenantv1.RevokeLoopResponse{}, nil
}

// ListLoopGrants returns one page of the loop grants of the tenant of the
// caller. The store pages by agent name with a keyset.
func (s *LoopGrantService) ListLoopGrants(ctx context.Context, req *tenantv1.ListLoopGrantsRequest) (*tenantv1.ListLoopGrantsResponse, error) {
	const rpc = "ListLoopGrants"
	tenant, err := loopGrantTenant(ctx, rpc)
	if err != nil {
		return nil, err
	}
	page, err := pageOf(s.pageKeys, "tenant-loop-grants", req.GetPageSize(), req.GetPageToken(), tenant)
	if err != nil {
		return nil, err
	}
	after, hasAfter := page.After()
	// The store reads one grant more than the page holds. That extra grant tells
	// whether a next page exists.
	fetched, err := s.store.ListPage(ctx, tenant, after, hasAfter, page.Limit()+1)
	if err != nil {
		return nil, loopGrantStatus(rpc, err)
	}
	grants, hasMore := splitPage(fetched, page.Limit())
	resp := &tenantv1.ListLoopGrantsResponse{Grants: make([]*tenantv1.LoopGrant, len(grants))}
	for i := range grants {
		resp.Grants[i] = loopGrantProto(grants[i])
	}
	if hasMore {
		resp.NextPageToken = page.Token(grants[len(grants)-1].MemberID, true)
	}
	return resp, nil
}

// splitPage cuts the extra grant that the store read, and reports whether it was
// there.
func splitPage(fetched []loopgrantstore.Grant, limit int) (page []loopgrantstore.Grant, hasMore bool) {
	if len(fetched) <= limit {
		return fetched, false
	}
	return fetched[:limit], true
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
