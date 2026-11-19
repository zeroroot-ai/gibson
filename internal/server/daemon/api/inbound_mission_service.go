// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/capname"
	"github.com/zeroroot-ai/gibson/internal/platform/inboundmissionstore"
	"github.com/zeroroot-ai/gibson/internal/platform/pagetoken"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

var (
	// ErrInboundDefinitionNotFound marks a mission definition that the tenant
	// does not have.
	ErrInboundDefinitionNotFound = errors.New("the mission definition does not exist")
	// ErrInboundTargetNotFound marks a target that the tenant does not have.
	ErrInboundTargetNotFound = errors.New("the target does not exist")
)

// maxInboundTargets bounds the approved targets of one published definition.
const maxInboundTargets = 100

// InboundMissionSource reads the part of the mission side that publishing
// needs. The tenant comes from the context.
type InboundMissionSource interface {
	// DefinitionAgents returns the names of the agents in the agent nodes of a
	// mission definition. It returns ErrInboundDefinitionNotFound for a
	// definition that the tenant does not have.
	DefinitionAgents(ctx context.Context, definitionID string) ([]string, error)
	// CheckTargets returns ErrInboundTargetNotFound for a target that the tenant
	// does not have.
	CheckTargets(ctx context.Context, targetIDs []string) error
}

// InboundIdentities reads the Capability Grant record of an agent identity.
type InboundIdentities interface {
	// ActiveCapabilityNames returns the names of the active grants of the
	// principal. An identity that has not enrolled has none.
	ActiveCapabilityNames(ctx context.Context, tenantID, principalRef string) ([]string, error)
}

// inboundOtherRelations are the relations that an agent identity can hold as the
// user of a tuple, other than the grant to a published definition. A caller
// identity holds none of them.
var inboundOtherRelations = []string{
	"direct_execute", "direct_configure", "direct_read", "direct_receive_work", "can_send",
	"opened_by", "scorer", "granted_agent",
}

// InboundMissionFGA is the part of authz.Authorizer that the service uses.
type InboundMissionFGA interface {
	Check(ctx context.Context, user, relation, object string) (bool, error)
	Write(ctx context.Context, tuples []authz.Tuple) error
	Delete(ctx context.Context, tuples []authz.Tuple) error
	ListUsersOfType(ctx context.Context, objectType, object, relation, userType string) ([]string, error)
}

// InboundMissionService serves gibson.tenant.v1.InboundMissionService (epic
// gibson#1367, gibson#1408). It keeps the record of each published definition
// in the database of the tenant, and the owner tuple and the caller grants in
// FGA.
type InboundMissionService struct {
	tenantv1.UnimplementedInboundMissionServiceServer

	store    inboundmissionstore.Store
	source   InboundMissionSource
	fga      InboundMissionFGA
	// identities reads the Capability Grant record of a caller identity.
	identities InboundIdentities
	pageKeys   *pagetoken.Keys
}

// NewInboundMissionService returns the service. Each argument is required.
func NewInboundMissionService(
	store inboundmissionstore.Store, source InboundMissionSource, fga InboundMissionFGA, identities InboundIdentities,
	pageKeys *pagetoken.Keys,
) (*InboundMissionService, error) {
	if store == nil || source == nil || fga == nil || identities == nil || pageKeys == nil {
		return nil, errors.New("api: InboundMissionService needs a store, a mission source, the authorizer, " +
			"the identity record and the page keys")
	}
	return &InboundMissionService{store: store, source: source, fga: fga, identities: identities, pageKeys: pageKeys}, nil
}

func inboundTenant(ctx context.Context, rpc string) (string, error) {
	tenantID, ok := auth.TenantFromContext(ctx)
	if !ok || tenantID.IsZero() {
		return "", status_grpc.Error(codes.PermissionDenied, rpc+": missing tenant in context")
	}
	return tenantID.String(), nil
}

// inboundObject checks the agent name and returns the FGA object of it. The name
// is a DNS label, because it is a segment of a URL path.
func inboundObject(rpc, tenant, agent string) (string, error) {
	if !outsideAgentNamePattern.MatchString(agent) {
		return "", status_grpc.Errorf(codes.InvalidArgument, "%s: %q is not a valid agent name (a DNS label)", rpc, agent)
	}
	object, err := authz.PublishedMissionObject(tenant, agent)
	if err != nil {
		return "", status_grpc.Error(codes.InvalidArgument, rpc+": "+err.Error())
	}
	return object, nil
}

// inboundIdentity checks the id of an agent identity and returns it. The id is the
// typed principal id that CreateAgentIdentity returns, "agent_principal:<id>", and
// it is also the FGA user. Only an agent identity can be a caller, and the account
// part holds no separator.
func inboundIdentity(rpc, id string) (string, error) {
	id = strings.TrimSpace(id)
	account, fgaType, err := parsePrincipalID(id)
	if err != nil || fgaType != "agent_principal" || account == "" || strings.ContainsAny(account, ":#/ ") {
		return "", status_grpc.Errorf(codes.InvalidArgument,
			"%s: the identity id must be an agent principal id, agent_principal:<id>", rpc)
	}
	return id, nil
}

func inboundStatus(rpc string, err error) error {
	switch {
	case errors.Is(err, inboundmissionstore.ErrNotFound):
		return status_grpc.Error(codes.NotFound, rpc+": "+err.Error())
	case errors.Is(err, inboundmissionstore.ErrConflict):
		return status_grpc.Error(codes.AlreadyExists, rpc+": "+err.Error()+": unpublish it first")
	default:
		return status_grpc.Error(codes.Internal, rpc+": "+err.Error())
	}
}

func inboundEntryProto(e inboundmissionstore.Entry) *tenantv1.InboundMissionEntry {
	return &tenantv1.InboundMissionEntry{
		Agent: e.Agent, MissionDefinitionId: e.DefinitionID, TargetIds: e.TargetIDs,
		PublishedBy: e.PublishedBy, CreatedAt: timestamppb.New(e.CreatedAt),
	}
}

// PublishInboundMission saves the mark and writes the owner tuple of the object.
// The tuple goes after the store, so a retry after a failure is safe.
func (s *InboundMissionService) PublishInboundMission(
	ctx context.Context, req *tenantv1.PublishInboundMissionRequest,
) (*tenantv1.PublishInboundMissionResponse, error) {
	const rpc = "PublishInboundMission"
	tenant, err := inboundTenant(ctx, rpc)
	if err != nil {
		return nil, err
	}
	object, err := inboundObject(rpc, tenant, req.GetAgent())
	if err != nil {
		return nil, err
	}
	targets := slices.Clone(req.GetTargetIds())
	if len(targets) == 0 || len(targets) > maxInboundTargets {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "%s: give between 1 and %d targets", rpc, maxInboundTargets)
	}
	slices.Sort(targets)
	if len(slices.Compact(slices.Clone(targets))) != len(targets) {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "%s: a target appears two times", rpc)
	}
	agents, err := s.source.DefinitionAgents(ctx, req.GetMissionDefinitionId())
	switch {
	case errors.Is(err, ErrInboundDefinitionNotFound):
		return nil, status_grpc.Error(codes.NotFound, rpc+": "+err.Error())
	case err != nil:
		return nil, status_grpc.Error(codes.Internal, fmt.Sprintf("%s: read the definition: %v", rpc, err))
	}
	if !slices.Contains(agents, req.GetAgent()) {
		return nil, status_grpc.Errorf(codes.InvalidArgument,
			"%s: the definition has no agent node for the agent %q", rpc, req.GetAgent())
	}
	switch err := s.source.CheckTargets(ctx, targets); {
	case errors.Is(err, ErrInboundTargetNotFound):
		return nil, status_grpc.Error(codes.NotFound, rpc+": "+err.Error())
	case err != nil:
		return nil, status_grpc.Error(codes.Internal, fmt.Sprintf("%s: read the targets: %v", rpc, err))
	}
	publishedBy := ""
	if id, idErr := auth.IdentityFromContext(ctx); idErr == nil {
		publishedBy = id.Subject
	}
	entry, err := s.store.Publish(ctx, tenant, inboundmissionstore.Entry{
		Agent: req.GetAgent(), DefinitionID: req.GetMissionDefinitionId(), TargetIDs: targets, PublishedBy: publishedBy,
	})
	if err != nil {
		return nil, inboundStatus(rpc, err)
	}
	if err := s.fga.Write(ctx, []authz.Tuple{{User: "tenant:" + tenant, Relation: "owner", Object: object}}); err != nil {
		return nil, status_grpc.Error(codes.Internal, fmt.Sprintf("%s: write the owner tuple: %v", rpc, err))
	}
	return &tenantv1.PublishInboundMissionResponse{Entry: inboundEntryProto(*entry)}, nil
}

// ListInboundMissions returns one page of the published definitions of the
// tenant. The store pages by agent with a keyset.
func (s *InboundMissionService) ListInboundMissions(
	ctx context.Context, req *tenantv1.ListInboundMissionsRequest,
) (*tenantv1.ListInboundMissionsResponse, error) {
	const rpc = "ListInboundMissions"
	tenant, err := inboundTenant(ctx, rpc)
	if err != nil {
		return nil, err
	}
	page, err := pageOf(s.pageKeys, "tenant-inbound-missions", req.GetPageSize(), req.GetPageToken(), tenant)
	if err != nil {
		return nil, err
	}
	entries, next, err := keysetPage(page, func(after string, hasAfter bool, limit int) ([]inboundmissionstore.Entry, error) {
		return s.store.ListPage(ctx, tenant, after, hasAfter, limit)
	}, func(e inboundmissionstore.Entry) string { return e.Agent })
	if err != nil {
		return nil, inboundStatus(rpc, err)
	}
	out := &tenantv1.ListInboundMissionsResponse{
		Entries: make([]*tenantv1.InboundMissionEntry, 0, len(entries)), NextPageToken: next,
	}
	for _, e := range entries {
		out.Entries = append(out.Entries, inboundEntryProto(e))
	}
	return out, nil
}

func (s *InboundMissionService) inboundCallers(ctx context.Context, object string) ([]string, error) {
	users, err := s.fga.ListUsersOfType(ctx, "published_mission", object, "granted_caller", "agent_principal")
	if err != nil {
		return nil, fmt.Errorf("list the grants: %w", err)
	}
	return users, nil
}

// UnpublishInboundMission removes the mark, the caller grants and the owner
// tuple. A grant that stayed would come back if the tenant published the same
// agent name again.
func (s *InboundMissionService) UnpublishInboundMission(
	ctx context.Context, req *tenantv1.UnpublishInboundMissionRequest,
) (*tenantv1.UnpublishInboundMissionResponse, error) {
	const rpc = "UnpublishInboundMission"
	tenant, err := inboundTenant(ctx, rpc)
	if err != nil {
		return nil, err
	}
	object, err := inboundObject(rpc, tenant, req.GetAgent())
	if err != nil {
		return nil, err
	}
	if _, gerr := s.store.Get(ctx, tenant, req.GetAgent()); gerr != nil {
		return nil, inboundStatus(rpc, gerr)
	}
	// The tuples go first. A failure here leaves the record in place, and the
	// caller can retry.
	tuples := []authz.Tuple{{User: "tenant:" + tenant, Relation: "owner", Object: object}}
	users, err := s.inboundCallers(ctx, object)
	if err != nil {
		return nil, status_grpc.Error(codes.Internal, rpc+": "+err.Error())
	}
	for _, u := range users {
		tuples = append(tuples, authz.Tuple{User: u, Relation: "granted_caller", Object: object})
	}
	if err := s.fga.Delete(ctx, tuples); err != nil {
		return nil, status_grpc.Error(codes.Internal, fmt.Sprintf("%s: delete the tuples: %v", rpc, err))
	}
	if err := s.store.Delete(ctx, tenant, req.GetAgent()); err != nil {
		return nil, inboundStatus(rpc, err)
	}
	return &tenantv1.UnpublishInboundMissionResponse{}, nil
}

// GrantInboundCaller lets one agent identity of the tenant call a published
// definition. It refuses an identity that is not of the tenant of the caller.
// Without that check an admin could name an identity of another tenant.
func (s *InboundMissionService) GrantInboundCaller(
	ctx context.Context, req *tenantv1.GrantInboundCallerRequest,
) (*tenantv1.GrantInboundCallerResponse, error) {
	const rpc = "GrantInboundCaller"
	tenant, err := inboundTenant(ctx, rpc)
	if err != nil {
		return nil, err
	}
	object, err := inboundObject(rpc, tenant, req.GetAgent())
	if err != nil {
		return nil, err
	}
	subject, err := inboundIdentity(rpc, req.GetIdentityId())
	if err != nil {
		return nil, err
	}
	owned, err := s.fga.Check(ctx, "tenant:"+tenant, "belongs_to", subject)
	if err != nil {
		return nil, status_grpc.Error(codes.Internal, fmt.Sprintf("%s: check the identity: %v", rpc, err))
	}
	if !owned {
		return nil, status_grpc.Errorf(codes.NotFound, "%s: %s is not of this tenant", rpc, subject)
	}
	// A grant on an agent that is not published is refused.
	if _, err := s.store.Get(ctx, tenant, req.GetAgent()); err != nil {
		return nil, inboundStatus(rpc, err)
	}
	if err := s.requireSoleGrant(ctx, tenant, subject, object); err != nil {
		return nil, err
	}
	if err := s.fga.Write(ctx, []authz.Tuple{{User: subject, Relation: "granted_caller", Object: object}}); err != nil {
		return nil, status_grpc.Error(codes.Internal, fmt.Sprintf("%s: write the grant: %v", rpc, err))
	}
	return &tenantv1.GrantInboundCallerResponse{}, nil
}

// RevokeInboundCaller removes the grant of an identity. It does not check that
// the identity exists, so it can remove the grant of an identity that is gone.
func (s *InboundMissionService) RevokeInboundCaller(
	ctx context.Context, req *tenantv1.RevokeInboundCallerRequest,
) (*tenantv1.RevokeInboundCallerResponse, error) {
	const rpc = "RevokeInboundCaller"
	tenant, err := inboundTenant(ctx, rpc)
	if err != nil {
		return nil, err
	}
	object, err := inboundObject(rpc, tenant, req.GetAgent())
	if err != nil {
		return nil, err
	}
	subject, err := inboundIdentity(rpc, req.GetIdentityId())
	if err != nil {
		return nil, err
	}
	if err := s.fga.Delete(ctx, []authz.Tuple{{User: subject, Relation: "granted_caller", Object: object}}); err != nil {
		return nil, status_grpc.Error(codes.Internal, fmt.Sprintf("%s: delete the grant: %v", rpc, err))
	}
	return &tenantv1.RevokeInboundCallerResponse{}, nil
}

// ListInboundCallers returns one page of the identities that may call one
// published definition. The FGA client returns the users of a relation whole, so
// the page is cut in memory over a stable sort.
func (s *InboundMissionService) ListInboundCallers(
	ctx context.Context, req *tenantv1.ListInboundCallersRequest,
) (*tenantv1.ListInboundCallersResponse, error) {
	const rpc = "ListInboundCallers"
	tenant, err := inboundTenant(ctx, rpc)
	if err != nil {
		return nil, err
	}
	object, err := inboundObject(rpc, tenant, req.GetAgent())
	if err != nil {
		return nil, err
	}
	page, err := pageOf(s.pageKeys, "tenant-inbound-callers", req.GetPageSize(), req.GetPageToken(), tenant,
		req.GetAgent())
	if err != nil {
		return nil, err
	}
	if _, err := s.store.Get(ctx, tenant, req.GetAgent()); err != nil {
		return nil, inboundStatus(rpc, err)
	}
	users, err := s.inboundCallers(ctx, object)
	if err != nil {
		return nil, status_grpc.Error(codes.Internal, rpc+": "+err.Error())
	}
	ids := make([]string, 0, len(users))
	for _, u := range users {
		ids = append(ids, u)
	}
	// The key of a grant is its identity id, which is unique.
	ids, next := pagetoken.Page(page, ids, func(id string) string { return id })
	return &tenantv1.ListInboundCallersResponse{IdentityIds: ids, NextPageToken: next}, nil
}

// inboundGrantTuples reads every stored grant of one principal to a published
// mission definition. ReadTuples pages through the tuples, so no grant is left out.
func inboundGrantTuples(ctx context.Context, az any, principalRef string) ([]authz.Tuple, error) {
	reader, ok := az.(authz.TupleReader)
	if !ok {
		return nil, errors.New("the authorizer cannot read stored tuples")
	}
	tuples, err := reader.ReadTuples(ctx, principalRef, "granted_caller", "published_mission:")
	if err != nil {
		return nil, fmt.Errorf("read the inbound grants of %s: %w", principalRef, err)
	}
	return tuples, nil
}

// requireSoleGrant refuses an identity that is not a caller identity. A caller
// identity has the one ceiling mission:originate, and it holds no other grant and
// no other relation. The one grant it may hold is the grant to this definition.
// An identity that has not enrolled has no Capability Grant record yet, and
// ext-authz refuses a call of an identity with another session bit.
func (s *InboundMissionService) requireSoleGrant(ctx context.Context, tenant, subject, object string) error {
	const rpc = "GrantInboundCaller"
	names, err := s.identities.ActiveCapabilityNames(ctx, tenant, subject)
	if err != nil {
		return status_grpc.Error(codes.Internal, fmt.Sprintf("%s: read the capability grants: %v", rpc, err))
	}
	for _, n := range names {
		if n != capname.MissionOriginate {
			return status_grpc.Errorf(codes.FailedPrecondition,
				"%s: the identity holds the capability %q. A caller identity has only mission:originate", rpc, n)
		}
	}
	reader, ok := any(s.fga).(authz.TupleReader)
	if !ok {
		return status_grpc.Error(codes.Internal, rpc+": the authorizer cannot read stored tuples")
	}
	others, err := reader.ReadTuples(ctx, subject, "granted_caller", "published_mission:")
	if err != nil {
		return status_grpc.Error(codes.Internal, fmt.Sprintf("%s: read the grants: %v", rpc, err))
	}
	for _, t := range others {
		if t.Object != object {
			return status_grpc.Errorf(codes.FailedPrecondition,
				"%s: the identity already holds the grant to %s. A caller identity has one grant", rpc, t.Object)
		}
	}
	for _, rel := range inboundOtherRelations {
		held, err := reader.ReadTuples(ctx, subject, rel, "")
		if err != nil {
			return status_grpc.Error(codes.Internal, fmt.Sprintf("%s: read the relations: %v", rpc, err))
		}
		if len(held) > 0 {
			return status_grpc.Errorf(codes.FailedPrecondition,
				"%s: the identity holds the relation %s. A caller identity has only the grant to a published definition", rpc, rel)
		}
	}
	return nil
}
