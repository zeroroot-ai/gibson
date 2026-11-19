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
	"github.com/zeroroot-ai/gibson/internal/platform/capabilitygrant"
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

// InboundDefinition is the part of a mission definition that a publication pins.
type InboundDefinition struct {
	// ID is the ID of the definition.
	ID string
	// Hash is the hash of the whole definition: its nodes, its budget and its
	// scope. A change of any part changes the hash.
	Hash string
	// Agents are the names of the agents in its agent nodes.
	Agents []string
}

// InboundMissionSource reads the part of the mission side that publishing and
// starting need. The tenant comes from the context.
type InboundMissionSource interface {
	// Definition returns a definition by name or ID. It returns
	// ErrInboundDefinitionNotFound for a definition that the tenant does not have.
	Definition(ctx context.Context, definitionID string) (InboundDefinition, error)
	// TargetHashes returns the hash of each target, by ID. It returns
	// ErrInboundTargetNotFound when the tenant does not have one of them.
	TargetHashes(ctx context.Context, targetIDs []string) (map[string]string, error)
}

// InboundStaleReason says why a publication no longer matches what the admin
// approved, or "" when it matches. targetIDs are the targets to check. A start
// checks the targets of the mission, and the list checks all approved targets.
// An error is a failure to read, and it is not a mismatch.
func InboundStaleReason(
	ctx context.Context, source InboundMissionSource, e inboundmissionstore.Entry, targetIDs []string,
) (string, error) {
	def, err := source.Definition(ctx, e.DefinitionID)
	switch {
	case errors.Is(err, ErrInboundDefinitionNotFound):
		return "the mission definition was deleted", nil
	case err != nil:
		return "", fmt.Errorf("read the definition: %w", err)
	case def.ID != e.DefinitionID || def.Hash != e.DefinitionHash:
		return "the mission definition changed after it was published", nil
	}
	hashes, err := source.TargetHashes(ctx, targetIDs)
	switch {
	case errors.Is(err, ErrInboundTargetNotFound):
		return "an approved target was deleted", nil
	case err != nil:
		return "", fmt.Errorf("read the targets: %w", err)
	}
	for _, id := range targetIDs {
		if hashes[id] != e.TargetHashes[id] {
			return "an approved target changed after it was published", nil
		}
	}
	return "", nil
}

// InboundIdentities reads the Capability Grant record of an agent identity.
type InboundIdentities interface {
	// ActiveCapabilityNames returns the names of the active grants of the
	// principal. An identity that has not enrolled has none.
	ActiveCapabilityNames(ctx context.Context, tenantID, principalRef string) ([]string, error)
}

// inboundRelationChecks are the relations that an agent identity can hold as the
// user of a stored tuple, each with the object type that a Read needs. OpenFGA
// refuses a Read with a user and no object type. A caller identity holds none of
// them, except the base tuples of inboundBaseTuples.
var inboundRelationChecks = []struct{ relation, objectType string }{
	{"direct_execute", "component:"}, {"direct_configure", "component:"}, {"direct_read", "component:"},
	{"direct_receive_work", "component:"}, {"can_be_invoked_by", "component:"},
	{"can_send", "bank:"}, {"opened_by", "job:"}, {"scorer", "job:"}, {"granted_agent", "agent_skill:"},
	{"member", "tenant:"}, {"member", "team:"},
}

// inboundBaseTuples are the tuples with the principal as user that CreateAgentIdentity
// writes for every agent identity: tenant membership, and the client grant of
// capabilitygrant.ClientCapabilityGrants (execute on the system backplane). The
// others written there have the principal as object (owner, belongs_to). A caller
// identity may hold these and nothing else.
func inboundBaseTuples(principal, tenant string) []authz.Tuple {
	return append(
		[]authz.Tuple{{User: principal, Relation: "member", Object: "tenant:" + tenant}},
		capabilitygrant.ClientCapabilityGrants(principal, "agent_principal")...)
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

	store  inboundmissionstore.Store
	source InboundMissionSource
	fga    InboundMissionFGA
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

func inboundEntryProto(e inboundmissionstore.Entry, staleReason string) *tenantv1.InboundMissionEntry {
	return &tenantv1.InboundMissionEntry{
		Agent: e.Agent, MissionDefinitionId: e.DefinitionID, TargetIds: e.TargetIDs,
		PublishedBy: e.PublishedBy, CreatedAt: timestamppb.New(e.CreatedAt),
		Stale: staleReason != "", StaleReason: staleReason, MaxActiveMissions: e.MaxActive,
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
	if req.GetMaxActiveMissions() < 1 {
		return nil, status_grpc.Errorf(codes.InvalidArgument,
			"%s: max_active_missions is required. Set the most missions that may run or wait at one time", rpc)
	}
	targets := slices.Clone(req.GetTargetIds())
	if len(targets) == 0 || len(targets) > maxInboundTargets {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "%s: give between 1 and %d targets", rpc, maxInboundTargets)
	}
	slices.Sort(targets)
	if len(slices.Compact(slices.Clone(targets))) != len(targets) {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "%s: a target appears two times", rpc)
	}
	def, err := s.source.Definition(ctx, req.GetMissionDefinitionId())
	switch {
	case errors.Is(err, ErrInboundDefinitionNotFound):
		return nil, status_grpc.Error(codes.NotFound, rpc+": "+err.Error())
	case err != nil:
		return nil, status_grpc.Error(codes.Internal, fmt.Sprintf("%s: read the definition: %v", rpc, err))
	case def.ID == "" || def.Hash == "":
		return nil, status_grpc.Error(codes.FailedPrecondition, rpc+": the definition has no ID, so it cannot be pinned")
	}
	if !slices.Contains(def.Agents, req.GetAgent()) {
		return nil, status_grpc.Errorf(codes.InvalidArgument,
			"%s: the definition has no agent node for the agent %q", rpc, req.GetAgent())
	}
	hashes, err := s.source.TargetHashes(ctx, targets)
	switch {
	case errors.Is(err, ErrInboundTargetNotFound):
		return nil, status_grpc.Error(codes.NotFound, rpc+": "+err.Error())
	case err != nil:
		return nil, status_grpc.Error(codes.Internal, fmt.Sprintf("%s: read the targets: %v", rpc, err))
	}
	// A new publication of a name starts with no grant. A grant that an earlier
	// publication of the name left behind, for example after a failed cleanup, is
	// deleted here, so it never applies to this publication.
	if _, gerr := s.store.Get(ctx, tenant, req.GetAgent()); errors.Is(gerr, inboundmissionstore.ErrNotFound) {
		stale, rerr := s.grantTuples(ctx, object)
		if rerr != nil {
			return nil, status_grpc.Error(codes.Internal, rpc+": "+rerr.Error())
		}
		if len(stale) > 0 {
			if derr := s.fga.Delete(ctx, stale); derr != nil {
				return nil, status_grpc.Error(codes.Internal, fmt.Sprintf("%s: delete the stale grants: %v", rpc, derr))
			}
		}
	}
	publishedBy := ""
	if id, idErr := auth.IdentityFromContext(ctx); idErr == nil {
		publishedBy = id.Subject
	}
	entry, err := s.store.Publish(ctx, tenant, inboundmissionstore.Entry{
		Agent: req.GetAgent(), DefinitionID: def.ID, DefinitionHash: def.Hash, TargetIDs: targets, TargetHashes: hashes, MaxActive: req.GetMaxActiveMissions(),
		PublishedBy: publishedBy,
	})
	if err != nil {
		return nil, inboundStatus(rpc, err)
	}
	if err := s.fga.Write(ctx, []authz.Tuple{{User: "tenant:" + tenant, Relation: "owner", Object: object}}); err != nil {
		return nil, status_grpc.Error(codes.Internal, fmt.Sprintf("%s: write the owner tuple: %v", rpc, err))
	}
	return &tenantv1.PublishInboundMissionResponse{Entry: inboundEntryProto(*entry, "")}, nil
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
		reason, rerr := InboundStaleReason(ctx, s.source, e, e.TargetIDs)
		if rerr != nil {
			return nil, status_grpc.Error(codes.Internal, fmt.Sprintf("%s: check %s: %v", rpc, e.Agent, rerr))
		}
		out.Entries = append(out.Entries, inboundEntryProto(e, reason))
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

// grantTuples reads every stored granted_caller tuple of one object. ReadTuples
// pages through the tuples, so none is left out.
func (s *InboundMissionService) grantTuples(ctx context.Context, object string) ([]authz.Tuple, error) {
	reader, ok := any(s.fga).(authz.TupleReader)
	if !ok {
		return nil, errors.New("the authorizer cannot read stored tuples")
	}
	tuples, err := reader.ReadTuples(ctx, "", "granted_caller", object)
	if err != nil {
		return nil, fmt.Errorf("read the grants of %s: %w", object, err)
	}
	return tuples, nil
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
	grants, err := s.grantTuples(ctx, object)
	if err != nil {
		return nil, status_grpc.Error(codes.Internal, rpc+": "+err.Error())
	}
	tuples := make([]authz.Tuple, 0, 1+len(grants))
	tuples = append(tuples, authz.Tuple{User: "tenant:" + tenant, Relation: "owner", Object: object})
	if err := s.fga.Delete(ctx, append(tuples, grants...)); err != nil {
		return nil, status_grpc.Error(codes.Internal, fmt.Sprintf("%s: delete the tuples: %v", rpc, err))
	}
	if err := s.store.Delete(ctx, tenant, req.GetAgent()); err != nil {
		return nil, inboundStatus(rpc, err)
	}
	// A grant that a parallel call wrote after the first read is deleted now. The
	// record is gone, so no new grant is written after this read.
	late, err := s.grantTuples(ctx, object)
	if err != nil {
		return nil, status_grpc.Error(codes.Internal, rpc+": "+err.Error())
	}
	if len(late) > 0 {
		if err := s.fga.Delete(ctx, late); err != nil {
			return nil, status_grpc.Error(codes.Internal, fmt.Sprintf("%s: delete the late grants: %v", rpc, err))
		}
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
	// The check of the sole grant and the write are one step for the identity. Two
	// parallel grants of one identity run one after the other, so the second one
	// sees the first and is refused.
	err = s.store.WithIdentityLock(ctx, tenant, subject, func() error {
		return s.grantLocked(ctx, tenant, req.GetAgent(), subject, object)
	})
	if err != nil {
		return nil, grantStatus(rpc, err)
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
	ids := append(make([]string, 0, len(users)), users...)
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
	base := inboundBaseTuples(subject, tenant)
	for _, check := range inboundRelationChecks {
		held, err := reader.ReadTuples(ctx, subject, check.relation, check.objectType)
		if err != nil {
			return status_grpc.Error(codes.Internal, fmt.Sprintf("%s: read the relations: %v", rpc, err))
		}
		for _, t := range held {
			if !slices.Contains(base, t) {
				return status_grpc.Errorf(codes.FailedPrecondition,
					"%s: the identity holds the relation %s on %s. A caller identity has only the grant to a published definition",
					rpc, t.Relation, t.Object)
			}
		}
	}
	return nil
}

// grantStatus passes a gRPC status of the locked step through, and it turns another
// error into Internal.
func grantStatus(rpc string, err error) error {
	if _, ok := status_grpc.FromError(err); ok {
		return err
	}
	if errors.Is(err, inboundmissionstore.ErrNotFound) {
		return inboundStatus(rpc, err)
	}
	return status_grpc.Error(codes.Internal, rpc+": "+err.Error())
}

// grantLocked checks the sole grant and writes the grant. The caller holds the lock
// of the identity.
func (s *InboundMissionService) grantLocked(ctx context.Context, tenant, agent, subject, object string) error {
	const rpc = "GrantInboundCaller"
	if err := s.requireSoleGrant(ctx, tenant, subject, object); err != nil {
		return err
	}
	grant := authz.Tuple{User: subject, Relation: "granted_caller", Object: object}
	if err := s.fga.Write(ctx, []authz.Tuple{grant}); err != nil {
		return status_grpc.Error(codes.Internal, fmt.Sprintf("%s: write the grant: %v", rpc, err))
	}
	// The record may have gone between the first check and the write. A grant to a
	// publication that is gone would come back with the next publish of the name, so
	// the grant is deleted and the call fails.
	if _, err := s.store.Get(ctx, tenant, agent); err != nil {
		if derr := s.fga.Delete(ctx, []authz.Tuple{grant}); derr != nil {
			return status_grpc.Error(codes.Internal, fmt.Sprintf("%s: delete the orphan grant: %v", rpc, derr))
		}
		return inboundStatus(rpc, err)
	}
	return nil
}
