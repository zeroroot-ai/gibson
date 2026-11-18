// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/zeroroot-ai/gibson/internal/engine/agentskill"
	"github.com/zeroroot-ai/gibson/internal/engine/toolid"
	"github.com/zeroroot-ai/gibson/internal/platform/agentskillstore"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// AgentSkillPuller reads the image that a digest reference names and returns
// the validated folder. In production it is agentskill.Pull with the keychain
// of the daemon process. A test supplies its own.
type AgentSkillPuller func(ctx context.Context, reference, folderName string) (*agentskill.Pulled, error)

// AgentSkillFGA is the part of authz.Authorizer that the service uses.
type AgentSkillFGA interface {
	Check(ctx context.Context, user, relation, object string) (bool, error)
	Write(ctx context.Context, tuples []authz.Tuple) error
	Delete(ctx context.Context, tuples []authz.Tuple) error
	ListUsersOfType(ctx context.Context, objectType, object, relation, userType string) ([]string, error)
}

// AgentSkillService serves gibson.tenant.v1.AgentSkillService (epic
// gibson#1364). The daemon has no write path to a registry. The publisher
// pushes the image, and this service pulls it by digest.
type AgentSkillService struct {
	tenantv1.UnimplementedAgentSkillServiceServer

	store agentskillstore.Store
	pull  AgentSkillPuller
	fga   AgentSkillFGA
}

// NewAgentSkillService returns the service. Each argument is required.
func NewAgentSkillService(
	store agentskillstore.Store, pull AgentSkillPuller, fga AgentSkillFGA,
) (*AgentSkillService, error) {
	if store == nil || pull == nil || fga == nil {
		return nil, errors.New("api: AgentSkillService needs a store, a puller and the authorizer")
	}
	return &AgentSkillService{store: store, pull: pull, fga: fga}, nil
}

// agentSkillTenant returns the tenant of the caller.
func agentSkillTenant(ctx context.Context, rpc string) (string, error) {
	tenantID, ok := auth.TenantFromContext(ctx)
	if !ok || tenantID.IsZero() {
		return "", status_grpc.Error(codes.PermissionDenied, rpc+": missing tenant in context")
	}
	return tenantID.String(), nil
}

func requireSkillName(rpc, name string) error {
	if !toolid.ValidSkillName(name) {
		return status_grpc.Errorf(codes.InvalidArgument, "%s: %q is not a valid Agent Skill name", rpc, name)
	}
	return nil
}

// agentSkillStatus maps a store or pull error to a gRPC status.
func agentSkillStatus(rpc string, err error) error {
	switch {
	case errors.Is(err, agentskill.ErrOverLimit):
		return status_grpc.Error(codes.ResourceExhausted, rpc+": "+err.Error())
	case errors.Is(err, agentskill.ErrInvalidFolder):
		return status_grpc.Error(codes.InvalidArgument, rpc+": "+err.Error())
	case errors.Is(err, agentskillstore.ErrNotFound):
		return status_grpc.Error(codes.NotFound, rpc+": "+err.Error())
	default:
		return status_grpc.Error(codes.Internal, rpc+": "+err.Error())
	}
}

func agentSkillEntryProto(e agentskillstore.Entry) *tenantv1.AgentSkillEntry {
	return &tenantv1.AgentSkillEntry{
		Name:          e.Name,
		Digest:        e.Digest,
		Reference:     e.Reference,
		Description:   e.Description,
		License:       e.License,
		Compatibility: e.Compatibility,
		Metadata:      e.Metadata,
		AllowedTools:  e.AllowedTools,
		PublishedAt:   timestamppb.New(e.PublishedAt),
		Current:       e.Current,
	}
}

// PublishAgentSkill pulls the image by digest, validates it, stores the content
// and makes the version current. The tenant owner tuple of the Agent Skill is
// written after the store, so a retry after a failure is safe.
func (s *AgentSkillService) PublishAgentSkill(
	ctx context.Context, req *tenantv1.PublishAgentSkillRequest,
) (*tenantv1.PublishAgentSkillResponse, error) {
	const rpc = "PublishAgentSkill"
	tenant, err := agentSkillTenant(ctx, rpc)
	if err != nil {
		return nil, err
	}
	if err := requireSkillName(rpc, req.GetName()); err != nil {
		return nil, err
	}
	object, err := authz.AgentSkillObject(tenant, req.GetName())
	if err != nil {
		return nil, status_grpc.Error(codes.InvalidArgument, rpc+": "+err.Error())
	}
	pulled, err := s.pull(ctx, req.GetReference(), req.GetName())
	if err != nil {
		return nil, agentSkillStatus(rpc, err)
	}
	entry, err := s.store.Publish(ctx, tenant, req.GetReference(), pulled)
	if err != nil {
		return nil, agentSkillStatus(rpc, err)
	}
	if err := s.fga.Write(ctx, []authz.Tuple{{User: "tenant:" + tenant, Relation: "owner", Object: object}}); err != nil {
		return nil, status_grpc.Error(codes.Internal, fmt.Sprintf("%s: write the owner tuple: %v", rpc, err))
	}
	return &tenantv1.PublishAgentSkillResponse{Entry: agentSkillEntryProto(*entry)}, nil
}

// ListAgentSkills returns the Agent Skills of the tenant.
func (s *AgentSkillService) ListAgentSkills(
	ctx context.Context, req *tenantv1.ListAgentSkillsRequest,
) (*tenantv1.ListAgentSkillsResponse, error) {
	const rpc = "ListAgentSkills"
	tenant, err := agentSkillTenant(ctx, rpc)
	if err != nil {
		return nil, err
	}
	if req.GetName() != "" {
		if err := requireSkillName(rpc, req.GetName()); err != nil {
			return nil, err
		}
	}
	entries, err := s.store.List(ctx, tenant, req.GetName(), req.GetAllVersions())
	if err != nil {
		return nil, agentSkillStatus(rpc, err)
	}
	out := &tenantv1.ListAgentSkillsResponse{Entries: make([]*tenantv1.AgentSkillEntry, 0, len(entries))}
	for _, e := range entries {
		out.Entries = append(out.Entries, agentSkillEntryProto(e))
	}
	return out, nil
}

// GetAgentSkill returns one version with its body and its file list.
func (s *AgentSkillService) GetAgentSkill(
	ctx context.Context, req *tenantv1.GetAgentSkillRequest,
) (*tenantv1.GetAgentSkillResponse, error) {
	const rpc = "GetAgentSkill"
	tenant, err := agentSkillTenant(ctx, rpc)
	if err != nil {
		return nil, err
	}
	if err := requireSkillName(rpc, req.GetName()); err != nil {
		return nil, err
	}
	digest := req.GetDigest()
	if digest == "" {
		cur, gerr := s.store.Get(ctx, tenant, req.GetName(), "")
		if gerr != nil {
			return nil, agentSkillStatus(rpc, gerr)
		}
		digest = cur.Digest
	}
	loaded, err := s.store.Load(ctx, tenant, req.GetName(), digest)
	if err != nil {
		return nil, agentSkillStatus(rpc, err)
	}
	out := &tenantv1.GetAgentSkillResponse{Entry: agentSkillEntryProto(loaded.Entry), Body: loaded.Body}
	for _, f := range loaded.Files {
		out.Files = append(out.Files, &tenantv1.AgentSkillFile{Path: f.Path, SizeBytes: int64(f.Size)})
	}
	return out, nil
}

// DeleteAgentSkill removes each version of a name, and the grants and the owner
// tuple of its object. A grant that stayed would come back if the tenant
// published the same name again.
func (s *AgentSkillService) DeleteAgentSkill(
	ctx context.Context, req *tenantv1.DeleteAgentSkillRequest,
) (*tenantv1.DeleteAgentSkillResponse, error) {
	const rpc = "DeleteAgentSkill"
	tenant, err := agentSkillTenant(ctx, rpc)
	if err != nil {
		return nil, err
	}
	if err := requireSkillName(rpc, req.GetName()); err != nil {
		return nil, err
	}
	object, err := authz.AgentSkillObject(tenant, req.GetName())
	if err != nil {
		return nil, status_grpc.Error(codes.InvalidArgument, rpc+": "+err.Error())
	}
	// The tuples go first. A failure here leaves the content in place, and the
	// caller can retry.
	tuples := []authz.Tuple{{User: "tenant:" + tenant, Relation: "owner", Object: object}}
	for _, g := range []struct{ userType, relation string }{
		{"agent_principal", "granted_agent"},
		{"mission", "granted_mission"},
	} {
		users, lerr := s.fga.ListUsersOfType(ctx, "agent_skill", object, g.relation, g.userType)
		if lerr != nil {
			return nil, status_grpc.Error(codes.Internal, fmt.Sprintf("%s: list the grants: %v", rpc, lerr))
		}
		for _, u := range users {
			tuples = append(tuples, authz.Tuple{User: u, Relation: g.relation, Object: object})
		}
	}
	if err := s.fga.Delete(ctx, tuples); err != nil {
		return nil, status_grpc.Error(codes.Internal, fmt.Sprintf("%s: delete the tuples: %v", rpc, err))
	}
	n, err := s.store.Delete(ctx, tenant, req.GetName())
	if err != nil {
		return nil, agentSkillStatus(rpc, err)
	}
	return &tenantv1.DeleteAgentSkillResponse{DeletedVersions: int32Count(int(n))}, nil
}

// grantTuple builds the tuple of a grant. With verify it also refuses a subject
// that is not of the tenant of the caller. Without that check an admin could
// name an agent or a mission of another tenant. A revoke does not verify,
// because it must still remove the grant of a mission that is gone.
func (s *AgentSkillService) grantTuple(
	ctx context.Context, rpc, tenant, name string, kind tenantv1.AgentSkillSubjectKind, subjectID string, verify bool,
) (authz.Tuple, error) {
	if err := requireSkillName(rpc, name); err != nil {
		return authz.Tuple{}, err
	}
	object, err := authz.AgentSkillObject(tenant, name)
	if err != nil {
		return authz.Tuple{}, status_grpc.Error(codes.InvalidArgument, rpc+": "+err.Error())
	}
	var subject, relation string
	switch kind {
	case tenantv1.AgentSkillSubjectKind_AGENT_SKILL_SUBJECT_KIND_AGENT:
		subject, relation = "agent_principal:"+subjectID, "granted_agent"
	case tenantv1.AgentSkillSubjectKind_AGENT_SKILL_SUBJECT_KIND_MISSION:
		subject, relation = "mission:"+subjectID, "granted_mission"
	default:
		return authz.Tuple{}, status_grpc.Error(codes.InvalidArgument, rpc+": the subject kind is not set")
	}
	if !verify {
		return authz.Tuple{User: subject, Relation: relation, Object: object}, nil
	}
	owned, err := s.fga.Check(ctx, "tenant:"+tenant, "belongs_to", subject)
	if err != nil {
		return authz.Tuple{}, status_grpc.Error(codes.Internal, fmt.Sprintf("%s: check the subject: %v", rpc, err))
	}
	if !owned {
		return authz.Tuple{}, status_grpc.Errorf(codes.NotFound, "%s: %s is not of this tenant", rpc, subject)
	}
	return authz.Tuple{User: subject, Relation: relation, Object: object}, nil
}

// GrantAgentSkill lets one agent or one mission load an Agent Skill.
func (s *AgentSkillService) GrantAgentSkill(
	ctx context.Context, req *tenantv1.GrantAgentSkillRequest,
) (*tenantv1.GrantAgentSkillResponse, error) {
	const rpc = "GrantAgentSkill"
	tenant, err := agentSkillTenant(ctx, rpc)
	if err != nil {
		return nil, err
	}
	tuple, err := s.grantTuple(ctx, rpc, tenant, req.GetName(), req.GetSubjectKind(), req.GetSubjectId(), true)
	if err != nil {
		return nil, err
	}
	// A grant on a name that has no version is refused.
	if _, err := s.store.Get(ctx, tenant, req.GetName(), ""); err != nil {
		return nil, agentSkillStatus(rpc, err)
	}
	if err := s.fga.Write(ctx, []authz.Tuple{tuple}); err != nil {
		return nil, status_grpc.Error(codes.Internal, fmt.Sprintf("%s: write the grant: %v", rpc, err))
	}
	return &tenantv1.GrantAgentSkillResponse{}, nil
}

// RevokeAgentSkill removes a grant.
func (s *AgentSkillService) RevokeAgentSkill(
	ctx context.Context, req *tenantv1.RevokeAgentSkillRequest,
) (*tenantv1.RevokeAgentSkillResponse, error) {
	const rpc = "RevokeAgentSkill"
	tenant, err := agentSkillTenant(ctx, rpc)
	if err != nil {
		return nil, err
	}
	tuple, err := s.grantTuple(ctx, rpc, tenant, req.GetName(), req.GetSubjectKind(), req.GetSubjectId(), false)
	if err != nil {
		return nil, err
	}
	if err := s.fga.Delete(ctx, []authz.Tuple{tuple}); err != nil {
		return nil, status_grpc.Error(codes.Internal, fmt.Sprintf("%s: delete the grant: %v", rpc, err))
	}
	return &tenantv1.RevokeAgentSkillResponse{}, nil
}
