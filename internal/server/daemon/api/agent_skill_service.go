// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/zeroroot-ai/gibson/internal/engine/agentskill"
	"github.com/zeroroot-ai/gibson/internal/engine/toolid"
	"github.com/zeroroot-ai/gibson/internal/platform/agentskillstore"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/supplychain"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// AgentSkillPuller reads the image that a digest reference names and returns
// the validated folder. In production it is agentskill.Puller.Pull. The keychain
// holds the credential of the tenant secret, or nothing for an anonymous pull.
// A test supplies its own.
type AgentSkillPuller func(
	ctx context.Context, reference, folderName string, keychain authn.Keychain,
) (*agentskill.Pulled, error)

// AgentSkillSecrets reads the value of a tenant secret by name, for the tenant of
// the context. *secrets.Service satisfies it.
type AgentSkillSecrets interface {
	Resolve(ctx context.Context, name string) ([]byte, error)
}

// AgentSkillFGA is the part of authz.Authorizer that the service uses.
type AgentSkillFGA interface {
	Check(ctx context.Context, user, relation, object string) (bool, error)
	Write(ctx context.Context, tuples []authz.Tuple) error
	Delete(ctx context.Context, tuples []authz.Tuple) error
	ListUsersOfType(ctx context.Context, objectType, object, relation, userType string) ([]string, error)
}

// SharedAgentSkill is one Shared Agent Skill that the operator offers. The
// daemon pulled and validated it at start.
type SharedAgentSkill struct {
	Reference string
	Pulled    *agentskill.Pulled
}

// SharedAgentSkillSource lists the Shared Agent Skills of the operator source.
type SharedAgentSkillSource interface {
	Names() []string
	Get(name string) (SharedAgentSkill, bool)
}

// AgentSkillService serves gibson.tenant.v1.AgentSkillService (epic
// gibson#1364). The daemon has no write path to a registry. The publisher
// pushes the image, and this service pulls it by digest.
type AgentSkillService struct {
	tenantv1.UnimplementedAgentSkillServiceServer

	store agentskillstore.Store
	pull  AgentSkillPuller
	fga   AgentSkillFGA
	// secrets reads the registry credential of a publish. The service never
	// stores the value.
	secrets AgentSkillSecrets
	// shared is the operator source of Shared Agent Skills.
	shared SharedAgentSkillSource
}

// NewAgentSkillService returns the service. Each argument is required.
func NewAgentSkillService(
	store agentskillstore.Store, pull AgentSkillPuller, fga AgentSkillFGA, secrets AgentSkillSecrets,
	shared SharedAgentSkillSource,
) (*AgentSkillService, error) {
	if store == nil || pull == nil || fga == nil || secrets == nil || shared == nil {
		return nil, errors.New("api: AgentSkillService needs a store, a puller, the authorizer, the secrets and the shared source")
	}
	return &AgentSkillService{store: store, pull: pull, fga: fga, secrets: secrets, shared: shared}, nil
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

func agentSkillSourceProto(source string) tenantv1.AgentSkillSource {
	switch source {
	case agentskillstore.SourceTenant:
		return tenantv1.AgentSkillSource_AGENT_SKILL_SOURCE_TENANT
	case agentskillstore.SourceShared:
		return tenantv1.AgentSkillSource_AGENT_SKILL_SOURCE_SHARED
	default:
		return tenantv1.AgentSkillSource_AGENT_SKILL_SOURCE_UNSPECIFIED
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
		Source:        agentSkillSourceProto(e.Source),
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
	keychain, err := s.registryKeychain(ctx, rpc, req.GetRegistrySecret())
	if err != nil {
		return nil, err
	}
	pulled, err := s.pull(ctx, req.GetReference(), req.GetName(), keychain)
	if err != nil {
		return nil, agentSkillStatus(rpc, err)
	}
	entry, err := s.store.Publish(ctx, tenant, req.GetReference(), agentskillstore.SourceTenant, pulled)
	if err != nil {
		return nil, agentSkillStatus(rpc, err)
	}
	if err := s.fga.Write(ctx, []authz.Tuple{{User: "tenant:" + tenant, Relation: "owner", Object: object}}); err != nil {
		return nil, status_grpc.Error(codes.Internal, fmt.Sprintf("%s: write the owner tuple: %v", rpc, err))
	}
	return &tenantv1.PublishAgentSkillResponse{Entry: agentSkillEntryProto(*entry)}, nil
}

// registryKeychain returns the credential of a pull. With no secret name the pull
// is anonymous. With a name, the value of that secret of the tenant is the
// credential, as the bytes of a docker config. The value lives in the keychain
// for this call and is never stored. The daemon process credential is never
// used here, because it would lend the operator credential to a tenant.
func (s *AgentSkillService) registryKeychain(ctx context.Context, rpc, secretName string) (authn.Keychain, error) {
	if secretName == "" {
		return authn.NewMultiKeychain(), nil
	}
	raw, err := s.secrets.Resolve(ctx, secretName)
	if err != nil {
		return nil, status_grpc.Errorf(codes.FailedPrecondition, "%s: read the registry secret %q: %v", rpc, secretName, err)
	}
	return supplychain.NewDockerConfigKeychain(raw, "the tenant secret "+secretName), nil
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

// grantRelations are the relations that hold a grant of an Agent Skill, with the
// FGA subject type and the subject kind of each.
var grantRelations = []struct {
	relation, userType string
	kind               tenantv1.AgentSkillSubjectKind
}{
	{"granted_agent", "agent_principal", tenantv1.AgentSkillSubjectKind_AGENT_SKILL_SUBJECT_KIND_AGENT},
	{"granted_mission", "mission", tenantv1.AgentSkillSubjectKind_AGENT_SKILL_SUBJECT_KIND_MISSION},
}

// ListAgentSkillGrants returns the agents and the missions that hold a grant of
// the Agent Skill. It reads the same tuples as DeleteAgentSkill.
func (s *AgentSkillService) ListAgentSkillGrants(
	ctx context.Context, req *tenantv1.ListAgentSkillGrantsRequest,
) (*tenantv1.ListAgentSkillGrantsResponse, error) {
	const rpc = "ListAgentSkillGrants"
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
	if _, err := s.store.Get(ctx, tenant, req.GetName(), ""); err != nil {
		return nil, agentSkillStatus(rpc, err)
	}
	out := &tenantv1.ListAgentSkillGrantsResponse{}
	for _, g := range grantRelations {
		users, lerr := s.fga.ListUsersOfType(ctx, "agent_skill", object, g.relation, g.userType)
		if lerr != nil {
			return nil, status_grpc.Error(codes.Internal, fmt.Sprintf("%s: list the grants: %v", rpc, lerr))
		}
		for _, u := range users {
			out.Grants = append(out.Grants, &tenantv1.AgentSkillGrant{
				SubjectKind: g.kind, SubjectId: strings.TrimPrefix(u, g.userType+":"),
			})
		}
	}
	return out, nil
}

// ListSharedAgentSkills returns the Shared Agent Skills that the operator offers
// and whether the tenant holds each digest.
func (s *AgentSkillService) ListSharedAgentSkills(
	ctx context.Context, _ *tenantv1.ListSharedAgentSkillsRequest,
) (*tenantv1.ListSharedAgentSkillsResponse, error) {
	const rpc = "ListSharedAgentSkills"
	tenant, err := agentSkillTenant(ctx, rpc)
	if err != nil {
		return nil, err
	}
	out := &tenantv1.ListSharedAgentSkillsResponse{}
	for _, name := range s.shared.Names() {
		e, ok := s.shared.Get(name)
		if !ok {
			continue
		}
		_, gerr := s.store.Get(ctx, tenant, name, e.Pulled.Digest)
		if gerr != nil && !errors.Is(gerr, agentskillstore.ErrNotFound) {
			return nil, agentSkillStatus(rpc, gerr)
		}
		out.Entries = append(out.Entries, &tenantv1.SharedAgentSkillEntry{
			Name: name, Description: e.Pulled.Manifest.Description, Digest: e.Pulled.Digest, Enabled: gerr == nil,
		})
	}
	return out, nil
}

// EnableSharedAgentSkill copies one Shared Agent Skill into the tenant. The
// platform gate must offer it: the system tenant holds platform_enabled on its
// shared object. The call writes the owner tuple and no grant, so a tenant admin
// still grants the Agent Skill before a load.
func (s *AgentSkillService) EnableSharedAgentSkill(
	ctx context.Context, req *tenantv1.EnableSharedAgentSkillRequest,
) (*tenantv1.EnableSharedAgentSkillResponse, error) {
	const rpc = "EnableSharedAgentSkill"
	tenant, err := agentSkillTenant(ctx, rpc)
	if err != nil {
		return nil, err
	}
	if err := requireSkillName(rpc, req.GetName()); err != nil {
		return nil, err
	}
	sharedObject, err := authz.SharedAgentSkillObject(req.GetName())
	if err != nil {
		return nil, status_grpc.Error(codes.InvalidArgument, rpc+": "+err.Error())
	}
	offered, err := s.fga.Check(ctx, "system_tenant:_system", "platform_enabled", sharedObject)
	if err != nil {
		return nil, status_grpc.Error(codes.Internal, fmt.Sprintf("%s: check the platform gate: %v", rpc, err))
	}
	shared, found := s.shared.Get(req.GetName())
	if !offered || !found {
		return nil, status_grpc.Errorf(codes.NotFound, "%s: the operator offers no Agent Skill %q", rpc, req.GetName())
	}
	object, err := authz.AgentSkillObject(tenant, req.GetName())
	if err != nil {
		return nil, status_grpc.Error(codes.InvalidArgument, rpc+": "+err.Error())
	}
	entry, err := s.store.Publish(ctx, tenant, shared.Reference, agentskillstore.SourceShared, shared.Pulled)
	if err != nil {
		return nil, agentSkillStatus(rpc, err)
	}
	if err := s.fga.Write(ctx, []authz.Tuple{{User: "tenant:" + tenant, Relation: "owner", Object: object}}); err != nil {
		return nil, status_grpc.Error(codes.Internal, fmt.Sprintf("%s: write the owner tuple: %v", rpc, err))
	}
	return &tenantv1.EnableSharedAgentSkillResponse{Entry: agentSkillEntryProto(*entry)}, nil
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
	case tenantv1.AgentSkillSubjectKind_AGENT_SKILL_SUBJECT_KIND_UNSPECIFIED:
		return authz.Tuple{}, status_grpc.Error(codes.InvalidArgument, rpc+": the subject kind is not set")
	default:
		return authz.Tuple{}, status_grpc.Error(codes.InvalidArgument, rpc+": the subject kind is not known")
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
