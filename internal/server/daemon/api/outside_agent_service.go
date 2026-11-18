// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/zeroroot-ai/gibson/internal/infra/netguard"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/componentcatalog"
	"github.com/zeroroot-ai/gibson/internal/platform/outsideagentstore"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// outsideAgentAddressHint is the hint of a refusal of the host of an outside
// agent. The setting security.allow_private_llm_endpoints does not apply to it.
const outsideAgentAddressHint = "the host of an outside agent must resolve to a public address"

// outsideAgentNamePattern is a DNS label. The name is part of a route match and
// of the name of a Kubernetes object, so it must be a label.
var outsideAgentNamePattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

// OutsideAgentFGA is the part of authz.Authorizer that the service uses.
type OutsideAgentFGA interface {
	Check(ctx context.Context, user, relation, object string) (bool, error)
	Write(ctx context.Context, tuples []authz.Tuple) error
	Delete(ctx context.Context, tuples []authz.Tuple) error
	ListUsersOfType(ctx context.Context, objectType, object, relation, userType string) ([]string, error)
}

// OutsideAgentService serves gibson.tenant.v1.OutsideAgentService (epic
// gibson#1366, gibson#1403). The daemon never calls an outside agent. The tenant
// operator renders a route, and the Agent gateway makes the call.
type OutsideAgentService struct {
	tenantv1.UnimplementedOutsideAgentServiceServer

	store    outsideagentstore.Store
	fga      OutsideAgentFGA
	resolver netguard.Resolver
}

// NewOutsideAgentService returns the service. Each argument is required.
func NewOutsideAgentService(
	store outsideagentstore.Store, fga OutsideAgentFGA, resolver netguard.Resolver,
) (*OutsideAgentService, error) {
	if store == nil || fga == nil || resolver == nil {
		return nil, errors.New("api: OutsideAgentService needs a store, the authorizer and a resolver")
	}
	return &OutsideAgentService{store: store, fga: fga, resolver: resolver}, nil
}

func outsideAgentTenant(ctx context.Context, rpc string) (string, error) {
	tenantID, ok := auth.TenantFromContext(ctx)
	if !ok || tenantID.IsZero() {
		return "", status_grpc.Error(codes.PermissionDenied, rpc+": missing tenant in context")
	}
	return tenantID.String(), nil
}

func requireOutsideAgentName(rpc, name string) error {
	if !outsideAgentNamePattern.MatchString(name) {
		return status_grpc.Errorf(codes.InvalidArgument, "%s: %q is not a valid outside agent name (a DNS label)", rpc, name)
	}
	return nil
}

// ValidateOutsideAgentURL refuses a URL that is not an HTTPS URL of a public
// host. It refuses a user name, a query and a fragment, because the tenant
// operator copies the host and the path into a route and nothing else. The
// check is for one point in time. The gateway must still refuse an internal
// address at the time of the call.
func ValidateOutsideAgentURL(ctx context.Context, r netguard.Resolver, raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("the URL does not parse: %w", err)
	}
	switch {
	case u.Scheme != "https":
		return nil, errors.New("the URL must use https")
	case u.Hostname() == "":
		return nil, errors.New("the URL has no host")
	case u.User != nil:
		return nil, errors.New("the URL must not hold a user name or a password")
	case u.RawQuery != "" || u.Fragment != "" || u.ForceQuery:
		return nil, errors.New("the URL must not hold a query or a fragment")
	}
	if err := netguard.CheckHost(ctx, r, u.Hostname(), outsideAgentAddressHint); err != nil {
		return nil, err
	}
	return u, nil
}

func outsideAgentStatus(rpc string, err error) error {
	switch {
	case errors.Is(err, outsideagentstore.ErrNotFound):
		return status_grpc.Error(codes.NotFound, rpc+": "+err.Error())
	case errors.Is(err, outsideagentstore.ErrConflict):
		return status_grpc.Error(codes.AlreadyExists, rpc+": "+err.Error())
	default:
		return status_grpc.Error(codes.Internal, rpc+": "+err.Error())
	}
}

func outsideAgentEntryProto(e outsideagentstore.Entry) *tenantv1.OutsideAgentEntry {
	return &tenantv1.OutsideAgentEntry{
		Name: e.Name, A2AUrl: e.A2AURL, CredentialSecret: e.CredentialSecret, Description: e.Description,
		CreatedAt: timestamppb.New(e.CreatedAt),
	}
}

// RegisterOutsideAgent saves one outside agent and writes the owner tuple of its
// object. The tuple goes after the store, so a retry after a failure is safe.
func (s *OutsideAgentService) RegisterOutsideAgent(
	ctx context.Context, req *tenantv1.RegisterOutsideAgentRequest,
) (*tenantv1.RegisterOutsideAgentResponse, error) {
	const rpc = "RegisterOutsideAgent"
	tenant, err := outsideAgentTenant(ctx, rpc)
	if err != nil {
		return nil, err
	}
	if err := requireOutsideAgentName(rpc, req.GetName()); err != nil {
		return nil, err
	}
	object, err := authz.OutsideAgentObject(tenant, req.GetName())
	if err != nil {
		return nil, status_grpc.Error(codes.InvalidArgument, rpc+": "+err.Error())
	}
	// A route names the target by its name. A catalog agent of the same name
	// would share the route headers of the outside agent, so the name is refused.
	if _, ok := componentcatalog.LookupAgent(req.GetName()); ok {
		return nil, status_grpc.Errorf(codes.AlreadyExists, "%s: the catalog has an agent named %q", rpc, req.GetName())
	}
	u, err := ValidateOutsideAgentURL(ctx, s.resolver, req.GetA2AUrl())
	if err != nil {
		return nil, status_grpc.Error(codes.InvalidArgument, rpc+": "+err.Error())
	}
	entry, err := s.store.Register(ctx, tenant, outsideagentstore.Entry{
		Name: req.GetName(), A2AURL: u.String(), CredentialSecret: req.GetCredentialSecret(),
		Description: req.GetDescription(),
	})
	if err != nil {
		return nil, outsideAgentStatus(rpc, err)
	}
	if err := s.fga.Write(ctx, []authz.Tuple{{User: "tenant:" + tenant, Relation: "owner", Object: object}}); err != nil {
		return nil, status_grpc.Error(codes.Internal, fmt.Sprintf("%s: write the owner tuple: %v", rpc, err))
	}
	return &tenantv1.RegisterOutsideAgentResponse{Entry: outsideAgentEntryProto(*entry)}, nil
}

// ListOutsideAgents returns the outside agents of the tenant.
func (s *OutsideAgentService) ListOutsideAgents(
	ctx context.Context, _ *tenantv1.ListOutsideAgentsRequest,
) (*tenantv1.ListOutsideAgentsResponse, error) {
	const rpc = "ListOutsideAgents"
	tenant, err := outsideAgentTenant(ctx, rpc)
	if err != nil {
		return nil, err
	}
	entries, err := s.store.List(ctx, tenant)
	if err != nil {
		return nil, outsideAgentStatus(rpc, err)
	}
	out := &tenantv1.ListOutsideAgentsResponse{Entries: make([]*tenantv1.OutsideAgentEntry, 0, len(entries))}
	for _, e := range entries {
		out.Entries = append(out.Entries, outsideAgentEntryProto(e))
	}
	return out, nil
}

// GetOutsideAgent returns one outside agent.
func (s *OutsideAgentService) GetOutsideAgent(
	ctx context.Context, req *tenantv1.GetOutsideAgentRequest,
) (*tenantv1.GetOutsideAgentResponse, error) {
	const rpc = "GetOutsideAgent"
	tenant, err := outsideAgentTenant(ctx, rpc)
	if err != nil {
		return nil, err
	}
	if err := requireOutsideAgentName(rpc, req.GetName()); err != nil {
		return nil, err
	}
	e, err := s.store.Get(ctx, tenant, req.GetName())
	if err != nil {
		return nil, outsideAgentStatus(rpc, err)
	}
	return &tenantv1.GetOutsideAgentResponse{Entry: outsideAgentEntryProto(*e)}, nil
}

// outsideAgentGrantees lists the missions that hold a grant of the object.
func (s *OutsideAgentService) outsideAgentGrantees(ctx context.Context, object string) ([]string, error) {
	users, err := s.fga.ListUsersOfType(ctx, "outside_agent", object, "granted_mission", "mission")
	if err != nil {
		return nil, fmt.Errorf("list the grants: %w", err)
	}
	return users, nil
}

// DeleteOutsideAgent removes the record, its grants and its owner tuple. A grant
// that stayed would come back if the tenant registered the same name again.
func (s *OutsideAgentService) DeleteOutsideAgent(
	ctx context.Context, req *tenantv1.DeleteOutsideAgentRequest,
) (*tenantv1.DeleteOutsideAgentResponse, error) {
	const rpc = "DeleteOutsideAgent"
	tenant, err := outsideAgentTenant(ctx, rpc)
	if err != nil {
		return nil, err
	}
	if err := requireOutsideAgentName(rpc, req.GetName()); err != nil {
		return nil, err
	}
	object, err := authz.OutsideAgentObject(tenant, req.GetName())
	if err != nil {
		return nil, status_grpc.Error(codes.InvalidArgument, rpc+": "+err.Error())
	}
	if _, gerr := s.store.Get(ctx, tenant, req.GetName()); gerr != nil {
		return nil, outsideAgentStatus(rpc, gerr)
	}
	// The tuples go first. A failure here leaves the record in place, and the
	// caller can retry.
	tuples := []authz.Tuple{{User: "tenant:" + tenant, Relation: "owner", Object: object}}
	users, err := s.outsideAgentGrantees(ctx, object)
	if err != nil {
		return nil, status_grpc.Error(codes.Internal, rpc+": "+err.Error())
	}
	for _, u := range users {
		tuples = append(tuples, authz.Tuple{User: u, Relation: "granted_mission", Object: object})
	}
	if err := s.fga.Delete(ctx, tuples); err != nil {
		return nil, status_grpc.Error(codes.Internal, fmt.Sprintf("%s: delete the tuples: %v", rpc, err))
	}
	if err := s.store.Delete(ctx, tenant, req.GetName()); err != nil {
		return nil, outsideAgentStatus(rpc, err)
	}
	return &tenantv1.DeleteOutsideAgentResponse{}, nil
}

// GrantOutsideAgent lets one mission of the tenant call an outside agent. It
// refuses a mission that is not of the tenant of the caller. Without that check
// an admin could name a mission of another tenant.
func (s *OutsideAgentService) GrantOutsideAgent(
	ctx context.Context, req *tenantv1.GrantOutsideAgentRequest,
) (*tenantv1.GrantOutsideAgentResponse, error) {
	const rpc = "GrantOutsideAgent"
	tenant, err := outsideAgentTenant(ctx, rpc)
	if err != nil {
		return nil, err
	}
	if err := requireOutsideAgentName(rpc, req.GetName()); err != nil {
		return nil, err
	}
	object, err := authz.OutsideAgentObject(tenant, req.GetName())
	if err != nil {
		return nil, status_grpc.Error(codes.InvalidArgument, rpc+": "+err.Error())
	}
	missionID := strings.TrimSpace(req.GetMissionId())
	if missionID == "" || strings.ContainsAny(missionID, ":#/ ") {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "%s: the mission id is not valid", rpc)
	}
	subject := "mission:" + missionID
	owned, err := s.fga.Check(ctx, "tenant:"+tenant, "belongs_to", subject)
	if err != nil {
		return nil, status_grpc.Error(codes.Internal, fmt.Sprintf("%s: check the mission: %v", rpc, err))
	}
	if !owned {
		return nil, status_grpc.Errorf(codes.NotFound, "%s: %s is not of this tenant", rpc, subject)
	}
	// A grant on a name that has no record is refused.
	if _, err := s.store.Get(ctx, tenant, req.GetName()); err != nil {
		return nil, outsideAgentStatus(rpc, err)
	}
	if err := s.fga.Write(ctx, []authz.Tuple{{User: subject, Relation: "granted_mission", Object: object}}); err != nil {
		return nil, status_grpc.Error(codes.Internal, fmt.Sprintf("%s: write the grant: %v", rpc, err))
	}
	return &tenantv1.GrantOutsideAgentResponse{}, nil
}

// RevokeOutsideAgent removes the grant of a mission. It does not check that the
// mission exists, so it can remove the grant of a mission that is gone.
func (s *OutsideAgentService) RevokeOutsideAgent(
	ctx context.Context, req *tenantv1.RevokeOutsideAgentRequest,
) (*tenantv1.RevokeOutsideAgentResponse, error) {
	const rpc = "RevokeOutsideAgent"
	tenant, err := outsideAgentTenant(ctx, rpc)
	if err != nil {
		return nil, err
	}
	if err := requireOutsideAgentName(rpc, req.GetName()); err != nil {
		return nil, err
	}
	object, err := authz.OutsideAgentObject(tenant, req.GetName())
	if err != nil {
		return nil, status_grpc.Error(codes.InvalidArgument, rpc+": "+err.Error())
	}
	missionID := strings.TrimSpace(req.GetMissionId())
	if missionID == "" || strings.ContainsAny(missionID, ":#/ ") {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "%s: the mission id is not valid", rpc)
	}
	err = s.fga.Delete(ctx, []authz.Tuple{{User: "mission:" + missionID, Relation: "granted_mission", Object: object}})
	if err != nil {
		return nil, status_grpc.Error(codes.Internal, fmt.Sprintf("%s: delete the grant: %v", rpc, err))
	}
	return &tenantv1.RevokeOutsideAgentResponse{}, nil
}

// ListOutsideAgentGrants returns the missions that may call one outside agent.
func (s *OutsideAgentService) ListOutsideAgentGrants(
	ctx context.Context, req *tenantv1.ListOutsideAgentGrantsRequest,
) (*tenantv1.ListOutsideAgentGrantsResponse, error) {
	const rpc = "ListOutsideAgentGrants"
	tenant, err := outsideAgentTenant(ctx, rpc)
	if err != nil {
		return nil, err
	}
	if err := requireOutsideAgentName(rpc, req.GetName()); err != nil {
		return nil, err
	}
	object, err := authz.OutsideAgentObject(tenant, req.GetName())
	if err != nil {
		return nil, status_grpc.Error(codes.InvalidArgument, rpc+": "+err.Error())
	}
	if _, err := s.store.Get(ctx, tenant, req.GetName()); err != nil {
		return nil, outsideAgentStatus(rpc, err)
	}
	users, err := s.outsideAgentGrantees(ctx, object)
	if err != nil {
		return nil, status_grpc.Error(codes.Internal, rpc+": "+err.Error())
	}
	out := &tenantv1.ListOutsideAgentGrantsResponse{}
	for _, u := range users {
		out.MissionIds = append(out.MissionIds, strings.TrimPrefix(u, "mission:"))
	}
	return out, nil
}
