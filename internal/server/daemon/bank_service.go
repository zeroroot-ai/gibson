// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package daemon — bank_service.go
//
// bankServer implements gibson.bank.v1.BankService: the declarative resource
// behind banks of always-on coding agents (ADR-0019, gibson#1708).
//
// A bank says how many members should run, who owns them, and how they
// authenticate. Nothing here launches a sandbox. The reconciler reads these
// rows and makes the running member count match the desired one; this service
// is where a person or a platform service writes what "desired" means.
//
// Tenant scope is the context's, never the request's: the tenant selects the
// per-tenant database, so a bank id from one tenant cannot resolve in another.
package daemon

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/bank"
	"github.com/zeroroot-ai/gibson/internal/platform/componentcatalog"
	"github.com/zeroroot-ai/gibson/pkg/billing/entitlements"
	bankpb "github.com/zeroroot-ai/sdk/api/gen/gibson/bank/v1"
	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// bankServer serves BankService over the bank store.
type bankServer struct {
	bankpb.UnimplementedBankServiceServer

	store        bank.Store
	authorizer   authz.Authorizer
	entitlements entitlements.Provider
	logger       *slog.Logger
	control      *harness.MemberControl
	feed         SignInFeed
}

// BankServerConfig is the constructor input. Store and Authorizer are
// required: without a store there is nothing to serve, and without an
// authorizer a created bank would carry no ownership tuple, so nobody could
// ever manage it and everybody could read it.
type BankServerConfig struct {
	Store        bank.Store
	Authorizer   authz.Authorizer
	Entitlements entitlements.Provider
	Logger       *slog.Logger
	// Control is the in-memory queue the sign-in relay enqueues on and the
	// member's inbox delivers from (gibson#1715). Required.
	Control *harness.MemberControl
	// Feed is the member's live stream the relay reads the flow's lines from.
	// Required.
	Feed SignInFeed
}

// NewBankServer constructs the BankService. It returns an error rather than
// panicking so the daemon can log and continue without the bank surface.
func NewBankServer(cfg BankServerConfig) (bankpb.BankServiceServer, error) {
	if cfg.Store == nil {
		return nil, errors.New("daemon: NewBankServer: Store is required")
	}
	if cfg.Control == nil {
		return nil, errors.New("bank service: Control is required")
	}
	if cfg.Feed == nil {
		return nil, errors.New("bank service: Feed is required")
	}
	if cfg.Authorizer == nil {
		return nil, errors.New("daemon: NewBankServer: Authorizer is required (a bank with no ownership tuple is a bank nobody can manage)")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &bankServer{
		store:        cfg.Store,
		authorizer:   cfg.Authorizer,
		entitlements: entitlements.Resolve(cfg.Entitlements),
		logger:       cfg.Logger.With("component", "bank_service"),
		control:      cfg.Control,
		feed:         cfg.Feed,
	}, nil
}

// tenant resolves the caller's tenant. It is the only scope a request reads.
func (s *bankServer) tenant(ctx context.Context) (string, error) {
	t, ok := auth.TenantFromContext(ctx)
	if !ok || t.String() == "" {
		return "", status.Error(codes.PermissionDenied, "no tenant in context")
	}
	return t.String(), nil
}

// caller resolves the identity that made the request. A bank needs one,
// because ownership is what decides who may change it later.
func (s *bankServer) caller(ctx context.Context) (string, error) {
	id, err := auth.IdentityFromContext(ctx)
	if err != nil || id.Subject == "" {
		return "", status.Error(codes.PermissionDenied, "no caller identity in context")
	}
	return id.Subject, nil
}

// CreateBank declares a bank and writes the tuples that say who owns it.
func (s *bankServer) CreateBank(ctx context.Context, req *bankpb.CreateBankRequest) (*bankpb.CreateBankResponse, error) {
	tenant, err := s.tenant(ctx)
	if err != nil {
		return nil, err
	}
	subject, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}

	in := bank.CreateInput{
		Name:               req.GetName(),
		DesiredCount:       req.GetDesiredCount(),
		LoginShape:         loginShapeFromProto(req.GetLoginShape()),
		ProviderConfigName: req.GetProviderConfigName(),
		AgentName:          req.GetAgentName(),
		Model:              req.GetModel(),
		MaxJobsInFlight:    req.GetMaxJobsInFlight(),
		StaleLimit:         req.GetStaleLimit().AsDuration(),
		SpillPolicy:        spillPolicyFromProto(req.GetSpillPolicy()),
	}
	if req.GetTenantOwned() {
		in.OwnerKind, in.OwnerID = bank.OwnerTenant, tenant
	} else {
		in.OwnerKind, in.OwnerID = bank.OwnerUser, subject
	}
	// A bank that names no per-member cap takes the agent's own answer. How
	// many jobs one process can hold is something the agent knows and the
	// person creating the bank does not: Claude Code is one conversation at a
	// time, so a second job is a second process.
	if in.AgentName == "" {
		in.AgentName = bank.DefaultAgentName
	}
	if in.MaxJobsInFlight == 0 {
		if entry, ok := componentcatalog.LookupAgent(in.AgentName); ok {
			in.MaxJobsInFlight = entry.MaxJobsInFlight
		}
	}
	if err := s.checkMemberCap(ctx, tenant, in.DesiredCount); err != nil {
		return nil, err
	}

	created, err := s.store.Create(ctx, tenant, in)
	if err != nil {
		return nil, bankStoreError(err)
	}

	// Ownership first, then the parent link. A bank with no ownership tuple is
	// unmanageable, so a failure here is not survivable: remove the row rather
	// than leave one nobody can change or delete.
	if err := s.authorizer.Write(ctx, ownershipTuples(tenant, created)); err != nil {
		if delErr := s.store.Delete(ctx, tenant, created.ID); delErr != nil {
			s.logger.ErrorContext(ctx, "bank ownership tuples failed and the row could not be removed",
				"bank_id", created.ID, "write_error", err, "delete_error", delErr)
		}
		return nil, status.Errorf(codes.Internal, "write bank ownership: %v", err)
	}

	s.logger.InfoContext(ctx, "bank created",
		"bank_id", created.ID, "name", created.Name, "owner_kind", string(created.OwnerKind),
		"desired_count", created.DesiredCount, "login_shape", string(created.LoginShape))
	return &bankpb.CreateBankResponse{Bank: bankToProto(tenant, created)}, nil
}

// GetBank returns one bank.
func (s *bankServer) GetBank(ctx context.Context, req *bankpb.GetBankRequest) (*bankpb.GetBankResponse, error) {
	tenant, err := s.tenant(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, "can_read", req.GetId()); err != nil {
		return nil, err
	}
	b, err := s.store.Get(ctx, tenant, req.GetId())
	if err != nil {
		return nil, bankStoreError(err)
	}
	return &bankpb.GetBankResponse{Bank: bankToProto(tenant, b)}, nil
}

// ListBanks returns one page of the caller tenant's banks, newest first.
func (s *bankServer) ListBanks(ctx context.Context, req *bankpb.ListBanksRequest) (*bankpb.ListBanksResponse, error) {
	tenant, err := s.tenant(ctx)
	if err != nil {
		return nil, err
	}
	banks, next, err := s.store.List(ctx, tenant, bank.Page{Size: req.GetPageSize(), Token: req.GetPageToken()})
	if err != nil {
		return nil, bankStoreError(err)
	}
	out := make([]*bankpb.Bank, 0, len(banks))
	for _, b := range banks {
		out = append(out, bankToProto(tenant, b))
	}
	return &bankpb.ListBanksResponse{Banks: out, NextPageToken: next}, nil
}

// UpdateBank changes the desired count and the policies. A field the request
// leaves unset keeps its value.
func (s *bankServer) UpdateBank(ctx context.Context, req *bankpb.UpdateBankRequest) (*bankpb.UpdateBankResponse, error) {
	tenant, err := s.tenant(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, "owner", req.GetId()); err != nil {
		return nil, err
	}
	in := bank.UpdateInput{
		DesiredCount:    req.DesiredCount,
		MaxJobsInFlight: req.MaxJobsInFlight,
	}
	if req.GetStaleLimit() != nil {
		d := req.GetStaleLimit().AsDuration()
		in.StaleLimit = &d
	}
	if req.SpillPolicy != nil {
		p := spillPolicyFromProto(req.GetSpillPolicy())
		in.SpillPolicy = &p
	}
	if in.DesiredCount != nil {
		if err := s.checkMemberCap(ctx, tenant, *in.DesiredCount); err != nil {
			return nil, err
		}
	}
	updated, err := s.store.Update(ctx, tenant, req.GetId(), in)
	if err != nil {
		return nil, bankStoreError(err)
	}
	s.logger.InfoContext(ctx, "bank updated", "bank_id", updated.ID, "desired_count", updated.DesiredCount)
	return &bankpb.UpdateBankResponse{Bank: bankToProto(tenant, updated)}, nil
}

// DeleteBank removes a bank and its ownership tuples. The reconciler drains
// the running members and closes their jobs as abandoned; this removes the
// record it reconciles against, so removing it is what starts the drain.
func (s *bankServer) DeleteBank(ctx context.Context, req *bankpb.DeleteBankRequest) (*bankpb.DeleteBankResponse, error) {
	tenant, err := s.tenant(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, "owner", req.GetId()); err != nil {
		return nil, err
	}
	b, err := s.store.Get(ctx, tenant, req.GetId())
	if err != nil {
		return nil, bankStoreError(err)
	}
	if err := s.store.Delete(ctx, tenant, b.ID); err != nil {
		return nil, bankStoreError(err)
	}
	// Tuples after the row. A leftover tuple grants a right on an object that
	// no longer exists, which nothing can reach; a leftover row with no tuple
	// would be a bank nobody can manage. Delete in the order whose failure is
	// harmless.
	if err := s.authorizer.Delete(ctx, ownershipTuples(tenant, b)); err != nil {
		s.logger.WarnContext(ctx, "bank deleted but its ownership tuples remain",
			"bank_id", b.ID, "error", err)
	}
	s.logger.InfoContext(ctx, "bank deleted", "bank_id", b.ID, "name", b.Name)
	return &bankpb.DeleteBankResponse{}, nil
}

// ListMembers returns one page of a bank's members with the status each last
// reported.
func (s *bankServer) ListMembers(ctx context.Context, req *bankpb.ListMembersRequest) (*bankpb.ListMembersResponse, error) {
	tenant, err := s.tenant(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, "can_read", req.GetBankId()); err != nil {
		return nil, err
	}
	// Get first, so a bank id the tenant does not have answers NOT_FOUND
	// rather than an empty page, which reads as "a bank with no members".
	if _, err := s.store.Get(ctx, tenant, req.GetBankId()); err != nil {
		return nil, bankStoreError(err)
	}
	members, next, err := s.store.ListMembers(ctx, tenant, req.GetBankId(),
		bank.Page{Size: req.GetPageSize(), Token: req.GetPageToken()})
	if err != nil {
		return nil, bankStoreError(err)
	}
	out := make([]*bankpb.Member, 0, len(members))
	for _, m := range members {
		out = append(out, memberToProto(m))
	}
	return &bankpb.ListMembersResponse{Members: out, NextPageToken: next}, nil
}

// authorize is the per-resource decision the daemon owes for every bank RPC
// whose registry rule derives its object from a request field.
//
// ext-authz cannot make that decision: a field deriver names a value in the
// request body, which the gateway does not decode, so it passes the request
// through and the handler decides (gibson#1245). CreateBank and ListBanks are
// not here on purpose — their rules derive the object from the caller's tenant,
// which ext-authz resolves on its own.
//
// The FGA user mirrors what ext-authz asks: a component's subject is already
// the typed principal and is used verbatim; anything else is a user.
func (s *bankServer) authorize(ctx context.Context, relation, bankID string) error {
	id, err := auth.IdentityFromContext(ctx)
	if err != nil || id.Subject == "" {
		return status.Error(codes.PermissionDenied, "no caller identity in context")
	}
	allowed, err := s.authorizer.Check(ctx, fgaUserFromIdentity(id), relation, "bank:"+bankID)
	if err != nil {
		// An undecidable authorization question is a deny, never a pass.
		s.logger.ErrorContext(ctx, "bank authorization check failed",
			"relation", relation, "bank_id", bankID, "error", err)
		return status.Error(codes.Unavailable, "authorization service unavailable")
	}
	if !allowed {
		// NotFound, not PermissionDenied: a caller with no right on a bank must
		// not learn that the bank exists.
		return status.Error(codes.NotFound, "no such bank")
	}
	return nil
}

// fgaUserFromIdentity maps a caller identity to the FGA user string. A
// component authenticates with a capability grant and its subject is already
// the typed principal ref the model accepts (ADR-0045); the model rejects the
// `user:` type for those, so it is used unchanged.
func fgaUserFromIdentity(id auth.Identity) string {
	for _, prefix := range []string{"agent_principal:", "tool_principal:", "plugin_principal:", "user:"} {
		if strings.HasPrefix(id.Subject, prefix) {
			return id.Subject
		}
	}
	return "user:" + strings.TrimPrefix(id.Subject, "spiffe://")
}

// checkMemberCap refuses a desired count above the tenant's agent ceiling.
//
// The ceiling is entitlements.Limits.ConcurrentAgents, the seam that already
// answers "how many agents may this tenant run at once". A bank of N members
// holds N agents, so a second knob for the same question would be a second
// authority that drifts from the first.
func (s *bankServer) checkMemberCap(ctx context.Context, tenant string, desired int32) error {
	limits, err := s.entitlements.Limits(ctx, tenant)
	if err != nil {
		return status.Errorf(codes.PermissionDenied, "entitlements unavailable: %v", err)
	}
	if limits.ConcurrentAgents > 0 && int(desired) > limits.ConcurrentAgents {
		return status.Errorf(codes.ResourceExhausted,
			"desired_count %d is above this tenant's ceiling of %d concurrent agents",
			desired, limits.ConcurrentAgents)
	}
	return nil
}

// ownershipTuples is what "this bank belongs to this tenant, and this is its
// owner" means in FGA. One function, used by create and delete, so the two can
// never write and remove different sets.
func ownershipTuples(tenant string, b *bank.Bank) []authz.Tuple {
	object := "bank:" + b.ID
	tuples := []authz.Tuple{
		{User: "tenant:" + tenant, Relation: "parent", Object: object},
	}
	if b.OwnerKind == bank.OwnerTenant {
		tuples = append(tuples, authz.Tuple{User: "tenant:" + tenant, Relation: "tenant_owned", Object: object})
		return tuples
	}
	tuples = append(tuples, authz.Tuple{User: "user:" + b.OwnerID, Relation: "owner", Object: object})
	return tuples
}

// bankStoreError maps a store error to the gRPC code a caller can act on.
func bankStoreError(err error) error {
	switch {
	case errors.Is(err, bank.ErrNotFound):
		return status.Error(codes.NotFound, "no such bank")
	case errors.Is(err, bank.ErrAlreadyExists):
		return status.Error(codes.AlreadyExists, err.Error())
	case errors.Is(err, bank.ErrInvalid):
		return status.Error(codes.InvalidArgument, err.Error())
	default:
		return status.Errorf(codes.Internal, "bank store: %v", err)
	}
}

// ---- wire conversion -------------------------------------------------------

func bankToProto(tenant string, b *bank.Bank) *bankpb.Bank {
	return &bankpb.Bank{
		Id:                 b.ID,
		TenantId:           tenant,
		Owner:              ownerToProto(b),
		Name:               b.Name,
		DesiredCount:       b.DesiredCount,
		LoginShape:         loginShapeToProto(b.LoginShape),
		ProviderConfigName: b.ProviderConfigName,
		AgentName:          b.AgentName,
		Model:              b.Model,
		MaxJobsInFlight:    b.MaxJobsInFlight,
		StaleLimit:         durationpb.New(b.StaleLimit),
		SpillPolicy:        spillPolicyToProto(b.SpillPolicy),
		CreatedAt:          timestamppb.New(b.CreatedAt),
		UpdatedAt:          timestamppb.New(b.UpdatedAt),
	}
}

func ownerToProto(b *bank.Bank) *commonpb.Principal {
	kind := commonpb.Principal_KIND_USER
	if b.OwnerKind == bank.OwnerTenant {
		kind = commonpb.Principal_KIND_TENANT
	}
	return &commonpb.Principal{Kind: kind, Id: b.OwnerID}
}

func memberToProto(m *bank.Member) *bankpb.Member {
	out := &bankpb.Member{
		Id:           m.ID,
		BankId:       m.BankID,
		MissionId:    m.MissionID,
		MissionRunId: m.MissionRunID,
		AgentRunId:   m.AgentRunID,
		SandboxId:    m.SandboxID,
		Status: &bankpb.MemberStatus{
			State:         memberStateToProto(m.State),
			JobsInFlight:  m.JobsInFlight,
			Cap:           m.JobCap,
			ActiveJobIds:  m.ActiveJobIDs,
			ClaudeVersion: m.ClaudeVersion,
		},
	}
	if !m.LastHeartbeat.IsZero() {
		out.LastHeartbeat = timestamppb.New(m.LastHeartbeat)
	}
	return out
}

// loginShapeFromProto maps the wire enum to the store value. An unknown value
// maps to the empty shape, which Validate refuses by name — so a new enum
// member the daemon does not know is a clear error, never a silent default.
func loginShapeFromProto(s bankpb.LoginShape) bank.LoginShape {
	switch s {
	case bankpb.LoginShape_LOGIN_SHAPE_SUBSCRIPTION:
		return bank.LoginShapeSubscription
	case bankpb.LoginShape_LOGIN_SHAPE_ANTHROPIC_API_KEY:
		return bank.LoginShapeAPIKey
	case bankpb.LoginShape_LOGIN_SHAPE_BEDROCK:
		return bank.LoginShapeBedrock
	case bankpb.LoginShape_LOGIN_SHAPE_VERTEX:
		return bank.LoginShapeVertex
	case bankpb.LoginShape_LOGIN_SHAPE_FOUNDRY:
		return bank.LoginShapeFoundry
	case bankpb.LoginShape_LOGIN_SHAPE_UNSPECIFIED:
		// A request that names no shape maps to the empty shape, which
		// Validate refuses by name. A default here would pick one for the
		// caller, and picking a login shape is not the daemon's to do.
		return ""
	default:
		return ""
	}
}

func loginShapeToProto(s bank.LoginShape) bankpb.LoginShape {
	switch s {
	case bank.LoginShapeSubscription:
		return bankpb.LoginShape_LOGIN_SHAPE_SUBSCRIPTION
	case bank.LoginShapeAPIKey:
		return bankpb.LoginShape_LOGIN_SHAPE_ANTHROPIC_API_KEY
	case bank.LoginShapeBedrock:
		return bankpb.LoginShape_LOGIN_SHAPE_BEDROCK
	case bank.LoginShapeVertex:
		return bankpb.LoginShape_LOGIN_SHAPE_VERTEX
	case bank.LoginShapeFoundry:
		return bankpb.LoginShape_LOGIN_SHAPE_FOUNDRY
	default:
		return bankpb.LoginShape_LOGIN_SHAPE_UNSPECIFIED
	}
}

// spillPolicyFromProto maps the wire enum. Unspecified means queue, which is
// what the proto says and what a bank does when its owner names nothing.
func spillPolicyFromProto(p bankpb.SpillPolicy) bank.SpillPolicy {
	if p == bankpb.SpillPolicy_SPILL_POLICY_EPHEMERAL {
		return bank.SpillEphemeral
	}
	return bank.SpillQueue
}

func spillPolicyToProto(p bank.SpillPolicy) bankpb.SpillPolicy {
	if p == bank.SpillEphemeral {
		return bankpb.SpillPolicy_SPILL_POLICY_EPHEMERAL
	}
	return bankpb.SpillPolicy_SPILL_POLICY_QUEUE
}

func memberStateToProto(s bank.MemberState) bankpb.MemberState {
	switch s {
	case bank.MemberLaunching:
		return bankpb.MemberState_MEMBER_STATE_LAUNCHING
	case bank.MemberNeedsSignIn:
		return bankpb.MemberState_MEMBER_STATE_NEEDS_SIGN_IN
	case bank.MemberIdle:
		return bankpb.MemberState_MEMBER_STATE_IDLE
	case bank.MemberBusy:
		return bankpb.MemberState_MEMBER_STATE_BUSY
	case bank.MemberDraining:
		return bankpb.MemberState_MEMBER_STATE_DRAINING
	case bank.MemberDead:
		return bankpb.MemberState_MEMBER_STATE_DEAD
	default:
		return bankpb.MemberState_MEMBER_STATE_UNSPECIFIED
	}
}
