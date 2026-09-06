// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/bank"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/liveagents"
	"github.com/zeroroot-ai/gibson/pkg/billing/entitlements"
	bankpb "github.com/zeroroot-ai/sdk/api/gen/gibson/bank/v1"
	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// fakeBankStore is an in-memory bank.Store. It keeps the real validation by
// calling through to CreateInput.Validate, so a test cannot pass an input the
// production store would refuse.
type fakeBankStore struct {
	banks     map[string]*bank.Bank
	members   map[string][]*bank.Member
	createErr error
	getErr    error
	deleteErr error
	deleted   []string
	seq       int
}

func newFakeBankStore() *fakeBankStore {
	return &fakeBankStore{banks: map[string]*bank.Bank{}, members: map[string][]*bank.Member{}}
}

func (f *fakeBankStore) Create(_ context.Context, _ string, in bank.CreateInput) (*bank.Bank, error) {
	if err := in.Validate(); err != nil {
		return nil, fmt.Errorf("fake bank store: %w", err)
	}
	if f.createErr != nil {
		return nil, f.createErr
	}
	for _, b := range f.banks {
		if b.Name == in.Name {
			return nil, bank.ErrAlreadyExists
		}
	}
	f.seq++
	now := time.Now().UTC()
	b := &bank.Bank{
		ID: "bank-" + string(rune('a'+f.seq-1)), Name: in.Name,
		OwnerKind: in.OwnerKind, OwnerID: in.OwnerID, DesiredCount: in.DesiredCount,
		LoginShape: in.LoginShape, ProviderConfigName: in.ProviderConfigName,
		AgentName: in.AgentName, Model: in.Model, MaxJobsInFlight: in.MaxJobsInFlight,
		StaleLimit: in.StaleLimit, SpillPolicy: in.SpillPolicy,
		CreatedAt: now, UpdatedAt: now,
	}
	f.banks[b.ID] = b
	return b, nil
}

func (f *fakeBankStore) Get(_ context.Context, _, id string) (*bank.Bank, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	b, ok := f.banks[id]
	if !ok {
		return nil, bank.ErrNotFound
	}
	return b, nil
}

func (f *fakeBankStore) List(_ context.Context, _ string, _ bank.Page) ([]*bank.Bank, string, error) {
	out := make([]*bank.Bank, 0, len(f.banks))
	for _, b := range f.banks {
		out = append(out, b)
	}
	return out, "", nil
}

func (f *fakeBankStore) Update(_ context.Context, _, id string, in bank.UpdateInput) (*bank.Bank, error) {
	if err := in.Validate(); err != nil {
		return nil, fmt.Errorf("fake bank store: %w", err)
	}
	b, ok := f.banks[id]
	if !ok {
		return nil, bank.ErrNotFound
	}
	if in.DesiredCount != nil {
		b.DesiredCount = *in.DesiredCount
	}
	if in.MaxJobsInFlight != nil {
		b.MaxJobsInFlight = *in.MaxJobsInFlight
	}
	if in.StaleLimit != nil {
		b.StaleLimit = *in.StaleLimit
	}
	if in.SpillPolicy != nil {
		b.SpillPolicy = *in.SpillPolicy
	}
	return b, nil
}

func (f *fakeBankStore) Delete(_ context.Context, _, id string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	if _, ok := f.banks[id]; !ok {
		return bank.ErrNotFound
	}
	delete(f.banks, id)
	f.deleted = append(f.deleted, id)
	return nil
}

func (f *fakeBankStore) GetMember(_ context.Context, _, memberID string) (*bank.Member, error) {
	for _, members := range f.members {
		for _, m := range members {
			if m.ID == memberID {
				return m, nil
			}
		}
	}
	return nil, bank.ErrNotFound
}

func (f *fakeBankStore) MemberByRun(_ context.Context, _, runID string) (*bank.Member, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	for _, members := range f.members {
		for _, m := range members {
			if m.MissionRunID == runID {
				return m, nil
			}
		}
	}
	return nil, bank.ErrNotFound
}

func (f *fakeBankStore) ListAll(_ context.Context, _ string) ([]*bank.Bank, error) {
	out := make([]*bank.Bank, 0, len(f.banks))
	for _, b := range f.banks {
		out = append(out, b)
	}
	return out, nil
}

func (f *fakeBankStore) AddMember(_ context.Context, _ string, m *bank.Member) error {
	f.members[m.BankID] = append(f.members[m.BankID], m)
	return nil
}

func (f *fakeBankStore) UpdateMemberStatus(_ context.Context, _, memberID string, st bank.MemberStatus) (*bank.Member, error) {
	for _, ms := range f.members {
		for _, m := range ms {
			if m.ID == memberID {
				m.State, m.JobsInFlight, m.JobCap = st.State, st.JobsInFlight, st.JobCap
				m.ActiveJobIDs, m.ClaudeVersion = st.ActiveJobIDs, st.ClaudeVersion
				return m, nil
			}
		}
	}
	return nil, bank.ErrNotFound
}

func (f *fakeBankStore) SetMemberState(_ context.Context, _, memberID string, state bank.MemberState) (*bank.Member, error) {
	for _, ms := range f.members {
		for _, m := range ms {
			if m.ID == memberID {
				m.State = state
				return m, nil
			}
		}
	}
	return nil, bank.ErrNotFound
}

func (f *fakeBankStore) RemoveMember(_ context.Context, _, memberID string) error {
	for bankID, ms := range f.members {
		for i, m := range ms {
			if m.ID == memberID {
				f.members[bankID] = append(ms[:i], ms[i+1:]...)
				return nil
			}
		}
	}
	return bank.ErrNotFound
}

func (f *fakeBankStore) ListMembers(_ context.Context, _, bankID string, _ bank.Page) ([]*bank.Member, string, error) {
	return f.members[bankID], "", nil
}

// fakeAuthorizer records the tuples written and deleted, and answers Check
// with a fixed decision. allow defaults to true so a test that is not about
// authorization does not have to seed tuples.
type fakeAuthorizer struct {
	authz.Authorizer
	written  []authz.Tuple
	removed  []authz.Tuple
	writeErr error
	deny     bool
	checkErr error
	checks   []string
}

func (f *fakeAuthorizer) Check(_ context.Context, user, relation, object string) (bool, error) {
	f.checks = append(f.checks, user+"|"+relation+"|"+object)
	if f.checkErr != nil {
		return false, f.checkErr
	}
	return !f.deny, nil
}

func (f *fakeAuthorizer) Write(_ context.Context, tuples []authz.Tuple) error {
	if f.writeErr != nil {
		return f.writeErr
	}
	f.written = append(f.written, tuples...)
	return nil
}

func (f *fakeAuthorizer) Delete(_ context.Context, tuples []authz.Tuple) error {
	f.removed = append(f.removed, tuples...)
	return nil
}

// cappedEntitlements answers one ceiling for every tenant.
type cappedEntitlements struct {
	agents int
	err    error
}

func (c cappedEntitlements) Limits(context.Context, string) (entitlements.Limits, error) {
	return entitlements.Limits{ConcurrentAgents: c.agents}, c.err
}

func bankTestServer(t *testing.T, store bank.Store, az authz.Authorizer, ent entitlements.Provider) bankpb.BankServiceServer {
	t.Helper()
	srv, err := NewBankServer(BankServerConfig{Store: store, Authorizer: az, Entitlements: ent,
		Control: harness.NewMemberControl(), Feed: liveagents.NewRegistry()})
	if err != nil {
		t.Fatalf("NewBankServer: %v", err)
	}
	return srv
}

// bankCtx puts a tenant and a caller identity on the context, the way
// ext-authz's headers reach a handler.
func bankCtx(t *testing.T, tenant, subject string) context.Context {
	t.Helper()
	tid, err := auth.NewTenantID(tenant)
	if err != nil {
		t.Fatalf("NewTenantID: %v", err)
	}
	ctx := auth.ContextWithTenant(context.Background(), tid)
	return auth.WithIdentity(ctx, auth.Identity{
		Subject: subject, Tenant: tid, Issuer: auth.IssuerOIDC, CredentialType: auth.CredentialOIDCUser,
	})
}

func apiKeyBank(name string) *bankpb.CreateBankRequest {
	return &bankpb.CreateBankRequest{
		Name:               name,
		DesiredCount:       2,
		LoginShape:         bankpb.LoginShape_LOGIN_SHAPE_ANTHROPIC_API_KEY,
		ProviderConfigName: "tenant-anthropic",
	}
}

func TestNewBankServer_RequiresAStoreAndAnAuthorizer(t *testing.T) {
	if _, err := NewBankServer(BankServerConfig{Store: newFakeBankStore(), Authorizer: &fakeAuthorizer{}, Feed: liveagents.NewRegistry()}); err == nil {
		t.Error("a bank service with no control queue must be refused")
	}
	if _, err := NewBankServer(BankServerConfig{Store: newFakeBankStore(), Authorizer: &fakeAuthorizer{}, Control: harness.NewMemberControl()}); err == nil {
		t.Error("a bank service with no feed must be refused")
	}
	if _, err := NewBankServer(BankServerConfig{Authorizer: &fakeAuthorizer{}, Control: harness.NewMemberControl(), Feed: liveagents.NewRegistry()}); err == nil {
		t.Error("a server with no store must not be constructible")
	}
	if _, err := NewBankServer(BankServerConfig{Store: newFakeBankStore()}); err == nil {
		t.Error("a server with no authorizer must not be constructible: the bank would carry no ownership tuple")
	}
}

func TestCreateBank_StoresTheBankAndItsOwnership(t *testing.T) {
	store, az := newFakeBankStore(), &fakeAuthorizer{}
	srv := bankTestServer(t, store, az, nil)

	resp, err := srv.CreateBank(bankCtx(t, "acme", "alice"), apiKeyBank("nightly"))
	if err != nil {
		t.Fatalf("CreateBank: %v", err)
	}
	got := resp.GetBank()
	if got.GetName() != "nightly" || got.GetTenantId() != "acme" {
		t.Fatalf("bank = %+v", got)
	}
	if got.GetOwner().GetKind() != commonpb.Principal_KIND_USER || got.GetOwner().GetId() != "alice" {
		t.Fatalf("owner = %+v, want the caller as a person", got.GetOwner())
	}
	if got.GetAgentName() != bank.DefaultAgentName || got.GetMaxJobsInFlight() != bank.DefaultMaxJobsInFlight {
		t.Errorf("defaults not filled: agent=%q cap=%d", got.GetAgentName(), got.GetMaxJobsInFlight())
	}
	if got.GetSpillPolicy() != bankpb.SpillPolicy_SPILL_POLICY_QUEUE {
		t.Errorf("spill policy = %v, want queue by default", got.GetSpillPolicy())
	}
	wantTuples := map[string]string{"parent": "tenant:acme", "owner": "user:alice"}
	if len(az.written) != 2 {
		t.Fatalf("tuples = %+v, want a parent and an owner", az.written)
	}
	for _, tp := range az.written {
		if wantTuples[tp.Relation] != tp.User || tp.Object != "bank:"+got.GetId() {
			t.Errorf("unexpected tuple %+v", tp)
		}
	}
}

func TestCreateBank_TenantOwnedNamesTheTenant(t *testing.T) {
	store, az := newFakeBankStore(), &fakeAuthorizer{}
	srv := bankTestServer(t, store, az, nil)

	req := apiKeyBank("shared")
	req.TenantOwned = true
	resp, err := srv.CreateBank(bankCtx(t, "acme", "alice"), req)
	if err != nil {
		t.Fatalf("CreateBank: %v", err)
	}
	if resp.GetBank().GetOwner().GetKind() != commonpb.Principal_KIND_TENANT {
		t.Fatalf("owner = %+v, want the tenant", resp.GetBank().GetOwner())
	}
	var sawTenantOwned bool
	for _, tp := range az.written {
		if tp.Relation == "tenant_owned" && tp.User == "tenant:acme" {
			sawTenantOwned = true
		}
		if tp.Relation == "owner" {
			t.Errorf("a tenant-owned bank must not carry a personal owner tuple: %+v", tp)
		}
	}
	if !sawTenantOwned {
		t.Errorf("tuples = %+v, want tenant_owned", az.written)
	}
}

func TestCreateBank_SubscriptionNeedsAPerson(t *testing.T) {
	srv := bankTestServer(t, newFakeBankStore(), &fakeAuthorizer{}, nil)
	req := &bankpb.CreateBankRequest{
		Name: "mine", TenantOwned: true,
		LoginShape: bankpb.LoginShape_LOGIN_SHAPE_SUBSCRIPTION,
	}
	_, err := srv.CreateBank(bankCtx(t, "acme", "alice"), req)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("err = %v, want InvalidArgument: a subscription belongs to a person", err)
	}
}

func TestCreateBank_ThirdPartyShapeNeedsAProviderConfig(t *testing.T) {
	srv := bankTestServer(t, newFakeBankStore(), &fakeAuthorizer{}, nil)
	req := &bankpb.CreateBankRequest{
		Name: "aws", LoginShape: bankpb.LoginShape_LOGIN_SHAPE_BEDROCK,
	}
	_, err := srv.CreateBank(bankCtx(t, "acme", "alice"), req)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("err = %v, want InvalidArgument: no provider configuration means no credential", err)
	}
}

func TestCreateBank_UnknownLoginShapeIsRefused(t *testing.T) {
	srv := bankTestServer(t, newFakeBankStore(), &fakeAuthorizer{}, nil)
	req := &bankpb.CreateBankRequest{Name: "x", LoginShape: bankpb.LoginShape(99)}
	_, err := srv.CreateBank(bankCtx(t, "acme", "alice"), req)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("err = %v, want InvalidArgument for an unknown shape", err)
	}
}

func TestCreateBank_AboveTheTenantCeilingIsRefused(t *testing.T) {
	srv := bankTestServer(t, newFakeBankStore(), &fakeAuthorizer{}, cappedEntitlements{agents: 1})
	_, err := srv.CreateBank(bankCtx(t, "acme", "alice"), apiKeyBank("big"))
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("err = %v, want ResourceExhausted for two members under a ceiling of one", err)
	}
}

func TestCreateBank_RemovesTheRowWhenOwnershipCannotBeWritten(t *testing.T) {
	store := newFakeBankStore()
	az := &fakeAuthorizer{writeErr: errors.New("fga down")}
	srv := bankTestServer(t, store, az, nil)

	_, err := srv.CreateBank(bankCtx(t, "acme", "alice"), apiKeyBank("orphan"))
	if status.Code(err) != codes.Internal {
		t.Fatalf("err = %v, want Internal", err)
	}
	if len(store.banks) != 0 {
		t.Fatalf("a bank nobody can manage must not survive: %+v", store.banks)
	}
}

func TestCreateBank_NeedsATenantAndACaller(t *testing.T) {
	srv := bankTestServer(t, newFakeBankStore(), &fakeAuthorizer{}, nil)
	if _, err := srv.CreateBank(context.Background(), apiKeyBank("x")); status.Code(err) != codes.PermissionDenied {
		t.Errorf("no tenant must be PermissionDenied, got %v", err)
	}
	tid, _ := auth.NewTenantID("acme")
	tenantOnly := auth.ContextWithTenant(context.Background(), tid)
	if _, err := srv.CreateBank(tenantOnly, apiKeyBank("x")); status.Code(err) != codes.PermissionDenied {
		t.Errorf("no caller identity must be PermissionDenied, got %v", err)
	}
}

func TestGetBank_ReturnsTheBank(t *testing.T) {
	store, az := newFakeBankStore(), &fakeAuthorizer{}
	srv := bankTestServer(t, store, az, nil)
	ctx := bankCtx(t, "acme", "alice")
	created, err := srv.CreateBank(ctx, apiKeyBank("nightly"))
	if err != nil {
		t.Fatal(err)
	}

	got, err := srv.GetBank(ctx, &bankpb.GetBankRequest{Id: created.GetBank().GetId()})
	if err != nil {
		t.Fatalf("GetBank: %v", err)
	}
	if got.GetBank().GetName() != "nightly" {
		t.Fatalf("bank = %+v", got.GetBank())
	}
}

func TestGetBank_UnknownIdIsNotFound(t *testing.T) {
	srv := bankTestServer(t, newFakeBankStore(), &fakeAuthorizer{}, nil)
	_, err := srv.GetBank(bankCtx(t, "acme", "alice"), &bankpb.GetBankRequest{Id: "nope"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("err = %v, want NotFound", err)
	}
}

func TestListBanks_ReturnsThePage(t *testing.T) {
	store, az := newFakeBankStore(), &fakeAuthorizer{}
	srv := bankTestServer(t, store, az, nil)
	ctx := bankCtx(t, "acme", "alice")
	if _, err := srv.CreateBank(ctx, apiKeyBank("one")); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.CreateBank(ctx, apiKeyBank("two")); err != nil {
		t.Fatal(err)
	}

	resp, err := srv.ListBanks(ctx, &bankpb.ListBanksRequest{})
	if err != nil {
		t.Fatalf("ListBanks: %v", err)
	}
	if len(resp.GetBanks()) != 2 {
		t.Fatalf("banks = %d, want 2", len(resp.GetBanks()))
	}
}

func TestUpdateBank_ChangesOnlyWhatIsSet(t *testing.T) {
	store, az := newFakeBankStore(), &fakeAuthorizer{}
	srv := bankTestServer(t, store, az, nil)
	ctx := bankCtx(t, "acme", "alice")
	created, err := srv.CreateBank(ctx, apiKeyBank("nightly"))
	if err != nil {
		t.Fatal(err)
	}
	id := created.GetBank().GetId()

	four := int32(4)
	resp, err := srv.UpdateBank(ctx, &bankpb.UpdateBankRequest{
		Id: id, DesiredCount: &four, StaleLimit: durationpb.New(90 * time.Minute),
	})
	if err != nil {
		t.Fatalf("UpdateBank: %v", err)
	}
	got := resp.GetBank()
	if got.GetDesiredCount() != 4 {
		t.Errorf("desired count = %d, want 4", got.GetDesiredCount())
	}
	if got.GetStaleLimit().AsDuration() != 90*time.Minute {
		t.Errorf("stale limit = %s, want 90m", got.GetStaleLimit().AsDuration())
	}
	if got.GetProviderConfigName() != "tenant-anthropic" {
		t.Errorf("an unset field must keep its value, got %q", got.GetProviderConfigName())
	}
}

func TestUpdateBank_AboveTheTenantCeilingIsRefused(t *testing.T) {
	store, az := newFakeBankStore(), &fakeAuthorizer{}
	srv := bankTestServer(t, store, az, cappedEntitlements{agents: 2})
	ctx := bankCtx(t, "acme", "alice")
	created, err := srv.CreateBank(ctx, apiKeyBank("nightly"))
	if err != nil {
		t.Fatal(err)
	}
	ten := int32(10)
	_, err = srv.UpdateBank(ctx, &bankpb.UpdateBankRequest{Id: created.GetBank().GetId(), DesiredCount: &ten})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("err = %v, want ResourceExhausted", err)
	}
}

func TestUpdateBank_UnknownIdIsNotFound(t *testing.T) {
	srv := bankTestServer(t, newFakeBankStore(), &fakeAuthorizer{}, nil)
	one := int32(1)
	_, err := srv.UpdateBank(bankCtx(t, "acme", "alice"), &bankpb.UpdateBankRequest{Id: "nope", DesiredCount: &one})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("err = %v, want NotFound", err)
	}
}

func TestDeleteBank_RemovesTheRowAndItsTuples(t *testing.T) {
	store, az := newFakeBankStore(), &fakeAuthorizer{}
	srv := bankTestServer(t, store, az, nil)
	ctx := bankCtx(t, "acme", "alice")
	created, err := srv.CreateBank(ctx, apiKeyBank("nightly"))
	if err != nil {
		t.Fatal(err)
	}
	id := created.GetBank().GetId()

	if _, err := srv.DeleteBank(ctx, &bankpb.DeleteBankRequest{Id: id}); err != nil {
		t.Fatalf("DeleteBank: %v", err)
	}
	if len(store.banks) != 0 {
		t.Errorf("bank row survived the delete")
	}
	if len(az.removed) != 2 {
		t.Errorf("removed tuples = %+v, want the parent and the owner", az.removed)
	}
}

func TestDeleteBank_UnknownIdIsNotFound(t *testing.T) {
	srv := bankTestServer(t, newFakeBankStore(), &fakeAuthorizer{}, nil)
	_, err := srv.DeleteBank(bankCtx(t, "acme", "alice"), &bankpb.DeleteBankRequest{Id: "nope"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("err = %v, want NotFound", err)
	}
}

func TestListMembers_ReturnsTheReportedStatus(t *testing.T) {
	store, az := newFakeBankStore(), &fakeAuthorizer{}
	srv := bankTestServer(t, store, az, nil)
	ctx := bankCtx(t, "acme", "alice")
	created, err := srv.CreateBank(ctx, apiKeyBank("nightly"))
	if err != nil {
		t.Fatal(err)
	}
	id := created.GetBank().GetId()
	store.members[id] = []*bank.Member{{
		ID: "m-1", BankID: id, State: bank.MemberBusy, JobsInFlight: 1, JobCap: 1,
		ActiveJobIDs: []string{"job-1"}, ClaudeVersion: "2.0.1", LastHeartbeat: time.Now().UTC(),
	}}

	resp, err := srv.ListMembers(ctx, &bankpb.ListMembersRequest{BankId: id})
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	if len(resp.GetMembers()) != 1 {
		t.Fatalf("members = %d, want 1", len(resp.GetMembers()))
	}
	m := resp.GetMembers()[0]
	if m.GetStatus().GetState() != bankpb.MemberState_MEMBER_STATE_BUSY {
		t.Errorf("state = %v, want busy", m.GetStatus().GetState())
	}
	if m.GetStatus().GetCap() != 1 || m.GetStatus().GetJobsInFlight() != 1 {
		t.Errorf("status = %+v", m.GetStatus())
	}
	if m.GetLastHeartbeat() == nil {
		t.Error("a member that reported must carry its heartbeat time")
	}
}

// TestGetBank_WithoutTheRightIsNotFound: the registry rule for GetBank derives
// its object from a request field, so ext-authz passes the call through and the
// handler owes the per-resource decision (gibson#1245). A caller with no right
// gets NotFound, never a hint that the bank exists.
func TestGetBank_WithoutTheRightIsNotFound(t *testing.T) {
	store, az := newFakeBankStore(), &fakeAuthorizer{}
	srv := bankTestServer(t, store, az, nil)
	ctx := bankCtx(t, "acme", "alice")
	created, err := srv.CreateBank(ctx, apiKeyBank("nightly"))
	if err != nil {
		t.Fatal(err)
	}
	az.deny = true

	_, err = srv.GetBank(ctx, &bankpb.GetBankRequest{Id: created.GetBank().GetId()})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("err = %v, want NotFound", err)
	}
	if len(az.checks) == 0 || !strings.Contains(az.checks[0], "user:alice|can_read|bank:") {
		t.Fatalf("checks = %v, want a can_read question about this bank", az.checks)
	}
}

// TestUpdateBank_WithoutOwnershipIsNotFound: managing a bank asks the owner
// relation, and the row is never touched when the answer is no.
func TestUpdateBank_WithoutOwnershipIsNotFound(t *testing.T) {
	store, az := newFakeBankStore(), &fakeAuthorizer{}
	srv := bankTestServer(t, store, az, nil)
	ctx := bankCtx(t, "acme", "alice")
	created, err := srv.CreateBank(ctx, apiKeyBank("nightly"))
	if err != nil {
		t.Fatal(err)
	}
	id := created.GetBank().GetId()
	az.deny = true

	nine := int32(9)
	if _, err := srv.UpdateBank(ctx, &bankpb.UpdateBankRequest{Id: id, DesiredCount: &nine}); status.Code(err) != codes.NotFound {
		t.Fatalf("err = %v, want NotFound", err)
	}
	if store.banks[id].DesiredCount != 2 {
		t.Errorf("a refused update must not change the row, got desired count %d", store.banks[id].DesiredCount)
	}
	var sawOwnerCheck bool
	for _, c := range az.checks {
		if strings.Contains(c, "|owner|bank:") {
			sawOwnerCheck = true
		}
	}
	if !sawOwnerCheck {
		t.Errorf("checks = %v, want an owner question", az.checks)
	}
}

// TestDeleteBank_WithoutOwnershipLeavesTheRow: a refused delete must leave the
// bank exactly as it was.
func TestDeleteBank_WithoutOwnershipLeavesTheRow(t *testing.T) {
	store, az := newFakeBankStore(), &fakeAuthorizer{}
	srv := bankTestServer(t, store, az, nil)
	ctx := bankCtx(t, "acme", "alice")
	created, err := srv.CreateBank(ctx, apiKeyBank("nightly"))
	if err != nil {
		t.Fatal(err)
	}
	az.deny = true

	if _, err := srv.DeleteBank(ctx, &bankpb.DeleteBankRequest{Id: created.GetBank().GetId()}); status.Code(err) != codes.NotFound {
		t.Fatalf("err = %v, want NotFound", err)
	}
	if len(store.banks) != 1 {
		t.Error("a refused delete must leave the bank")
	}
}

// TestGetBank_AuthorizationOutageIsUnavailable: an undecidable authorization
// question is a deny, and it says so as an outage rather than as a missing
// bank, so an operator can tell the two apart.
func TestGetBank_AuthorizationOutageIsUnavailable(t *testing.T) {
	store, az := newFakeBankStore(), &fakeAuthorizer{}
	srv := bankTestServer(t, store, az, nil)
	ctx := bankCtx(t, "acme", "alice")
	created, err := srv.CreateBank(ctx, apiKeyBank("nightly"))
	if err != nil {
		t.Fatal(err)
	}
	az.checkErr = errors.New("fga down")

	if _, err := srv.GetBank(ctx, &bankpb.GetBankRequest{Id: created.GetBank().GetId()}); status.Code(err) != codes.Unavailable {
		t.Fatalf("err = %v, want Unavailable", err)
	}
}

func TestListMembers_UnknownBankIsNotFound(t *testing.T) {
	srv := bankTestServer(t, newFakeBankStore(), &fakeAuthorizer{}, nil)
	_, err := srv.ListMembers(bankCtx(t, "acme", "alice"), &bankpb.ListMembersRequest{BankId: "nope"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("err = %v, want NotFound, never an empty page that reads as a bank with no members", err)
	}
}

// TestBankEnums_RoundTripEveryNamedValue asserts that every login shape,
// spill policy and member state survives the wire mapping in both directions,
// and that the unspecified wire values map to what the proto documents: the
// empty shape (which Validate refuses) and the queue spill policy.
func TestBankEnums_RoundTripEveryNamedValue(t *testing.T) {
	shapes := map[bankpb.LoginShape]bank.LoginShape{
		bankpb.LoginShape_LOGIN_SHAPE_SUBSCRIPTION:      bank.LoginShapeSubscription,
		bankpb.LoginShape_LOGIN_SHAPE_ANTHROPIC_API_KEY: bank.LoginShapeAPIKey,
		bankpb.LoginShape_LOGIN_SHAPE_BEDROCK:           bank.LoginShapeBedrock,
		bankpb.LoginShape_LOGIN_SHAPE_VERTEX:            bank.LoginShapeVertex,
		bankpb.LoginShape_LOGIN_SHAPE_FOUNDRY:           bank.LoginShapeFoundry,
	}
	for wire, domain := range shapes {
		if got := loginShapeFromProto(wire); got != domain {
			t.Errorf("loginShapeFromProto(%v) = %q, want %q", wire, got, domain)
		}
		if got := loginShapeToProto(domain); got != wire {
			t.Errorf("loginShapeToProto(%q) = %v, want %v", domain, got, wire)
		}
	}
	if got := loginShapeFromProto(bankpb.LoginShape_LOGIN_SHAPE_UNSPECIFIED); got != "" {
		t.Errorf("an unspecified shape must map to the empty shape, got %q", got)
	}
	if got := loginShapeFromProto(bankpb.LoginShape(99)); got != "" {
		t.Errorf("an unknown wire value must map to the empty shape, got %q", got)
	}
	if got := loginShapeToProto(bank.LoginShape("")); got != bankpb.LoginShape_LOGIN_SHAPE_UNSPECIFIED {
		t.Errorf("the empty shape must map to unspecified, got %v", got)
	}

	if got := spillPolicyFromProto(bankpb.SpillPolicy_SPILL_POLICY_UNSPECIFIED); got != bank.SpillQueue {
		t.Errorf("an unspecified spill policy must mean queue, got %q", got)
	}
	if got := spillPolicyFromProto(bankpb.SpillPolicy_SPILL_POLICY_EPHEMERAL); got != bank.SpillEphemeral {
		t.Errorf("spillPolicyFromProto(ephemeral) = %q", got)
	}
	if got := spillPolicyToProto(bank.SpillEphemeral); got != bankpb.SpillPolicy_SPILL_POLICY_EPHEMERAL {
		t.Errorf("spillPolicyToProto(ephemeral) = %v", got)
	}
	if got := spillPolicyToProto(bank.SpillQueue); got != bankpb.SpillPolicy_SPILL_POLICY_QUEUE {
		t.Errorf("spillPolicyToProto(queue) = %v", got)
	}

	states := map[bank.MemberState]bankpb.MemberState{
		bank.MemberLaunching:   bankpb.MemberState_MEMBER_STATE_LAUNCHING,
		bank.MemberNeedsSignIn: bankpb.MemberState_MEMBER_STATE_NEEDS_SIGN_IN,
		bank.MemberIdle:        bankpb.MemberState_MEMBER_STATE_IDLE,
		bank.MemberBusy:        bankpb.MemberState_MEMBER_STATE_BUSY,
		bank.MemberDraining:    bankpb.MemberState_MEMBER_STATE_DRAINING,
		bank.MemberDead:        bankpb.MemberState_MEMBER_STATE_DEAD,
	}
	for domain, wire := range states {
		if got := memberStateToProto(domain); got != wire {
			t.Errorf("memberStateToProto(%q) = %v, want %v", domain, got, wire)
		}
	}
	if got := memberStateToProto(bank.MemberState("")); got != bankpb.MemberState_MEMBER_STATE_UNSPECIFIED {
		t.Errorf("an unknown state must map to unspecified, got %v", got)
	}
}
