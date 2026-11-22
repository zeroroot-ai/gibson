// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/componentcatalog"
	"github.com/zeroroot-ai/gibson/internal/platform/loopgrantstore"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// memLoopStore keeps one table for each tenant, as the per-tenant database does.
type memLoopStore struct {
	byTenant map[string]map[string]loopgrantstore.Grant
	// err makes each method fail. getErr makes Get fail alone, deleteErr Delete,
	// and putErrAfter makes the Put after that many Puts fail.
	err, getErr, deleteErr error
	puts                   int
	failPutFrom            int
}

func newMemLoopStore() *memLoopStore {
	return &memLoopStore{byTenant: map[string]map[string]loopgrantstore.Grant{}}
}

func (m *memLoopStore) table(t string) map[string]loopgrantstore.Grant {
	if m.byTenant[t] == nil {
		m.byTenant[t] = map[string]loopgrantstore.Grant{}
	}
	return m.byTenant[t]
}

func (m *memLoopStore) Put(_ context.Context, t string, g loopgrantstore.Grant) (*loopgrantstore.Grant, error) {
	if m.err != nil {
		return nil, m.err
	}
	m.puts++
	if m.failPutFrom > 0 && m.puts >= m.failPutFrom {
		return nil, errors.New("put down")
	}
	if g.GrantedAt.IsZero() {
		g.GrantedAt = time.Unix(int64(m.puts), 0).UTC()
	}
	m.table(t)[g.MemberID] = g
	return &g, nil
}

func (m *memLoopStore) Get(_ context.Context, t, member string) (*loopgrantstore.Grant, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	g, ok := m.table(t)[member]
	if !ok {
		return nil, loopgrantstore.ErrNotFound
	}
	return &g, nil
}

func (m *memLoopStore) ListPage(_ context.Context, t, after string, hasAfter bool, limit int) ([]loopgrantstore.Grant, error) {
	if m.err != nil {
		return nil, m.err
	}
	names := make([]string, 0, len(m.table(t)))
	for name := range m.table(t) {
		if !hasAfter || name > after {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	out := make([]loopgrantstore.Grant, 0, limit)
	for _, name := range names {
		if len(out) < limit {
			out = append(out, m.table(t)[name])
		}
	}
	return out, nil
}

func (m *memLoopStore) Delete(_ context.Context, t, member string) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.table(t), member)
	return nil
}

// fakeLoopMembers is the bank store: each tenant has its own members.
type fakeLoopMembers struct {
	agents map[string]map[string]string // tenant -> member -> agent
	err    error
}

func (f fakeLoopMembers) AgentOfMember(_ context.Context, tenant, member string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	agent, ok := f.agents[tenant][member]
	if !ok {
		return "", ErrLoopMemberNotFound
	}
	return agent, nil
}

type loopAuditRec struct {
	action, resourceID string
	details            map[string]any
	actor              string
}

type fakeLoopAudit struct {
	recs []loopAuditRec
	err  error
}

func (f *fakeLoopAudit) Record(ctx context.Context, action, _, resourceID string, details map[string]any) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	id, _ := auth.IdentityFromContext(ctx)
	f.recs = append(f.recs, loopAuditRec{action: action, resourceID: resourceID, details: details, actor: id.Subject})
	return "rec", nil
}

func loopAgents(id string) (componentcatalog.AgentEntry, bool) {
	switch id {
	case "intake-agent":
		return componentcatalog.AgentEntry{
			ID: id, MemberCommand: []string{"node", "member.js"}, LoopGrantClasses: []string{"ticket", "paging", "siem"},
		}, true
	case "one-shot":
		return componentcatalog.AgentEntry{ID: id}, true
	}
	return componentcatalog.AgentEntry{}, false
}

func loopCtx(t *testing.T, tenant, subject string) context.Context {
	t.Helper()
	tid, err := auth.NewTenantID(tenant)
	require.NoError(t, err)
	ctx := auth.ContextWithTenantString(context.Background(), tenant)
	return auth.WithIdentity(ctx, auth.Identity{Subject: subject, Tenant: tid, CredentialType: auth.CredentialOIDCUser})
}

const (
	tenantA = "tenant-a"
	tenantB = "tenant-b"
)

func newLoopSvc(t *testing.T) (*LoopGrantService, *memLoopStore, *fakeLoopAudit) {
	t.Helper()
	st, au := newMemLoopStore(), &fakeLoopAudit{}
	members := fakeLoopMembers{agents: map[string]map[string]string{
		tenantA: {"m-1": "intake-agent", "m-2": "intake-agent", "m-3": "one-shot", "m-4": "ghost"},
		tenantB: {"m-9": "intake-agent"},
	}}
	svc, err := NewLoopGrantService(st, members, au, loopAgents, []string{"SubmitFinding"}, testPageKeys(t))
	require.NoError(t, err)
	return svc, st, au
}

func loopGrantReq(member string, classes ...string) *tenantv1.GrantLoopRequest {
	return &tenantv1.GrantLoopRequest{MemberId: member, ToolClasses: classes}
}

func TestGrantLoop_StoresTheGrantOfOneMemberAndAuditsTheGrantor(t *testing.T) {
	svc, st, au := newLoopSvc(t)
	resp, err := svc.GrantLoop(loopCtx(t, tenantA, "user:alice"), &tenantv1.GrantLoopRequest{
		MemberId: "m-1", ToolClasses: []string{"ticket", "paging", "ticket"}, HarnessCalls: []string{"SubmitFinding"},
	})
	require.NoError(t, err)
	g := resp.GetGrant()
	assert.NotEmpty(t, g.GetId())
	assert.Equal(t, "m-1", g.GetMemberId())
	assert.Equal(t, "intake-agent", g.GetAgentName())
	assert.Equal(t, []string{"ticket", "paging"}, g.GetToolClasses())
	assert.Equal(t, "user:alice", g.GetGrantor())

	stored, err := st.Get(context.Background(), tenantA, "m-1")
	require.NoError(t, err)
	assert.Equal(t, g.GetId(), stored.ID)

	// Another member of the same agent holds nothing.
	_, err = st.Get(context.Background(), tenantA, "m-2")
	require.ErrorIs(t, err, loopgrantstore.ErrNotFound)

	require.Len(t, au.recs, 1)
	assert.Equal(t, loopGrantAuditGrant, au.recs[0].action)
	assert.Equal(t, "m-1", au.recs[0].resourceID)
	assert.Equal(t, "user:alice", au.recs[0].actor)
	assert.Equal(t, g.GetId(), au.recs[0].details["loop_grant_id"])
	assert.Equal(t, "user:alice", au.recs[0].details["grantor"])
}

func TestGrantLoop_Refusals(t *testing.T) {
	svc, _, _ := newLoopSvc(t)
	ctx := loopCtx(t, tenantA, "user:alice")
	for name, tc := range map[string]struct {
		req  *tenantv1.GrantLoopRequest
		code codes.Code
	}{
		"a member of another tenant":         {loopGrantReq("m-9", "ticket"), codes.NotFound},
		"a member that does not exist":       {loopGrantReq("m-404", "ticket"), codes.NotFound},
		"a member whose agent is not listed": {loopGrantReq("m-4", "ticket"), codes.NotFound},
		"an agent with no member command":    {loopGrantReq("m-3", "ticket"), codes.FailedPrecondition},
		"an unknown class":                   {loopGrantReq("m-1", "toaster"), codes.InvalidArgument},
		"a class the manifest does not name": {loopGrantReq("m-1", "edr"), codes.PermissionDenied},
		"an ungrantable harness call": {&tenantv1.GrantLoopRequest{
			MemberId: "m-1", HarnessCalls: []string{"GetCredential"},
		}, codes.InvalidArgument},
		"an empty grant":     {loopGrantReq("m-1"), codes.InvalidArgument},
		"a bad member id":    {loopGrantReq("bad id!", "ticket"), codes.InvalidArgument},
		"an empty member id": {loopGrantReq("", "ticket"), codes.InvalidArgument},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := svc.GrantLoop(ctx, tc.req)
			require.Error(t, err)
			assert.Equal(t, tc.code, status.Code(err))
		})
	}
}

func TestGrantLoop_NoStandingGrantWithoutItsAuditRecordAndAGrantThatWorkedIsKept(t *testing.T) {
	svc, st, au := newLoopSvc(t)
	ctx := loopCtx(t, tenantA, "user:alice")

	// No prior grant: the failed audit write leaves no row.
	au.err = errors.New("audit down")
	_, err := svc.GrantLoop(ctx, loopGrantReq("m-1", "ticket"))
	assert.Equal(t, codes.Unavailable, status.Code(err))
	_, gerr := st.Get(context.Background(), tenantA, "m-1")
	require.ErrorIs(t, gerr, loopgrantstore.ErrNotFound)

	// A prior grant that worked: the failed audit write of a second grant puts the
	// first grant back, with its id, its classes and its time.
	au.err = nil
	first, err := svc.GrantLoop(ctx, loopGrantReq("m-1", "ticket"))
	require.NoError(t, err)
	au.err = errors.New("audit down")
	_, err = svc.GrantLoop(ctx, loopGrantReq("m-1", "paging", "siem"))
	assert.Equal(t, codes.Unavailable, status.Code(err))
	kept, gerr := st.Get(context.Background(), tenantA, "m-1")
	require.NoError(t, gerr)
	assert.Equal(t, first.GetGrant().GetId(), kept.ID)
	assert.Equal(t, []string{"ticket"}, kept.ToolClasses)
	assert.Equal(t, first.GetGrant().GetGrantedAt().AsTime(), kept.GrantedAt)

	// A restore that fails says so.
	st.failPutFrom = st.puts + 2
	_, err = svc.GrantLoop(ctx, loopGrantReq("m-1", "paging"))
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestRevokeLoop_RemovesAndAuditsAndIsIdempotent(t *testing.T) {
	svc, st, au := newLoopSvc(t)
	ctx := loopCtx(t, tenantA, "user:alice")
	_, err := svc.GrantLoop(ctx, loopGrantReq("m-1", "ticket"))
	require.NoError(t, err)
	_, err = svc.RevokeLoop(ctx, &tenantv1.RevokeLoopRequest{MemberId: "m-1"})
	require.NoError(t, err)
	_, err = svc.RevokeLoop(ctx, &tenantv1.RevokeLoopRequest{MemberId: "m-1"})
	require.NoError(t, err)
	_, gerr := st.Get(context.Background(), tenantA, "m-1")
	require.ErrorIs(t, gerr, loopgrantstore.ErrNotFound)
	assert.Equal(t, loopGrantAuditRevoke, au.recs[1].action)
}

// An admin of tenant B neither lists nor revokes the grant of tenant A.
func TestListLoopGrants_AreTenantScoped(t *testing.T) {
	svc, st, _ := newLoopSvc(t)
	_, err := svc.GrantLoop(loopCtx(t, tenantA, "user:alice"), loopGrantReq("m-1", "ticket"))
	require.NoError(t, err)

	bCtx := loopCtx(t, tenantB, "user:bob")
	list, err := svc.ListLoopGrants(bCtx, &tenantv1.ListLoopGrantsRequest{})
	require.NoError(t, err)
	assert.Empty(t, list.GetGrants())

	_, err = svc.RevokeLoop(bCtx, &tenantv1.RevokeLoopRequest{MemberId: "m-1"})
	require.NoError(t, err)
	_, gerr := st.Get(context.Background(), tenantA, "m-1")
	assert.NoError(t, gerr, "the revoke of tenant B must leave the grant of tenant A")
}

func TestGrantLoop_RefusesNoTenantAndNoIdentity(t *testing.T) {
	svc, _, _ := newLoopSvc(t)
	_, err := svc.GrantLoop(context.Background(), loopGrantReq("m-1", "ticket"))
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	_, err = svc.GrantLoop(loopCtx(t, tenantA, ""), loopGrantReq("m-1", "ticket"))
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestListLoopGrants_ReturnsTheGrantsOfTheTenant(t *testing.T) {
	svc, _, _ := newLoopSvc(t)
	ctx := loopCtx(t, tenantA, "user:alice")
	_, err := svc.GrantLoop(ctx, loopGrantReq("m-1", "ticket"))
	require.NoError(t, err)
	list, err := svc.ListLoopGrants(ctx, &tenantv1.ListLoopGrantsRequest{})
	require.NoError(t, err)
	require.Len(t, list.GetGrants(), 1)
	assert.Equal(t, "m-1", list.GetGrants()[0].GetMemberId())
}

func TestListLoopGrants_RefusesNoTenant(t *testing.T) {
	svc, _, _ := newLoopSvc(t)
	_, err := svc.ListLoopGrants(context.Background(), &tenantv1.ListLoopGrantsRequest{})
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestRevokeLoop_RefusesABadMemberID(t *testing.T) {
	svc, _, _ := newLoopSvc(t)
	_, err := svc.RevokeLoop(loopCtx(t, tenantA, "user:alice"), &tenantv1.RevokeLoopRequest{MemberId: "bad id!"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestListLoopGrants_PagesWithAKeysetToken(t *testing.T) {
	svc, st, _ := newLoopSvc(t)
	ctx := loopCtx(t, tenantA, "user:alice")
	for _, m := range []string{"m-1", "m-2", "m-3"} {
		_, err := st.Put(ctx, tenantA, loopgrantstore.Grant{
			ID: "g-" + m, MemberID: m, AgentName: "intake-agent", Grantor: "u", ToolClasses: []string{"ticket"},
		})
		require.NoError(t, err)
	}
	first, err := svc.ListLoopGrants(ctx, &tenantv1.ListLoopGrantsRequest{PageSize: 2})
	require.NoError(t, err)
	require.Len(t, first.GetGrants(), 2)
	require.NotEmpty(t, first.GetNextPageToken())
	second, err := svc.ListLoopGrants(ctx, &tenantv1.ListLoopGrantsRequest{PageSize: 2, PageToken: first.GetNextPageToken()})
	require.NoError(t, err)
	require.Len(t, second.GetGrants(), 1)
	assert.Equal(t, "m-3", second.GetGrants()[0].GetMemberId())
	assert.Empty(t, second.GetNextPageToken())

	// A token of tenant A does not open a page of tenant B.
	_, err = svc.ListLoopGrants(loopCtx(t, tenantB, "user:bob"),
		&tenantv1.ListLoopGrantsRequest{PageSize: 2, PageToken: first.GetNextPageToken()})
	require.Error(t, err)
}

func TestLoopGrantService_StoreFailuresAreStatuses(t *testing.T) {
	svc, st, au := newLoopSvc(t)
	ctx := loopCtx(t, tenantA, "user:alice")

	st.err = errors.New("db down")
	_, err := svc.GrantLoop(ctx, loopGrantReq("m-1", "ticket"))
	assert.Equal(t, codes.Internal, status.Code(err))
	_, err = svc.ListLoopGrants(ctx, &tenantv1.ListLoopGrantsRequest{})
	assert.Equal(t, codes.Internal, status.Code(err))
	st.err = nil

	// The prior grant cannot be read.
	st.getErr = errors.New("read down")
	_, err = svc.GrantLoop(ctx, loopGrantReq("m-1", "ticket"))
	assert.Equal(t, codes.Internal, status.Code(err))
	_, err = svc.RevokeLoop(ctx, &tenantv1.RevokeLoopRequest{MemberId: "m-1"})
	assert.Equal(t, codes.Internal, status.Code(err))
	st.getErr = nil

	// An audit failure whose cleanup also fails leaves a grant, and the call says so.
	au.err = errors.New("audit down")
	st.deleteErr = errors.New("delete down")
	_, err = svc.GrantLoop(ctx, loopGrantReq("m-1", "ticket"))
	assert.Equal(t, codes.Internal, status.Code(err))
	au.err = nil

	// The revoke reports a failed delete and a failed record.
	_, err = svc.RevokeLoop(ctx, &tenantv1.RevokeLoopRequest{MemberId: "m-1"})
	assert.Equal(t, codes.Internal, status.Code(err))
	st.deleteErr = nil
	au.err = errors.New("audit down")
	_, err = svc.RevokeLoop(ctx, &tenantv1.RevokeLoopRequest{MemberId: "m-1"})
	assert.Equal(t, codes.Unavailable, status.Code(err))
	au.err = nil

	// The bank store fails.
	failing := fakeLoopMembers{err: errors.New("bank store down")}
	svc2, err := NewLoopGrantService(st, failing, au, loopAgents, nil, testPageKeys(t))
	require.NoError(t, err)
	_, err = svc2.GrantLoop(ctx, loopGrantReq("m-1", "ticket"))
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestNewLoopGrantService_NeedsEachCollaborator(t *testing.T) {
	_, err := NewLoopGrantService(nil, nil, nil, nil, nil, nil)
	require.Error(t, err)
}

func TestRevokeLoop_RefusesNoTenantAndNoIdentity(t *testing.T) {
	svc, _, _ := newLoopSvc(t)
	_, err := svc.RevokeLoop(context.Background(), &tenantv1.RevokeLoopRequest{MemberId: "m-1"})
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	_, err = svc.RevokeLoop(loopCtx(t, tenantA, ""), &tenantv1.RevokeLoopRequest{MemberId: "m-1"})
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}
