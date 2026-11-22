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
	// err makes each method fail. getErr makes Get fail alone, deleteErr Delete.
	err, getErr, deleteErr error
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
	g.GrantedAt = time.Unix(1, 0).UTC()
	m.table(t)[g.AgentName] = g
	return &g, nil
}

func (m *memLoopStore) Get(_ context.Context, t, a string) (*loopgrantstore.Grant, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	g, ok := m.table(t)[a]
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

func (m *memLoopStore) Delete(_ context.Context, t, a string) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.table(t), a)
	return nil
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

func newLoopSvc(t *testing.T) (*LoopGrantService, *memLoopStore, *fakeLoopAudit) {
	t.Helper()
	st, au := newMemLoopStore(), &fakeLoopAudit{}
	svc, err := NewLoopGrantService(st, au, loopAgents, []string{"SubmitFinding"}, testPageKeys(t))
	require.NoError(t, err)
	return svc, st, au
}

const tenantA = "tenant-a"
const tenantB = "tenant-b"

func TestGrantLoop_StoresGrantAndAuditsTheGrantor(t *testing.T) {
	svc, st, au := newLoopSvc(t)
	resp, err := svc.GrantLoop(loopCtx(t, tenantA, "user:alice"), &tenantv1.GrantLoopRequest{
		AgentName: "intake-agent", ToolClasses: []string{"ticket", "paging", "ticket"}, HarnessCalls: []string{"SubmitFinding"},
	})
	require.NoError(t, err)
	g := resp.GetGrant()
	assert.NotEmpty(t, g.GetId())
	assert.Equal(t, []string{"ticket", "paging"}, g.GetToolClasses())
	assert.Equal(t, "user:alice", g.GetGrantor())

	stored, err := st.Get(context.Background(), tenantA, "intake-agent")
	require.NoError(t, err)
	assert.Equal(t, g.GetId(), stored.ID)

	require.Len(t, au.recs, 1)
	assert.Equal(t, loopGrantAuditGrant, au.recs[0].action)
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
		"an agent that is not in the catalog": {&tenantv1.GrantLoopRequest{AgentName: "ghost", ToolClasses: []string{"ticket"}}, codes.NotFound},
		"an agent with no member command":     {&tenantv1.GrantLoopRequest{AgentName: "one-shot", ToolClasses: []string{"ticket"}}, codes.FailedPrecondition},
		"an unknown class":                    {&tenantv1.GrantLoopRequest{AgentName: "intake-agent", ToolClasses: []string{"toaster"}}, codes.InvalidArgument},
		"a class the manifest does not name":  {&tenantv1.GrantLoopRequest{AgentName: "intake-agent", ToolClasses: []string{"edr"}}, codes.PermissionDenied},
		"an ungrantable harness call":         {&tenantv1.GrantLoopRequest{AgentName: "intake-agent", HarnessCalls: []string{"GetCredential"}}, codes.InvalidArgument},
		"an empty grant":                      {&tenantv1.GrantLoopRequest{AgentName: "intake-agent"}, codes.InvalidArgument},
		"a bad agent name":                    {&tenantv1.GrantLoopRequest{AgentName: "Bad Name", ToolClasses: []string{"ticket"}}, codes.InvalidArgument},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := svc.GrantLoop(ctx, tc.req)
			require.Error(t, err)
			assert.Equal(t, tc.code, status.Code(err))
		})
	}
}

func TestGrantLoop_NoStandingGrantWithoutItsAuditRecord(t *testing.T) {
	svc, st, au := newLoopSvc(t)
	au.err = errors.New("audit down")
	_, err := svc.GrantLoop(loopCtx(t, tenantA, "user:alice"),
		&tenantv1.GrantLoopRequest{AgentName: "intake-agent", ToolClasses: []string{"ticket"}})
	assert.Equal(t, codes.Unavailable, status.Code(err))
	_, gerr := st.Get(context.Background(), tenantA, "intake-agent")
	assert.ErrorIs(t, gerr, loopgrantstore.ErrNotFound)
}

func TestRevokeLoop_RemovesAndAuditsAndIsIdempotent(t *testing.T) {
	svc, st, au := newLoopSvc(t)
	ctx := loopCtx(t, tenantA, "user:alice")
	_, err := svc.GrantLoop(ctx, &tenantv1.GrantLoopRequest{AgentName: "intake-agent", ToolClasses: []string{"ticket"}})
	require.NoError(t, err)
	_, err = svc.RevokeLoop(ctx, &tenantv1.RevokeLoopRequest{AgentName: "intake-agent"})
	require.NoError(t, err)
	_, err = svc.RevokeLoop(ctx, &tenantv1.RevokeLoopRequest{AgentName: "intake-agent"})
	require.NoError(t, err)
	_, gerr := st.Get(context.Background(), tenantA, "intake-agent")
	require.ErrorIs(t, gerr, loopgrantstore.ErrNotFound)
	assert.Equal(t, loopGrantAuditRevoke, au.recs[1].action)
}

// An admin of tenant B neither lists nor revokes the grant of tenant A.
func TestListLoopGrants_AreTenantScoped(t *testing.T) {
	svc, st, _ := newLoopSvc(t)
	_, err := svc.GrantLoop(loopCtx(t, tenantA, "user:alice"),
		&tenantv1.GrantLoopRequest{AgentName: "intake-agent", ToolClasses: []string{"ticket"}})
	require.NoError(t, err)

	bCtx := loopCtx(t, tenantB, "user:bob")
	list, err := svc.ListLoopGrants(bCtx, &tenantv1.ListLoopGrantsRequest{})
	require.NoError(t, err)
	assert.Empty(t, list.GetGrants())

	_, err = svc.RevokeLoop(bCtx, &tenantv1.RevokeLoopRequest{AgentName: "intake-agent"})
	require.NoError(t, err)
	_, gerr := st.Get(context.Background(), tenantA, "intake-agent")
	assert.NoError(t, gerr, "the revoke of tenant B must leave the grant of tenant A")
}

func TestGrantLoop_RefusesNoTenantAndNoIdentity(t *testing.T) {
	svc, _, _ := newLoopSvc(t)
	_, err := svc.GrantLoop(context.Background(), &tenantv1.GrantLoopRequest{AgentName: "intake-agent", ToolClasses: []string{"ticket"}})
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	tenantOnly := loopCtx(t, tenantA, "")
	_, err = svc.GrantLoop(tenantOnly, &tenantv1.GrantLoopRequest{AgentName: "intake-agent", ToolClasses: []string{"ticket"}})
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestListLoopGrants_ReturnsTheGrantsOfTheTenant(t *testing.T) {
	svc, _, _ := newLoopSvc(t)
	ctx := loopCtx(t, tenantA, "user:alice")
	_, err := svc.GrantLoop(ctx, &tenantv1.GrantLoopRequest{AgentName: "intake-agent", ToolClasses: []string{"ticket"}})
	require.NoError(t, err)
	list, err := svc.ListLoopGrants(ctx, &tenantv1.ListLoopGrantsRequest{})
	require.NoError(t, err)
	require.Len(t, list.GetGrants(), 1)
	assert.Equal(t, "intake-agent", list.GetGrants()[0].GetAgentName())
}

func TestListLoopGrants_RefusesNoTenant(t *testing.T) {
	svc, _, _ := newLoopSvc(t)
	_, err := svc.ListLoopGrants(context.Background(), &tenantv1.ListLoopGrantsRequest{})
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestRevokeLoop_RefusesABadAgentName(t *testing.T) {
	svc, _, _ := newLoopSvc(t)
	_, err := svc.RevokeLoop(loopCtx(t, tenantA, "user:alice"), &tenantv1.RevokeLoopRequest{AgentName: "Bad Name"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestListLoopGrants_PagesWithAKeysetToken(t *testing.T) {
	svc, st, _ := newLoopSvc(t)
	ctx := loopCtx(t, tenantA, "user:alice")
	for _, name := range []string{"a-agent", "b-agent", "c-agent"} {
		_, err := st.Put(ctx, tenantA, loopgrantstore.Grant{ID: "g-" + name, AgentName: name, Grantor: "u", ToolClasses: []string{"ticket"}})
		require.NoError(t, err)
	}
	first, err := svc.ListLoopGrants(ctx, &tenantv1.ListLoopGrantsRequest{PageSize: 2})
	require.NoError(t, err)
	require.Len(t, first.GetGrants(), 2)
	require.NotEmpty(t, first.GetNextPageToken())
	second, err := svc.ListLoopGrants(ctx, &tenantv1.ListLoopGrantsRequest{PageSize: 2, PageToken: first.GetNextPageToken()})
	require.NoError(t, err)
	require.Len(t, second.GetGrants(), 1)
	assert.Equal(t, "c-agent", second.GetGrants()[0].GetAgentName())
	assert.Empty(t, second.GetNextPageToken())

	// A token of tenant A does not open a page of tenant B.
	_, err = svc.ListLoopGrants(loopCtx(t, tenantB, "user:bob"),
		&tenantv1.ListLoopGrantsRequest{PageSize: 2, PageToken: first.GetNextPageToken()})
	require.Error(t, err)
}

func TestLoopGrantService_StoreFailuresAreStatuses(t *testing.T) {
	svc, st, au := newLoopSvc(t)
	ctx := loopCtx(t, tenantA, "user:alice")
	grant := &tenantv1.GrantLoopRequest{AgentName: "intake-agent", ToolClasses: []string{"ticket"}}

	st.err = errors.New("db down")
	_, err := svc.GrantLoop(ctx, grant)
	assert.Equal(t, codes.Internal, status.Code(err))
	_, err = svc.ListLoopGrants(ctx, &tenantv1.ListLoopGrantsRequest{})
	assert.Equal(t, codes.Internal, status.Code(err))
	st.err = nil

	// A failed audit record whose cleanup also fails leaves a grant, and the
	// call says so.
	au.err = errors.New("audit down")
	st.deleteErr = errors.New("delete down")
	_, err = svc.GrantLoop(ctx, grant)
	assert.Equal(t, codes.Internal, status.Code(err))
	st.deleteErr = nil
	au.err = nil

	// The revoke reports a failed read, a failed delete and a failed record.
	st.getErr = errors.New("read down")
	_, err = svc.RevokeLoop(ctx, &tenantv1.RevokeLoopRequest{AgentName: "intake-agent"})
	assert.Equal(t, codes.Internal, status.Code(err))
	st.getErr = nil
	st.deleteErr = errors.New("delete down")
	_, err = svc.RevokeLoop(ctx, &tenantv1.RevokeLoopRequest{AgentName: "intake-agent"})
	assert.Equal(t, codes.Internal, status.Code(err))
	st.deleteErr = nil
	au.err = errors.New("audit down")
	_, err = svc.RevokeLoop(ctx, &tenantv1.RevokeLoopRequest{AgentName: "intake-agent"})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

func TestNewLoopGrantService_NeedsEachCollaborator(t *testing.T) {
	_, err := NewLoopGrantService(nil, nil, nil, nil, nil)
	require.Error(t, err)
}

func TestRevokeLoop_RefusesNoTenantAndNoIdentity(t *testing.T) {
	svc, _, _ := newLoopSvc(t)
	_, err := svc.RevokeLoop(context.Background(), &tenantv1.RevokeLoopRequest{AgentName: "intake-agent"})
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	_, err = svc.RevokeLoop(loopCtx(t, tenantA, ""), &tenantv1.RevokeLoopRequest{AgentName: "intake-agent"})
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}
