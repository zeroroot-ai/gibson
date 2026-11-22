// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"errors"
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
	g.GrantedAt = time.Unix(1, 0).UTC()
	m.table(t)[g.AgentName] = g
	return &g, nil
}

func (m *memLoopStore) Get(_ context.Context, t, a string) (*loopgrantstore.Grant, error) {
	g, ok := m.table(t)[a]
	if !ok {
		return nil, loopgrantstore.ErrNotFound
	}
	return &g, nil
}

func (m *memLoopStore) List(_ context.Context, t string) ([]loopgrantstore.Grant, error) {
	out := []loopgrantstore.Grant{}
	for _, g := range m.table(t) {
		out = append(out, g)
	}
	return out, nil
}

func (m *memLoopStore) Delete(_ context.Context, t, a string) error {
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
	svc, err := NewLoopGrantService(st, au, loopAgents, []string{"SubmitFinding"})
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
	assert.ErrorIs(t, gerr, loopgrantstore.ErrNotFound)
	assert.Equal(t, loopGrantAuditRevoke, au.recs[1].action)
}

// An admin of tenant B neither lists nor revokes the grant of tenant A.
func TestLoopGrants_AreTenantScoped(t *testing.T) {
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

func TestLoopGrantService_RefusesNoTenantAndNoIdentity(t *testing.T) {
	svc, _, _ := newLoopSvc(t)
	_, err := svc.GrantLoop(context.Background(), &tenantv1.GrantLoopRequest{AgentName: "intake-agent", ToolClasses: []string{"ticket"}})
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	tenantOnly := loopCtx(t, tenantA, "")
	_, err = svc.GrantLoop(tenantOnly, &tenantv1.GrantLoopRequest{AgentName: "intake-agent", ToolClasses: []string{"ticket"}})
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}
