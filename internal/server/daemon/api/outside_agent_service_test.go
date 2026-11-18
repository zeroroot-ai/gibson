// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/outsideagentstore"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

type memOutsideStore struct {
	entries map[string]outsideagentstore.Entry
}

func (m *memOutsideStore) Register(
	_ context.Context, _ string, e outsideagentstore.Entry,
) (*outsideagentstore.Entry, error) {
	if old, ok := m.entries[e.Name]; ok {
		if old.A2AURL != e.A2AURL || old.CredentialSecret != e.CredentialSecret || old.Description != e.Description {
			return nil, fmt.Errorf("%w: %s", outsideagentstore.ErrConflict, e.Name)
		}
		return &old, nil
	}
	e.CreatedAt = time.Unix(1, 0).UTC()
	m.entries[e.Name] = e
	return &e, nil
}

func (m *memOutsideStore) List(context.Context, string) ([]outsideagentstore.Entry, error) {
	out := []outsideagentstore.Entry{}
	for _, e := range m.entries {
		out = append(out, e)
	}
	return out, nil
}

func (m *memOutsideStore) Get(_ context.Context, _, name string) (*outsideagentstore.Entry, error) {
	e, ok := m.entries[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", outsideagentstore.ErrNotFound, name)
	}
	return &e, nil
}

func (m *memOutsideStore) Delete(_ context.Context, _, name string) error {
	if _, ok := m.entries[name]; !ok {
		return fmt.Errorf("%w: %s", outsideagentstore.ErrNotFound, name)
	}
	delete(m.entries, name)
	return nil
}

type fakeOutsideResolver map[string][]net.IP

func (f fakeOutsideResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	ips, ok := f[host]
	if !ok {
		return nil, errors.New("no such host")
	}
	out := []net.IPAddr{}
	for _, ip := range ips {
		out = append(out, net.IPAddr{IP: ip})
	}
	return out, nil
}

type outsideFixture struct {
	svc   *OutsideAgentService
	store *memOutsideStore
	fga   *recordingAuthorizer
	ctx   context.Context
}

func newOutsideFixture(t *testing.T) *outsideFixture {
	t.Helper()
	f := &outsideFixture{
		store: &memOutsideStore{entries: map[string]outsideagentstore.Entry{}},
		fga:   &recordingAuthorizer{fakeAuthorizer: newFakeAuthorizer()},
	}
	resolver := fakeOutsideResolver{
		"agent.partner.example": {net.ParseIP("93.184.216.34")},
		"rebind.example":        {net.ParseIP("93.184.216.34"), net.ParseIP("10.0.0.5")},
		"internal.example":      {net.ParseIP("10.0.0.5")},
	}
	svc, err := NewOutsideAgentService(f.store, f.fga, resolver)
	require.NoError(t, err)
	f.svc = svc
	f.ctx = auth.WithIdentity(context.Background(),
		auth.Identity{Subject: "admin-1", Tenant: auth.MustNewTenantID("acme")})
	return f
}

func reg(name, u string) *tenantv1.RegisterOutsideAgentRequest {
	return &tenantv1.RegisterOutsideAgentRequest{Name: name, A2AUrl: u}
}

const outsideURL = "https://agent.partner.example/a2a"

func TestRegisterOutsideAgent_StoresAndWritesTheOwnerTuple(t *testing.T) {
	f := newOutsideFixture(t)
	resp, err := f.svc.RegisterOutsideAgent(f.ctx, &tenantv1.RegisterOutsideAgentRequest{
		Name: "partner-scout", A2AUrl: outsideURL, CredentialSecret: "partner-key", Description: "d"})
	require.NoError(t, err)
	assert.Equal(t, outsideURL, resp.GetEntry().GetA2AUrl())
	assert.Equal(t, "partner-key", resp.GetEntry().GetCredentialSecret())
	assert.Equal(t, []authz.Tuple{{User: "tenant:acme", Relation: "owner", Object: "outside_agent:acme/partner-scout"}},
		f.fga.writtenTuples())

	// The same call again changes nothing.
	_, err = f.svc.RegisterOutsideAgent(f.ctx, &tenantv1.RegisterOutsideAgentRequest{
		Name: "partner-scout", A2AUrl: outsideURL, CredentialSecret: "partner-key", Description: "d"})
	require.NoError(t, err)
	assert.Len(t, f.store.entries, 1)
}

func TestRegisterOutsideAgent_Refusals(t *testing.T) {
	cases := map[string]struct {
		req  *tenantv1.RegisterOutsideAgentRequest
		want codes.Code
	}{
		"http url":            {reg("a", "http://agent.partner.example/a2a"), codes.InvalidArgument},
		"no host":             {reg("a", "https:///a2a"), codes.InvalidArgument},
		"user info":           {reg("a", "https://u:p@agent.partner.example/"), codes.InvalidArgument},
		"query":               {reg("a", outsideURL+"?x=1"), codes.InvalidArgument},
		"fragment":            {reg("a", outsideURL+"#f"), codes.InvalidArgument},
		"loopback literal":    {reg("a", "https://127.0.0.1/a2a"), codes.InvalidArgument},
		"metadata literal":    {reg("a", "https://169.254.169.254/"), codes.InvalidArgument},
		"internal name":       {reg("a", "https://internal.example/"), codes.InvalidArgument},
		"one internal answer": {reg("a", "https://rebind.example/"), codes.InvalidArgument},
		"unknown host":        {reg("a", "https://nope.example/"), codes.InvalidArgument},
		"bad name":            {reg("Bad_Name", outsideURL), codes.InvalidArgument},
		"name with slash":     {reg("a/b", outsideURL), codes.InvalidArgument},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newOutsideFixture(t)
			_, err := f.svc.RegisterOutsideAgent(f.ctx, tc.req)
			assert.Equal(t, tc.want, code(err))
			assert.Empty(t, f.store.entries, "nothing stored for a refused call")
			assert.Empty(t, f.fga.writtenTuples(), "no tuple for a refused call")
		})
	}

	f := newOutsideFixture(t)
	_, err := f.svc.RegisterOutsideAgent(context.Background(),
		&tenantv1.RegisterOutsideAgentRequest{Name: "a", A2AUrl: outsideURL})
	assert.Equal(t, codes.PermissionDenied, code(err), "no tenant")

	_, err = f.svc.RegisterOutsideAgent(f.ctx, &tenantv1.RegisterOutsideAgentRequest{Name: "a", A2AUrl: outsideURL})
	require.NoError(t, err)
	_, err = f.svc.RegisterOutsideAgent(f.ctx, &tenantv1.RegisterOutsideAgentRequest{
		Name: "a", A2AUrl: "https://agent.partner.example/other"})
	assert.Equal(t, codes.AlreadyExists, code(err), "the same name with another URL")
}

func TestRegisterOutsideAgent_RefusalNamesNoLLMSetting(t *testing.T) {
	f := newOutsideFixture(t)
	_, err := f.svc.RegisterOutsideAgent(f.ctx, &tenantv1.RegisterOutsideAgentRequest{
		Name: "a", A2AUrl: "https://internal.example/"})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "allow_private_llm_endpoints")
	assert.Contains(t, err.Error(), outsideAgentAddressHint)
}

func registeredOutside(t *testing.T) *outsideFixture {
	t.Helper()
	f := newOutsideFixture(t)
	_, err := f.svc.RegisterOutsideAgent(f.ctx, &tenantv1.RegisterOutsideAgentRequest{Name: "scout", A2AUrl: outsideURL})
	require.NoError(t, err)
	return f
}

const scoutObject = "outside_agent:acme/scout"

func TestGrantOutsideAgent(t *testing.T) {
	f := registeredOutside(t)
	f.fga.allow("tenant:acme", "belongs_to", "mission:m1")
	_, err := f.svc.GrantOutsideAgent(f.ctx, &tenantv1.GrantOutsideAgentRequest{Name: "scout", MissionId: "m1"})
	require.NoError(t, err)
	assert.Contains(t, f.fga.writtenTuples(),
		authz.Tuple{User: "mission:m1", Relation: "granted_mission", Object: scoutObject})
}

func TestGrantOutsideAgent_Refusals(t *testing.T) {
	f := registeredOutside(t)
	ownerOnly := len(f.fga.writtenTuples())

	_, err := f.svc.GrantOutsideAgent(context.Background(),
		&tenantv1.GrantOutsideAgentRequest{Name: "scout", MissionId: "m1"})
	assert.Equal(t, codes.PermissionDenied, code(err), "no tenant")

	// A mission of another tenant is refused.
	_, err = f.svc.GrantOutsideAgent(f.ctx, &tenantv1.GrantOutsideAgentRequest{Name: "scout", MissionId: "m-other"})
	assert.Equal(t, codes.NotFound, code(err))

	// A grant on an unknown name is refused.
	f.fga.allow("tenant:acme", "belongs_to", "mission:m1")
	_, err = f.svc.GrantOutsideAgent(f.ctx, &tenantv1.GrantOutsideAgentRequest{Name: "ghost", MissionId: "m1"})
	assert.Equal(t, codes.NotFound, code(err))

	// A mission id with a type prefix or a userset marker is refused.
	for _, bad := range []string{"mission:m1", "m1#member", "", "a/b"} {
		_, err = f.svc.GrantOutsideAgent(f.ctx, &tenantv1.GrantOutsideAgentRequest{Name: "scout", MissionId: bad})
		assert.Equal(t, codes.InvalidArgument, code(err), bad)
	}
	assert.Len(t, f.fga.writtenTuples(), ownerOnly, "no grant tuple for a refused call")
}

func TestRevokeOutsideAgent(t *testing.T) {
	f := registeredOutside(t)
	_, err := f.svc.RevokeOutsideAgent(f.ctx, &tenantv1.RevokeOutsideAgentRequest{Name: "scout", MissionId: "m1"})
	require.NoError(t, err)
	assert.Contains(t, f.fga.deleted, authz.Tuple{User: "mission:m1", Relation: "granted_mission", Object: scoutObject})
}

func TestRevokeOutsideAgent_Refusals(t *testing.T) {
	f := registeredOutside(t)
	_, err := f.svc.RevokeOutsideAgent(context.Background(),
		&tenantv1.RevokeOutsideAgentRequest{Name: "scout", MissionId: "m1"})
	assert.Equal(t, codes.PermissionDenied, code(err), "no tenant")
	_, err = f.svc.RevokeOutsideAgent(f.ctx, &tenantv1.RevokeOutsideAgentRequest{Name: "scout", MissionId: "mission:m1"})
	assert.Equal(t, codes.InvalidArgument, code(err), "a mission id with a prefix")
	_, err = f.svc.RevokeOutsideAgent(f.ctx, &tenantv1.RevokeOutsideAgentRequest{Name: "Bad_Name", MissionId: "m1"})
	assert.Equal(t, codes.InvalidArgument, code(err), "a bad name")
	assert.Empty(t, f.fga.deleted)
}

func TestListOutsideAgentGrants(t *testing.T) {
	f := registeredOutside(t)
	f.fga.users["outside_agent|"+scoutObject+"|granted_mission"] = []string{"mission:m1"}
	got, err := f.svc.ListOutsideAgentGrants(f.ctx, &tenantv1.ListOutsideAgentGrantsRequest{Name: "scout"})
	require.NoError(t, err)
	assert.Equal(t, []string{"m1"}, got.GetMissionIds())
}

func TestListOutsideAgentGrants_Refusals(t *testing.T) {
	f := registeredOutside(t)
	_, err := f.svc.ListOutsideAgentGrants(context.Background(), &tenantv1.ListOutsideAgentGrantsRequest{Name: "scout"})
	assert.Equal(t, codes.PermissionDenied, code(err), "no tenant")
	_, err = f.svc.ListOutsideAgentGrants(f.ctx, &tenantv1.ListOutsideAgentGrantsRequest{Name: "ghost"})
	assert.Equal(t, codes.NotFound, code(err))
}

func TestDeleteOutsideAgent_RemovesTheRecordAndEachTuple(t *testing.T) {
	f := newOutsideFixture(t)
	_, err := f.svc.RegisterOutsideAgent(f.ctx, &tenantv1.RegisterOutsideAgentRequest{Name: "scout", A2AUrl: outsideURL})
	require.NoError(t, err)
	obj := "outside_agent:acme/scout"
	f.fga.users["outside_agent|"+obj+"|granted_mission"] = []string{"mission:m1", "mission:m2"}

	_, err = f.svc.DeleteOutsideAgent(f.ctx, &tenantv1.DeleteOutsideAgentRequest{Name: "scout"})
	require.NoError(t, err)
	assert.Empty(t, f.store.entries)
	assert.ElementsMatch(t, []authz.Tuple{
		{User: "tenant:acme", Relation: "owner", Object: obj},
		{User: "mission:m1", Relation: "granted_mission", Object: obj},
		{User: "mission:m2", Relation: "granted_mission", Object: obj},
	}, f.fga.deleted)

	_, err = f.svc.DeleteOutsideAgent(f.ctx, &tenantv1.DeleteOutsideAgentRequest{Name: "scout"})
	assert.Equal(t, codes.NotFound, code(err))
}

func TestListOutsideAgents(t *testing.T) {
	f := registeredOutside(t)
	l, err := f.svc.ListOutsideAgents(f.ctx, &tenantv1.ListOutsideAgentsRequest{})
	require.NoError(t, err)
	assert.Len(t, l.GetEntries(), 1)
}

func TestListOutsideAgents_Refusals(t *testing.T) {
	f := newOutsideFixture(t)
	_, err := f.svc.ListOutsideAgents(context.Background(), &tenantv1.ListOutsideAgentsRequest{})
	assert.Equal(t, codes.PermissionDenied, code(err))
}

func TestGetOutsideAgent(t *testing.T) {
	f := registeredOutside(t)
	g, err := f.svc.GetOutsideAgent(f.ctx, &tenantv1.GetOutsideAgentRequest{Name: "scout"})
	require.NoError(t, err)
	assert.Equal(t, "scout", g.GetEntry().GetName())
}

func TestGetOutsideAgent_Refusals(t *testing.T) {
	f := registeredOutside(t)
	_, err := f.svc.GetOutsideAgent(f.ctx, &tenantv1.GetOutsideAgentRequest{Name: "ghost"})
	assert.Equal(t, codes.NotFound, code(err))
	_, err = f.svc.GetOutsideAgent(context.Background(), &tenantv1.GetOutsideAgentRequest{Name: "scout"})
	assert.Equal(t, codes.PermissionDenied, code(err))
}

func TestRegisterOutsideAgent_RefusesTheNameOfACatalogAgent(t *testing.T) {
	f := newOutsideFixture(t)
	_, err := f.svc.RegisterOutsideAgent(f.ctx, reg("cve-triage", outsideURL))
	assert.Equal(t, codes.AlreadyExists, code(err))
	assert.Empty(t, f.store.entries)
}
