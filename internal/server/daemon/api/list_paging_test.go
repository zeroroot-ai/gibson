// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/zeroroot-ai/gibson/internal/platform/agentskillstore"
	"github.com/zeroroot-ai/gibson/internal/platform/outsideagentstore"
	"github.com/zeroroot-ai/gibson/internal/platform/pagetoken"
	"github.com/zeroroot-ai/gibson/internal/platform/providerconfig"
	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// signedToken signs a position for a list of the service, as the daemon does.
func signedToken(t *testing.T, keys *pagetoken.Keys, list, position string, scope ...string) string {
	t.Helper()
	page, err := pageOf(keys, list, 1, "", scope[0], scope[1:]...)
	require.NoError(t, err)
	return page.Token(position, true)
}

func skillNames(entries []*tenantv1.AgentSkillEntry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.GetName()+"@"+e.GetDigest())
	}
	return out
}

func TestListAgentSkills_PagesWithAKeysetToken(t *testing.T) {
	f := newSkillFixture(t, nil)
	f.store.entries = []agentskillstore.Entry{
		{Name: "c", Digest: "sha256:03", Current: true, PublishedAt: time.Unix(30, 0)},
		{Name: "a", Digest: "sha256:01", Current: true, PublishedAt: time.Unix(10, 0)},
		{Name: "b", Digest: "sha256:02", Current: true, PublishedAt: time.Unix(20, 0)},
	}

	first, err := f.svc.ListAgentSkills(f.ctx, &tenantv1.ListAgentSkillsRequest{PageSize: 2})
	require.NoError(t, err)
	assert.Equal(t, []string{"a@sha256:01", "b@sha256:02"}, skillNames(first.GetEntries()))
	require.NotEmpty(t, first.GetNextPageToken())

	second, err := f.svc.ListAgentSkills(f.ctx,
		&tenantv1.ListAgentSkillsRequest{PageSize: 2, PageToken: first.GetNextPageToken()})
	require.NoError(t, err)
	assert.Equal(t, []string{"c@sha256:03"}, skillNames(second.GetEntries()))
	assert.Empty(t, second.GetNextPageToken(), "the last page has no token")
}

// All versions of one name walk newest first, then by digest. Two versions of
// one name can share a publish time, so the digest must break the tie.
func TestListAgentSkills_AllVersionsWalkWithNoGapAndNoRepeat(t *testing.T) {
	f := newSkillFixture(t, nil)
	f.store.entries = []agentskillstore.Entry{
		{Name: "a", Digest: "sha256:01", PublishedAt: time.Unix(10, 0)},
		{Name: "a", Digest: "sha256:02", PublishedAt: time.Unix(20, 0)},
		{Name: "a", Digest: "sha256:03", PublishedAt: time.Unix(20, 0)},
		{Name: "b", Digest: "sha256:04", PublishedAt: time.Unix(5, 0)},
	}
	var got []string
	token := ""
	for range 10 {
		resp, err := f.svc.ListAgentSkills(f.ctx,
			&tenantv1.ListAgentSkillsRequest{AllVersions: true, PageSize: 1, PageToken: token})
		require.NoError(t, err)
		got = append(got, skillNames(resp.GetEntries())...)
		if token = resp.GetNextPageToken(); token == "" {
			break
		}
	}
	assert.Equal(t, []string{"a@sha256:02", "a@sha256:03", "a@sha256:01", "b@sha256:04"}, got)
}

func TestListAgentSkills_RefusesABadToken(t *testing.T) {
	f := newSkillFixture(t, nil)
	f.store.entries = []agentskillstore.Entry{{Name: "a", Digest: "sha256:01", Current: true}}
	keys := f.svc.pageKeys
	scope := []string{"acme", "", "false"}
	tests := map[string]string{
		"not a token":      "garbage",
		"another list":     signedToken(t, keys, "tenant-outside-agents", joinKey("a", "1", "d"), "acme", "", "false"),
		"another filter":   signedToken(t, keys, "tenant-agent-skills", joinKey("a", "1", "d"), "acme", "x", "false"),
		"key of one field": signedToken(t, keys, "tenant-agent-skills", "a", scope...),
		"time not a number": signedToken(t, keys, "tenant-agent-skills", joinKey("a", "late", "d"),
			scope...),
	}
	for name, token := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := f.svc.ListAgentSkills(f.ctx, &tenantv1.ListAgentSkillsRequest{PageToken: token})
			assert.Equal(t, codes.InvalidArgument, code(err))
		})
	}
}

func TestListAgentSkills_StoreFailureAndPageSizeCap(t *testing.T) {
	svc, f := faultySkillService(t, func(s *faultSkillStore) { s.listErr = errSkillBackend }, nil)
	_, err := svc.ListAgentSkills(f.ctx, &tenantv1.ListAgentSkillsRequest{})
	assert.Equal(t, codes.Internal, code(err))

	f = newSkillFixture(t, nil)
	for i := range pagetoken.MaxSize + 5 {
		f.store.entries = append(f.store.entries,
			agentskillstore.Entry{Name: fmt.Sprintf("s%05d", i), Digest: "sha256:aa", Current: true})
	}
	resp, err := f.svc.ListAgentSkills(f.ctx, &tenantv1.ListAgentSkillsRequest{PageSize: 100000})
	require.NoError(t, err)
	assert.Len(t, resp.GetEntries(), pagetoken.MaxSize, "a large page_size is capped")
	assert.NotEmpty(t, resp.GetNextPageToken())
}

func TestListAgentSkillGrants_PagesInMemoryOverAStableSort(t *testing.T) {
	f := newSkillFixture(t, nil)
	f.store.entries = []agentskillstore.Entry{{Name: "a", Digest: "sha256:02", Current: true}}
	obj := "agent_skill:acme/a"
	f.fga.withUsers("agent_skill", obj, "granted_agent", "agent_principal:y", "agent_principal:x")
	f.fga.withUsers("agent_skill", obj, "granted_mission", "mission:m1")

	first, err := f.svc.ListAgentSkillGrants(f.ctx, &tenantv1.ListAgentSkillGrantsRequest{Name: "a", PageSize: 2})
	require.NoError(t, err)
	require.Len(t, first.GetGrants(), 2)
	assert.Equal(t, "x", first.GetGrants()[0].GetSubjectId())
	assert.Equal(t, "y", first.GetGrants()[1].GetSubjectId())
	require.NotEmpty(t, first.GetNextPageToken())

	second, err := f.svc.ListAgentSkillGrants(f.ctx,
		&tenantv1.ListAgentSkillGrantsRequest{Name: "a", PageSize: 2, PageToken: first.GetNextPageToken()})
	require.NoError(t, err)
	require.Len(t, second.GetGrants(), 1)
	assert.Equal(t, "m1", second.GetGrants()[0].GetSubjectId())
	assert.Empty(t, second.GetNextPageToken())

	_, err = f.svc.ListAgentSkillGrants(f.ctx,
		&tenantv1.ListAgentSkillGrantsRequest{Name: "other", PageToken: first.GetNextPageToken()})
	assert.Equal(t, codes.InvalidArgument, code(err), "a token of another Agent Skill is refused")
}

func TestListSharedAgentSkills_PagesTheSortedNames(t *testing.T) {
	f := newSkillFixture(t, nil)
	offerShared(f)
	one := f.shared.entries["web-recon"]
	f.shared.entries["alpha"] = one
	f.shared.entries["zulu"] = one

	first, err := f.svc.ListSharedAgentSkills(f.ctx, &tenantv1.ListSharedAgentSkillsRequest{PageSize: 2})
	require.NoError(t, err)
	require.Len(t, first.GetEntries(), 2)
	assert.Equal(t, "alpha", first.GetEntries()[0].GetName())
	assert.Equal(t, "web-recon", first.GetEntries()[1].GetName())
	require.NotEmpty(t, first.GetNextPageToken())

	second, err := f.svc.ListSharedAgentSkills(f.ctx,
		&tenantv1.ListSharedAgentSkillsRequest{PageSize: 2, PageToken: first.GetNextPageToken()})
	require.NoError(t, err)
	require.Len(t, second.GetEntries(), 1)
	assert.Equal(t, "zulu", second.GetEntries()[0].GetName())
	assert.Empty(t, second.GetNextPageToken())

	_, err = f.svc.ListSharedAgentSkills(f.ctx, &tenantv1.ListSharedAgentSkillsRequest{PageToken: "garbage"})
	assert.Equal(t, codes.InvalidArgument, code(err))
}

func TestListOutsideAgents_PagesByName(t *testing.T) {
	f := newOutsideFixture(t)
	for _, name := range []string{"charlie", "alpha", "bravo"} {
		_, err := f.svc.RegisterOutsideAgent(f.ctx, &tenantv1.RegisterOutsideAgentRequest{Name: name, A2AUrl: outsideURL})
		require.NoError(t, err)
	}

	first, err := f.svc.ListOutsideAgents(f.ctx, &tenantv1.ListOutsideAgentsRequest{PageSize: 2})
	require.NoError(t, err)
	require.Len(t, first.GetEntries(), 2)
	assert.Equal(t, "alpha", first.GetEntries()[0].GetName())
	assert.Equal(t, "bravo", first.GetEntries()[1].GetName())
	require.NotEmpty(t, first.GetNextPageToken())

	second, err := f.svc.ListOutsideAgents(f.ctx,
		&tenantv1.ListOutsideAgentsRequest{PageSize: 2, PageToken: first.GetNextPageToken()})
	require.NoError(t, err)
	require.Len(t, second.GetEntries(), 1)
	assert.Equal(t, "charlie", second.GetEntries()[0].GetName())
	assert.Empty(t, second.GetNextPageToken())

	_, err = f.svc.ListOutsideAgents(f.ctx, &tenantv1.ListOutsideAgentsRequest{PageToken: "garbage"})
	assert.Equal(t, codes.InvalidArgument, code(err))
	_, err = f.svc.ListOutsideAgents(f.ctx, &tenantv1.ListOutsideAgentsRequest{PageToken: signedToken(
		t, f.svc.pageKeys, "tenant-outside-agent-grants", "a", "acme", "scout")})
	assert.Equal(t, codes.InvalidArgument, code(err), "a token of another list is refused")
}

func TestListOutsideAgents_StoreFailure(t *testing.T) {
	svc, f := faultyOutsideService(t, func(s *faultOutsideStore) { s.listErr = errSkillBackend }, nil)
	_, err := svc.ListOutsideAgents(f.ctx, &tenantv1.ListOutsideAgentsRequest{})
	assert.Equal(t, codes.Internal, code(err))
}

func TestListOutsideAgentGrants_PagesInMemoryOverAStableSort(t *testing.T) {
	f := registeredOutside(t)
	f.fga.withUsers("outside_agent", scoutObject, "granted_mission", "mission:m3", "mission:m1", "mission:m2")

	first, err := f.svc.ListOutsideAgentGrants(f.ctx, &tenantv1.ListOutsideAgentGrantsRequest{Name: "scout", PageSize: 2})
	require.NoError(t, err)
	assert.Equal(t, []string{"m1", "m2"}, first.GetMissionIds())
	require.NotEmpty(t, first.GetNextPageToken())

	second, err := f.svc.ListOutsideAgentGrants(f.ctx,
		&tenantv1.ListOutsideAgentGrantsRequest{Name: "scout", PageSize: 2, PageToken: first.GetNextPageToken()})
	require.NoError(t, err)
	assert.Equal(t, []string{"m3"}, second.GetMissionIds())
	assert.Empty(t, second.GetNextPageToken())

	_, err = f.svc.ListOutsideAgentGrants(f.ctx,
		&tenantv1.ListOutsideAgentGrantsRequest{Name: "scout", PageToken: "garbage"})
	assert.Equal(t, codes.InvalidArgument, code(err))
}

func providerRecords(names ...string) []*providerconfig.ProviderConfig {
	out := make([]*providerconfig.ProviderConfig, 0, len(names))
	for _, n := range names {
		out = append(out, &providerconfig.ProviderConfig{Name: n, Type: providerconfig.ProviderAnthropic, Enabled: true})
	}
	return out
}

func TestGetTenantModelProviders_PagesAndKeepsEachSkippedRecordOnItsPage(t *testing.T) {
	ctx := peerCtx(t, testTenantOperatorSVID)
	srv := modelCredServer(&fakeCredStore{})
	records := providerRecords("delta", "alpha", "charlie")
	records = append(records,
		&providerconfig.ProviderConfig{Name: "bravo", Type: providerconfig.ProviderVoyage, Enabled: true},
		&providerconfig.ProviderConfig{Name: "echo", Type: providerconfig.ProviderAnthropic, Enabled: false})
	srv.providerConfig = fakeProviders{records: records}

	var names, skipped []string
	token, pages := "", 0
	for range 10 {
		resp, err := srv.GetTenantModelProviders(ctx,
			&daemonoperatorv1.GetTenantModelProvidersRequest{TenantId: "acme", PageSize: 2, PageToken: token})
		require.NoError(t, err)
		pages++
		for _, p := range resp.GetProviders() {
			names = append(names, p.GetName())
		}
		skipped = append(skipped, resp.GetSkipped()...)
		if token = resp.GetNextPageToken(); token == "" {
			break
		}
	}
	assert.Equal(t, 2, pages, "four enabled records fill two pages of two")
	assert.Equal(t, []string{"alpha", "charlie", "delta"}, names)
	require.Len(t, skipped, 1)
	assert.Contains(t, skipped[0], "bravo: voyage")
}

func TestGetTenantModelProviders_RefusesABadOrForeignToken(t *testing.T) {
	ctx := peerCtx(t, testTenantOperatorSVID)
	srv := modelCredServer(&fakeCredStore{})
	srv.providerConfig = fakeProviders{records: providerRecords("a", "b")}

	first, err := srv.GetTenantModelProviders(ctx,
		&daemonoperatorv1.GetTenantModelProvidersRequest{TenantId: "acme", PageSize: 1})
	require.NoError(t, err)
	require.NotEmpty(t, first.GetNextPageToken())

	_, err = srv.GetTenantModelProviders(ctx,
		&daemonoperatorv1.GetTenantModelProvidersRequest{TenantId: "other", PageToken: first.GetNextPageToken()})
	assert.Equal(t, codes.InvalidArgument, code(err), "a token of another tenant is refused")
	_, err = srv.GetTenantModelProviders(ctx,
		&daemonoperatorv1.GetTenantModelProvidersRequest{TenantId: "acme", PageToken: "garbage"})
	assert.Equal(t, codes.InvalidArgument, code(err))

	srv.pageKeys = nil
	_, err = srv.GetTenantModelProviders(ctx, &daemonoperatorv1.GetTenantModelProvidersRequest{TenantId: "acme"})
	assert.Equal(t, codes.Unavailable, code(err), "no page keys")
}

func TestGetTenantOutsideAgents_PagesByName(t *testing.T) {
	ctx := peerCtx(t, testTenantOperatorSVID)
	store := &tenantOutsideStore{byTenant: map[string][]outsideagentstore.Entry{
		"acme": {{Name: "c"}, {Name: "a"}, {Name: "b"}}, "other": {{Name: "z"}},
	}}
	srv := outsideOperatorServer(store, &fakeCredStore{})

	first, err := srv.GetTenantOutsideAgents(ctx,
		&daemonoperatorv1.GetTenantOutsideAgentsRequest{TenantId: "acme", PageSize: 2})
	require.NoError(t, err)
	require.Len(t, first.GetAgents(), 2)
	assert.Equal(t, "a", first.GetAgents()[0].GetName())
	assert.Equal(t, "b", first.GetAgents()[1].GetName())
	require.NotEmpty(t, first.GetNextPageToken())

	second, err := srv.GetTenantOutsideAgents(ctx, &daemonoperatorv1.GetTenantOutsideAgentsRequest{
		TenantId: "acme", PageSize: 2, PageToken: first.GetNextPageToken(),
	})
	require.NoError(t, err)
	require.Len(t, second.GetAgents(), 1)
	assert.Equal(t, "c", second.GetAgents()[0].GetName())
	assert.Empty(t, second.GetNextPageToken())

	_, err = srv.GetTenantOutsideAgents(ctx, &daemonoperatorv1.GetTenantOutsideAgentsRequest{
		TenantId: "other", PageToken: first.GetNextPageToken(),
	})
	assert.Equal(t, codes.InvalidArgument, code(err), "a token of another tenant is refused")
	srv.pageKeys = nil
	_, err = srv.GetTenantOutsideAgents(ctx, &daemonoperatorv1.GetTenantOutsideAgentsRequest{TenantId: "acme"})
	assert.Equal(t, codes.Unavailable, code(err), "no page keys")
}
