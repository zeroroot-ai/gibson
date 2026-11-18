// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"github.com/zeroroot-ai/sdk/auth"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/agentskillstore"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

// userAwareAuthz answers Check from a set of "user|relation|object" grants. The
// existing fakeSearchAuthz keys on the object only, and an Agent Skill grant
// depends on who asks.
type userAwareAuthz struct {
	authz.Authorizer
	grants map[string]bool
	checks []string
}

func (a *userAwareAuthz) Check(_ context.Context, user, relation, object string) (bool, error) {
	a.checks = append(a.checks, user+"|"+relation+"|"+object)
	return a.grants[user+"|"+relation+"|"+object], nil
}

// wireSkillStore serves one Agent Skill with a fixed digest.
type wireSkillStore struct {
	agentskillstore.Store
	resolved int
}

func (s *wireSkillStore) List(context.Context, string, string, bool) ([]agentskillstore.Entry, error) {
	return []agentskillstore.Entry{{Name: "web-recon", Description: "map a web target before a scan"}}, nil
}

func (s *wireSkillStore) Resolve(context.Context, string, string, string) (string, error) {
	s.resolved++
	return "sha256:aa", nil
}

func (s *wireSkillStore) Load(_ context.Context, _, name, digest string) (*agentskillstore.Loaded, error) {
	return &agentskillstore.Loaded{
		Entry: agentskillstore.Entry{Name: name, Digest: digest, Description: "map a web target"},
		Body:  "# Steps\nRun httpx first.",
	}, nil
}

type wireRig struct {
	svc    *HarnessCallbackService
	store  *wireSkillStore
	fga    *userAwareAuthz
	loads  []SkillLoadRecord
	ctx    context.Context
	info   *harnesspb.ContextInfo
	blocks []string
}

// newWireRig builds a callback service that serves the two meta-tools through
// callMetaTool, with one Agent Skill and the grants given.
func newWireRig(t *testing.T, grants map[string]bool, denied []string) *wireRig {
	t.Helper()
	missionID := types.NewID()
	h := &proposeOntologyExtensionMockHarness{missionID: missionID, tenantID: "acme"}
	registry := NewCallbackHarnessRegistry()
	mustRegister(t, registry, missionID.String(), "recon-agent", h)

	r := &wireRig{store: &wireSkillStore{}, fga: &userAwareAuthz{grants: grants}, blocks: denied}
	r.svc = NewHarnessCallbackServiceWithRegistry(slog.New(slog.DiscardHandler), registry, testEventBus())
	r.svc.authzStore = fakeSearchAuthzStore{state: &RunAuthzState{
		RunID: "run-1", MissionID: missionID.String(), UserID: "alice", TenantID: "acme", Status: "active",
	}}
	r.svc.componentRegistry = fakeSearchReg{}
	r.svc.connectors = fakeConnectors{}
	r.svc.componentAuthorizer = r.fga
	r.svc.missionBlockedTools = func(context.Context, string, string) ([]string, error) { return r.blocks, nil }
	r.svc.agentSkills = func() agentskillstore.Store { return r.store }
	r.svc.skillLoadSink = func(_ context.Context, _ string, l SkillLoadRecord) error {
		r.loads = append(r.loads, l)
		return nil
	}
	r.ctx = auth.WithIdentity(context.Background(),
		auth.Identity{Subject: "agent_principal:a1", Tenant: auth.MustNewTenantID("acme")})
	r.info = &harnesspb.ContextInfo{MissionId: missionID.String(), AgentName: "recon-agent", MissionRunId: "run-1"}
	return r
}

func (r *wireRig) call(t *testing.T, tool, input string) *harnesspb.CallToolProtoResponse {
	t.Helper()
	resp, err := r.svc.callMetaTool(r.ctx, &harnesspb.CallToolProtoRequest{
		Name: tool, InputJson: []byte(input), Context: r.info,
	})
	require.NoError(t, err)
	return resp
}

func searchIDs(t *testing.T, resp *harnesspb.CallToolProtoResponse) []string {
	t.Helper()
	require.Nil(t, resp.GetError(), "search_tools error: %v", resp.GetError())
	var out struct {
		Candidates []struct {
			ID string `json:"id"`
		} `json:"candidates"`
	}
	require.NoError(t, json.Unmarshal(resp.GetOutputJson(), &out))
	ids := make([]string, 0, len(out.Candidates))
	for _, c := range out.Candidates {
		ids = append(ids, c.ID)
	}
	return ids
}

const skillSearch = `{"query":"recon","sources":["skill"]}`
const skillInvoke = `{"id":"skill:web-recon"}`

// A granted agent finds the Agent Skill with search_tools and loads the body
// with invoke_tool. The body is the output of the tool and the load is recorded
// with the digest.
func TestCallMetaTool_AgentSkillSearchThenLoad(t *testing.T) {
	r := newWireRig(t, map[string]bool{
		"agent_principal:a1|can_load|agent_skill:acme/web-recon": true,
	}, nil)

	assert.Equal(t, []string{"skill:web-recon"}, searchIDs(t, r.call(t, "search_tools", skillSearch)))

	resp := r.call(t, "invoke_tool", skillInvoke)
	require.Nil(t, resp.GetError(), "invoke_tool error: %v", resp.GetError())
	var out struct {
		Result struct {
			Name   string `json:"name"`
			Digest string `json:"digest"`
			Body   string `json:"body"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal(resp.GetOutputJson(), &out))
	assert.Equal(t, "web-recon", out.Result.Name)
	assert.Equal(t, "sha256:aa", out.Result.Digest)
	assert.Equal(t, "# Steps\nRun httpx first.", out.Result.Body)
	require.Len(t, r.loads, 1)
	assert.Equal(t, "sha256:aa", r.loads[0].Digest)
	assert.Equal(t, "agent_principal:a1", r.loads[0].Agent)
}

// A grant to the mission is enough, with no grant to the agent.
func TestCallMetaTool_AgentSkillGrantedToTheMission(t *testing.T) {
	r := newWireRig(t, map[string]bool{}, nil)
	r.fga.grants["mission:"+r.info.GetMissionId()+"|can_load|agent_skill:acme/web-recon"] = true
	assert.Equal(t, []string{"skill:web-recon"}, searchIDs(t, r.call(t, "search_tools", skillSearch)))
	require.Nil(t, r.call(t, "invoke_tool", skillInvoke).GetError())
	assert.Len(t, r.loads, 1)
}

// With no grant the agent does not find the Agent Skill, and a direct load by id
// is refused. The store is not read and no load is recorded.
func TestCallMetaTool_AgentSkillWithNoGrant(t *testing.T) {
	r := newWireRig(t, map[string]bool{
		// The user of the run holds a grant. It does not count.
		"user:alice|can_load|agent_skill:acme/web-recon": true,
	}, nil)

	assert.Empty(t, searchIDs(t, r.call(t, "search_tools", skillSearch)))

	resp := r.call(t, "invoke_tool", skillInvoke)
	require.NotNil(t, resp.GetError())
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED, resp.GetError().GetCode())
	assert.Zero(t, r.store.resolved, "the store must not be read for a caller with no grant")
	assert.Empty(t, r.loads)
}

// A mission that denies the Agent Skill cannot find it or load it, even when the
// agent holds the grant.
func TestCallMetaTool_AgentSkillOnTheDenyList(t *testing.T) {
	r := newWireRig(t, map[string]bool{
		"agent_principal:a1|can_load|agent_skill:acme/web-recon": true,
	}, []string{"skill:web-recon"})

	assert.Empty(t, searchIDs(t, r.call(t, "search_tools", skillSearch)))

	resp := r.call(t, "invoke_tool", skillInvoke)
	require.NotNil(t, resp.GetError())
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED, resp.GetError().GetCode())
	assert.Zero(t, r.store.resolved)
	assert.Empty(t, r.loads)
}
