// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build e2e
// +build e2e

// Package e2e: agent_skills_test.go is the exit test of the Agent Skills epic
// (gibson#1377).
//
// In plain words: a tenant publishes a folder as an Agent Skill. An agent that
// holds a grant finds it with search_tools and loads it with invoke_tool. An
// agent with no grant does not see it and cannot load it. A load always gives
// the content that the mission pinned, and the Timeline holds one event for
// each load.
//
// The agent of the test is an outside agent that the suite serves itself (see
// helpers.HeldAgent). It holds each mission open, so the test calls
// ComponentService.CallTool with the work id of the open work item, as an agent
// in pull mode does.
//
// The 10 points of the epic, and the subtest that holds each one:
//
//	1  a tenant publishes a folder, the entry holds the digest      "publish"
//	2  a granted agent searches and loads                           "a granted mission ..."
//	3  an agent with no grant sees nothing and is refused           "an agent with no grant ..."
//	4  a second tenant cannot find or load                          "a second tenant ..."
//	5  a script cannot reach a host outside the egress limit        "a script of an Agent Skill ..."
//	6  an Agent Skill that names a tool gives no tool               "an Agent Skill that names a tool ..."
//	7  a path outside the folder is refused                         "a file path outside ..."
//	8  a new publish does not change a running mission              "a new publish ..."
//	9  a mission that denies the Agent Skill cannot load it         "a mission that denies ..."
//	10 the Timeline holds one load event with the digest            "the Timeline ..."
//
// The Shared Agent Skill of the operator (gibson#1376) has one more subtest:
// "a Shared Agent Skill ...". The daemon writes the platform_enabled tuple of the
// name in its config at start. The tenant lists it, enables it, and still no
// agent loads it before a grant.
//
// Point 5 covers what exists. The sandbox files of an Agent Skill are not built
// (gibson#1373). So the test loads the script as text with invoke_tool, reads the
// command in it, and runs that command with the nmap tool in a sandbox, as a
// mission TOOL node. The workflow then reads the Cilium drop records and fails
// when the network let a packet reach the host. The agent that loads the script
// and the node that runs it are two parts of the test, not one agent.
//
// It needs GIBSON_TEST_FIXTURES_ENABLED=true and DAEMON_GRPC_ADDR, and the
// variables that exit-test-agent-skills.yml writes (agentSkillEnv* below).
package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	worldpb "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/world/v1"
	"github.com/zeroroot-ai/gibson/tests/e2e/helpers"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
	secretsv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/secrets/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

const (
	agentSkillTenant = "primary"
	// agentSkillStranger is a tenant that the profile does not provision. The
	// suite only asserts that this tenant gets nothing.
	agentSkillStranger = "e2e-stranger"
	agentSkillAgent    = "e2e-skill-agent"

	agentSkillAlpha     = "e2e-alpha"
	agentSkillProbe     = "e2e-probe"
	agentSkillToolnamer = "e2e-toolnamer"
	// agentSkillShared is the Shared Agent Skill that the operator config offers.
	// The workflow writes its name and its reference into the daemon config.
	agentSkillShared = "e2e-shared"
	phantomTool      = "e2e-phantom-tool"

	// The tenant secret that holds the registry credential, as a docker config.
	agentSkillRegistrySecret = "e2e-skill-registry"

	// The variables of the workflow. Each *Ref holds a digest reference that the
	// pack command of tests/fixtures/agentskills printed.
	agentSkillEnvAlphaV1       = "E2E_SKILL_REF_ALPHA_V1"
	agentSkillEnvAlphaV2       = "E2E_SKILL_REF_ALPHA_V2"
	agentSkillEnvProbe         = "E2E_SKILL_REF_PROBE"
	agentSkillEnvToolnamer     = "E2E_SKILL_REF_TOOLNAMER"
	agentSkillEnvShared        = "E2E_SKILL_REF_SHARED"
	agentSkillEnvRegistry      = "E2E_SKILL_REGISTRY"
	agentSkillEnvRegistryUser  = "E2E_SKILL_REGISTRY_USERNAME"
	agentSkillEnvRegistryToken = "E2E_SKILL_REGISTRY_PASSWORD"
	agentSkillEnvEgressIP      = "E2E_EGRESS_BLOCKED_IP"
	agentSkillEnvEgressPort    = "E2E_EGRESS_BLOCKED_PORT"

	agentSkillMissionTimeout = 6 * time.Minute
)

// requireEnv returns the value of a variable. The test fails when it is empty,
// because a missing variable means the workflow did not set the test up.
func requireEnv(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		t.Fatalf("%s is empty: exit-test-agent-skills.yml did not give the suite its fixture", name)
	}
	return v
}

// digestOf returns the digest of a digest reference.
func digestOf(t *testing.T, ref string) string {
	t.Helper()
	_, d, ok := strings.Cut(ref, "@")
	require.True(t, ok, "the reference %q holds no digest", ref)
	return d
}

// skillMeta is the answer of CallTool for a meta-tool. Err is the error of the
// reply, or nil.
type skillMeta struct {
	Output string
	Err    *componentpb.ComponentError
}

// callMeta calls a meta-tool with the work id of an open work item.
func callMeta(
	ctx context.Context, t *testing.T, comp componentpb.ComponentServiceClient, workID, tool string, input any,
) skillMeta {
	t.Helper()
	raw, err := json.Marshal(input)
	require.NoError(t, err, "encode the input of %s", tool)
	resp, err := comp.CallTool(ctx, &componentpb.CallToolRequest{WorkId: workID, ToolName: tool, InputJson: string(raw)})
	require.NoError(t, err, "CallTool(%s)", tool)
	return skillMeta{Output: resp.GetOutputJson(), Err: resp.GetError()}
}

// searchIDs returns the ids that search_tools returns for a query.
func searchIDs(
	ctx context.Context, t *testing.T, comp componentpb.ComponentServiceClient, workID, query string,
) []string {
	t.Helper()
	reply := callMeta(ctx, t, comp, workID, "search_tools", map[string]any{"query": query, "limit": 50})
	require.Nil(t, reply.Err, "search_tools(%q) must not fail: %v", query, reply.Err)
	var out struct {
		Candidates []struct {
			ID string `json:"id"`
		} `json:"candidates"`
	}
	require.NoError(t, json.Unmarshal([]byte(reply.Output), &out), "decode the search result: %s", reply.Output)
	ids := make([]string, 0, len(out.Candidates))
	for _, c := range out.Candidates {
		ids = append(ids, c.ID)
	}
	return ids
}

// skillResult is the result of a load of the body.
type skillResult struct {
	Result struct {
		Name         string   `json:"name"`
		Digest       string   `json:"digest"`
		Body         string   `json:"body"`
		AllowedTools []string `json:"allowed_tools"`
		Files        []struct {
			Path string `json:"path"`
		} `json:"files"`
		File    string `json:"file"`
		Content string `json:"content"`
	} `json:"result"`
}

// invoke loads an Agent Skill, or one file of it when file is set.
func invoke(
	ctx context.Context, t *testing.T, comp componentpb.ComponentServiceClient, workID, name, file string,
) (skillResult, *componentpb.ComponentError) {
	t.Helper()
	args := map[string]any{}
	if file != "" {
		args["file"] = file
	}
	reply := callMeta(ctx, t, comp, workID, "invoke_tool", map[string]any{"id": "skill:" + name, "args": args})
	if reply.Err != nil {
		return skillResult{}, reply.Err
	}
	var out skillResult
	require.NoError(t, json.Unmarshal([]byte(reply.Output), &out), "decode the load result: %s", reply.Output)
	return out, nil
}

// requireDenied checks that a reply is a refusal by permission.
func requireDenied(t *testing.T, e *componentpb.ComponentError, what string) {
	t.Helper()
	require.NotNil(t, e, "%s must be refused", what)
	require.Contains(t, e.GetCode(), "PERMISSION_DENIED", "%s must be refused by permission: %s", what, e.GetMessage())
}

// skillLoads returns the load events of one Agent Skill on the Timeline of a
// mission.
func skillLoads(
	ctx context.Context, t *testing.T, world worldpb.WorldServiceClient, missionID, name string,
) []helpers.TimelineEvent {
	t.Helper()
	events, err := helpers.ReadTimeline(ctx, world, missionID)
	require.NoError(t, err, "read the Timeline of mission %s", missionID)
	var out []helpers.TimelineEvent
	for _, ev := range helpers.OfKind(events, "agent_skill.loaded") {
		if strings.Contains(ev.Summary, "Name:"+name+" ") || strings.Contains(ev.Summary, "Name:"+name+"}") {
			out = append(out, ev)
		}
	}
	return out
}

// TestAgentSkills is the exit test of gibson#1377.
func TestAgentSkills(t *testing.T) {
	checkTestFixturesEnabled(t)
	refAlphaV1 := requireEnv(t, agentSkillEnvAlphaV1)
	refAlphaV2 := requireEnv(t, agentSkillEnvAlphaV2)
	refProbe := requireEnv(t, agentSkillEnvProbe)
	refToolnamer := requireEnv(t, agentSkillEnvToolnamer)
	refShared := requireEnv(t, agentSkillEnvShared)
	registry := requireEnv(t, agentSkillEnvRegistry)
	registryUser := requireEnv(t, agentSkillEnvRegistryUser)
	registryToken := requireEnv(t, agentSkillEnvRegistryToken)
	egressIP := requireEnv(t, agentSkillEnvEgressIP)
	egressPort := requireEnv(t, agentSkillEnvEgressPort)
	digestV1, digestV2 := digestOf(t, refAlphaV1), digestOf(t, refAlphaV2)
	digestShared := digestOf(t, refShared)
	require.NotEqual(t, digestV1, digestV2, "the two versions of the alpha Agent Skill must differ in their digest")

	clients, err := helpers.NewGRPCClients()
	require.NoError(t, err, "dial daemon at DAEMON_GRPC_ADDR")
	t.Cleanup(func() { _ = clients.Close() })
	ctx := auth.ContextWithTenantString(context.Background(), agentSkillTenant)

	skills := tenantv1.NewAgentSkillServiceClient(clients.Conn())
	membership := tenantv1.NewMembershipServiceClient(clients.Conn())
	secrets := secretsv1.NewSecretsServiceClient(clients.Conn())
	comp := componentpb.NewComponentServiceClient(clients.Conn())
	world := worldpb.NewWorldServiceClient(clients.Conn())

	// A clean start: no version and no grant of an earlier run.
	for _, n := range []string{agentSkillAlpha, agentSkillProbe, agentSkillToolnamer, agentSkillShared} {
		_, derr := skills.DeleteAgentSkill(ctx, &tenantv1.DeleteAgentSkillRequest{Name: n})
		if derr != nil && status.Code(derr) != codes.NotFound {
			require.NoError(t, derr, "DeleteAgentSkill(%s) before the run", n)
		}
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(auth.ContextWithTenantString(context.Background(), agentSkillTenant), 30*time.Second)
		defer cancel()
		for _, n := range []string{agentSkillAlpha, agentSkillProbe, agentSkillToolnamer, agentSkillShared} {
			_, _ = skills.DeleteAgentSkill(c, &tenantv1.DeleteAgentSkillRequest{Name: n})
		}
	})

	// The registry credential, as the bytes of a docker config. The daemon reads
	// it for one publish and never stores it.
	dockerConfig, err := json.Marshal(map[string]any{"auths": map[string]any{
		registry: map[string]string{"username": registryUser, "password": registryToken},
	}})
	require.NoError(t, err, "encode the docker config")
	_, err = secrets.SetSecret(ctx, &secretsv1.SetSecretRequest{
		Name: agentSkillRegistrySecret, Category: secretsv1.SecretCategory_SECRET_CATEGORY_CRED, Value: dockerConfig,
	})
	require.NoError(t, err, "SetSecret(%s)", agentSkillRegistrySecret)
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(auth.ContextWithTenantString(context.Background(), agentSkillTenant), 30*time.Second)
		defer cancel()
		_, _ = secrets.DeleteSecret(c, &secretsv1.DeleteSecretRequest{Name: agentSkillRegistrySecret})
	})

	publish := func(name, ref string) *tenantv1.AgentSkillEntry {
		t.Helper()
		resp, perr := skills.PublishAgentSkill(ctx, &tenantv1.PublishAgentSkillRequest{
			Name: name, Reference: ref, RegistrySecret: agentSkillRegistrySecret,
		})
		require.NoError(t, perr, "PublishAgentSkill(%s, %s): the daemon must pull the image from the registry", name, ref)
		return resp.GetEntry()
	}
	grantMission := func(name, missionID string) {
		t.Helper()
		_, gerr := skills.GrantAgentSkill(ctx, &tenantv1.GrantAgentSkillRequest{
			Name: name, SubjectKind: tenantv1.AgentSkillSubjectKind_AGENT_SKILL_SUBJECT_KIND_MISSION, SubjectId: missionID,
		})
		require.NoError(t, gerr, "GrantAgentSkill(%s) to mission %s", name, missionID)
	}

	// The synthetic target of the missions.
	targetID, err := helpers.RegisterTestTarget(ctx, clients.Daemon, toolTargetName, toolTargetURL)
	require.NoError(t, err, "register the synthetic target")
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		helpers.DeleteTestTarget(auth.ContextWithTenantString(c, agentSkillTenant), clients.Daemon, targetID)
	})

	t.Run("publish: the catalog entry holds the digest of the folder", func(t *testing.T) {
		entry := publish(agentSkillAlpha, refAlphaV1)
		require.Equal(t, agentSkillAlpha, entry.GetName())
		require.Equal(t, digestV1, entry.GetDigest(), "the entry must hold the digest of the reference")
		require.True(t, entry.GetCurrent(), "the first publish is the current version")
		list, lerr := skills.ListAgentSkills(ctx, &tenantv1.ListAgentSkillsRequest{Name: agentSkillAlpha})
		require.NoError(t, lerr, "ListAgentSkills")
		require.Len(t, list.GetEntries(), 1, "the catalog must hold one version")
		require.Equal(t, digestV1, list.GetEntries()[0].GetDigest())
	})
	publish(agentSkillToolnamer, refToolnamer)
	publish(agentSkillProbe, refProbe)

	agent := helpers.StartHeldAgent(ctx, t, comp, membership, agentSkillAgent)
	newMission := func(name string, c *missionpb.MissionConstraints) (*helpers.MissionRun, *helpers.HeldWork) {
		t.Helper()
		defID := helpers.CreateAgentMission(ctx, t, clients.Daemon, name, agentSkillAgent, c)
		run := helpers.StartMission(ctx, t, clients.Daemon, defID, targetID)
		w := agent.Next(t, agentSkillMissionTimeout)
		require.NotEmpty(t, w.MissionID, "the work item of mission %s names no mission", name)
		return run, w
	}

	// Mission A: points 3, 2, 10, 7, 6, 4 and 8, in this order.
	runA, workA := newMission("agent-skills-exit-a", nil)
	missionA := workA.MissionID

	t.Run("an agent with no grant sees nothing and cannot load", func(t *testing.T) {
		ids := searchIDs(ctx, t, comp, workA.WorkID, agentSkillAlpha)
		require.NotContains(t, ids, "skill:"+agentSkillAlpha, "an Agent Skill with no grant must not be in a search")
		_, e := invoke(ctx, t, comp, workA.WorkID, agentSkillAlpha, "")
		requireDenied(t, e, "a load by id with no grant")
		require.Empty(t, skillLoads(ctx, t, world, missionA, agentSkillAlpha), "a refused load must leave no event")
	})

	t.Run("a granted mission finds the Agent Skill and loads the body", func(t *testing.T) {
		grantMission(agentSkillAlpha, missionA)
		helpers.Eventually(t, time.Minute, "the granted mission finds skill:"+agentSkillAlpha, func() (bool, string) {
			ids := searchIDs(ctx, t, comp, workA.WorkID, agentSkillAlpha)
			return containsString(ids, "skill:"+agentSkillAlpha), fmt.Sprint(ids)
		})
		got, e := invoke(ctx, t, comp, workA.WorkID, agentSkillAlpha, "")
		require.Nil(t, e, "the granted mission must load the Agent Skill: %v", e)
		require.Equal(t, digestV1, got.Result.Digest)
		require.Contains(t, got.Result.Body, "ALPHA-BODY-VERSION-1")
		var paths []string
		for _, f := range got.Result.Files {
			paths = append(paths, f.Path)
		}
		require.Contains(t, paths, "references/notes.md", "the file list must name the reference file")
	})

	t.Run("the Timeline holds one load event with the digest", func(t *testing.T) {
		helpers.Eventually(t, time.Minute, "one load event of the body", func() (bool, string) {
			loads := skillLoads(ctx, t, world, missionA, agentSkillAlpha)
			return len(loads) == 1, fmt.Sprint(loads)
		})
		loads := skillLoads(ctx, t, world, missionA, agentSkillAlpha)
		require.Contains(t, loads[0].Summary, "Digest:"+digestV1, "the event must hold the digest that the agent got")
		require.Contains(t, loads[0].Summary, "MissionID:"+missionA)
	})

	t.Run("a file path outside the folder is refused", func(t *testing.T) {
		got, e := invoke(ctx, t, comp, workA.WorkID, agentSkillAlpha, "references/notes.md")
		require.Nil(t, e, "a file of the folder must load: %v", e)
		require.Contains(t, got.Result.Content, "ALPHA-NOTES-VERSION-1")
		for _, bad := range []string{"../SKILL.md", "/etc/passwd", "references/../../x", "scripts/../../../etc/passwd"} {
			_, e := invoke(ctx, t, comp, workA.WorkID, agentSkillAlpha, bad)
			require.NotNil(t, e, "the path %q must be refused", bad)
			require.Contains(t, e.GetMessage(), "not inside the folder", "the path %q must be refused as a path outside the folder", bad)
		}
		_, e = invoke(ctx, t, comp, workA.WorkID, agentSkillAlpha, "references/missing.md")
		require.NotNil(t, e, "a file that the folder does not hold must be refused")
		// The body and one reference file are two loads. The refused paths add none.
		helpers.Eventually(t, time.Minute, "two load events", func() (bool, string) {
			loads := skillLoads(ctx, t, world, missionA, agentSkillAlpha)
			return len(loads) == 2, fmt.Sprint(len(loads))
		})
	})

	t.Run("an Agent Skill that names a tool gives the agent no new tool", func(t *testing.T) {
		grantMission(agentSkillToolnamer, missionA)
		helpers.Eventually(t, time.Minute, "the toolnamer load", func() (bool, string) {
			got, e := invoke(ctx, t, comp, workA.WorkID, agentSkillToolnamer, "")
			if e != nil {
				return false, e.GetMessage()
			}
			return containsString(got.Result.AllowedTools, phantomTool), fmt.Sprint(got.Result.AllowedTools)
		})
		for _, id := range searchIDs(ctx, t, comp, workA.WorkID, phantomTool) {
			require.False(t, strings.HasSuffix(id, ":"+phantomTool) || id == phantomTool,
				"the search must not list the tool %s that the Agent Skill names; got %s", phantomTool, id)
		}
		_, err := comp.CallTool(ctx, &componentpb.CallToolRequest{WorkId: workA.WorkID, ToolName: phantomTool, InputJson: "{}"})
		require.Error(t, err, "the agent must not be able to call the tool that the Agent Skill names")
		require.Equal(t, codes.NotFound, status.Code(err), "the tool is in no catalog: %v", err)
	})

	t.Run("a second tenant cannot find or load a Tenant Agent Skill", func(t *testing.T) {
		// The profile has one provisioned tenant, and the runner holds no
		// membership in another one. So this subtest proves that a caller of
		// another tenant gets nothing. It does not run an agent of a second
		// provisioned tenant.
		other := auth.ContextWithTenantString(context.Background(), agentSkillStranger)
		list, lerr := skills.ListAgentSkills(other, &tenantv1.ListAgentSkillsRequest{})
		if lerr != nil {
			requireOneOf(t, status.Code(lerr), "ListAgentSkills of a second tenant", codes.PermissionDenied, codes.NotFound)
		} else {
			for _, e := range list.GetEntries() {
				require.NotEqual(t, agentSkillAlpha, e.GetName(), "a second tenant must not list a Tenant Agent Skill")
			}
		}
		_, gerr := skills.GetAgentSkill(other, &tenantv1.GetAgentSkillRequest{Name: agentSkillAlpha})
		require.Error(t, gerr, "a second tenant must not read a Tenant Agent Skill")
		requireOneOf(t, status.Code(gerr), "GetAgentSkill of a second tenant", codes.PermissionDenied, codes.NotFound)
		// The work item of tenant primary is not an item of the second tenant.
		raw, merr := json.Marshal(map[string]any{"id": "skill:" + agentSkillAlpha, "args": map[string]any{}})
		require.NoError(t, merr)
		resp, cerr := comp.CallTool(other, &componentpb.CallToolRequest{WorkId: workA.WorkID, ToolName: "invoke_tool", InputJson: string(raw)})
		if cerr == nil {
			require.NotNil(t, resp.GetError(), "a second tenant must not load with the work item of tenant %s", agentSkillTenant)
		}
	})

	t.Run("a new publish does not change the content that a running mission loads", func(t *testing.T) {
		entry := publish(agentSkillAlpha, refAlphaV2)
		require.Equal(t, digestV2, entry.GetDigest())
		require.True(t, entry.GetCurrent(), "the new publish is the current version")
		list, lerr := skills.ListAgentSkills(ctx, &tenantv1.ListAgentSkillsRequest{Name: agentSkillAlpha, AllVersions: true})
		require.NoError(t, lerr)
		require.Len(t, list.GetEntries(), 2, "the old digest stays readable")
		got, e := invoke(ctx, t, comp, workA.WorkID, agentSkillAlpha, "")
		require.Nil(t, e, "the running mission must still load: %v", e)
		require.Equal(t, digestV1, got.Result.Digest, "the running mission must keep the digest that it pinned")
		require.Contains(t, got.Result.Body, "ALPHA-BODY-VERSION-1")
		for _, ev := range skillLoads(ctx, t, world, missionA, agentSkillAlpha) {
			require.NotContains(t, ev.Summary, digestV2, "no load of mission A may hold the new digest")
		}
	})

	workA.Complete()
	require.Equal(t, "mission_completed", runA.Wait(t, agentSkillMissionTimeout).EventType, "mission A must complete")

	t.Run("a new mission loads the new version", func(t *testing.T) {
		runB, workB := newMission("agent-skills-exit-b", nil)
		grantMission(agentSkillAlpha, workB.MissionID)
		helpers.Eventually(t, time.Minute, "mission B loads version 2", func() (bool, string) {
			got, e := invoke(ctx, t, comp, workB.WorkID, agentSkillAlpha, "")
			if e != nil {
				return false, e.GetMessage()
			}
			return got.Result.Digest == digestV2 && strings.Contains(got.Result.Body, "ALPHA-BODY-VERSION-2"), got.Result.Digest
		})
		workB.Complete()
		require.Equal(t, "mission_completed", runB.Wait(t, agentSkillMissionTimeout).EventType)
	})

	t.Run("a mission that denies the Agent Skill cannot load it", func(t *testing.T) {
		runC, workC := newMission("agent-skills-exit-c", &missionpb.MissionConstraints{
			BlockedTools: []string{"skill:" + agentSkillAlpha},
		})
		// The grant allows the load. Only the deny list of the mission stops it.
		grantMission(agentSkillAlpha, workC.MissionID)
		time.Sleep(5 * time.Second)
		ids := searchIDs(ctx, t, comp, workC.WorkID, agentSkillAlpha)
		require.NotContains(t, ids, "skill:"+agentSkillAlpha, "a denied Agent Skill must not be in a search")
		_, e := invoke(ctx, t, comp, workC.WorkID, agentSkillAlpha, "")
		requireDenied(t, e, "a load of a denied Agent Skill")
		require.Empty(t, skillLoads(ctx, t, world, workC.MissionID, agentSkillAlpha), "a denied load must leave no event")
		workC.Complete()
		require.Equal(t, "mission_completed", runC.Wait(t, agentSkillMissionTimeout).EventType)
	})

	t.Run("a Shared Agent Skill reaches the tenant and loads only after a grant", func(t *testing.T) {
		// The daemon wrote the platform_enabled tuple of each name in its config
		// at start. The operator source lists the name with the digest that the
		// daemon pulled, and the tenant holds no copy yet.
		list, lerr := skills.ListSharedAgentSkills(ctx, &tenantv1.ListSharedAgentSkillsRequest{})
		require.NoError(t, lerr, "ListSharedAgentSkills")
		var offer *tenantv1.SharedAgentSkillEntry
		for _, e := range list.GetEntries() {
			if e.GetName() == agentSkillShared {
				offer = e
			}
		}
		require.NotNil(t, offer, "the operator config names %s, so the daemon must offer it", agentSkillShared)
		require.Equal(t, digestShared, offer.GetDigest(), "the offer must hold the digest of the configured reference")
		require.False(t, offer.GetEnabled(), "the tenant holds no copy before it enables the Agent Skill")

		// The platform gate is closed for a name that the config does not hold.
		_, nerr := skills.EnableSharedAgentSkill(ctx, &tenantv1.EnableSharedAgentSkillRequest{Name: "e2e-not-offered"})
		require.Error(t, nerr, "a name that the operator does not offer must not be enabled")
		require.Equal(t, codes.NotFound, status.Code(nerr), "a name that the operator does not offer: %v", nerr)

		// The gate is open for the configured name. The call copies the Agent
		// Skill into the tenant and writes no grant.
		resp, eerr := skills.EnableSharedAgentSkill(ctx, &tenantv1.EnableSharedAgentSkillRequest{Name: agentSkillShared})
		require.NoError(t, eerr, "EnableSharedAgentSkill: the platform_enabled tuple of %s must exist", agentSkillShared)
		require.Equal(t, agentSkillShared, resp.GetEntry().GetName())
		require.Equal(t, digestShared, resp.GetEntry().GetDigest())
		require.Equal(t, tenantv1.AgentSkillSource_AGENT_SKILL_SOURCE_SHARED, resp.GetEntry().GetSource())
		catalog, cerr := skills.ListAgentSkills(ctx, &tenantv1.ListAgentSkillsRequest{Name: agentSkillShared})
		require.NoError(t, cerr, "ListAgentSkills")
		require.Len(t, catalog.GetEntries(), 1, "the catalog of the tenant must hold the Shared Agent Skill")
		list, lerr = skills.ListSharedAgentSkills(ctx, &tenantv1.ListSharedAgentSkillsRequest{})
		require.NoError(t, lerr)
		for _, e := range list.GetEntries() {
			if e.GetName() == agentSkillShared {
				require.True(t, e.GetEnabled(), "the offer must show the copy of the tenant")
			}
		}

		// An enabled Agent Skill is still not loadable. A mission needs a grant.
		runE, workE := newMission("agent-skills-exit-e", nil)
		ids := searchIDs(ctx, t, comp, workE.WorkID, agentSkillShared)
		require.NotContains(t, ids, "skill:"+agentSkillShared, "a Shared Agent Skill with no grant must not be in a search")
		_, e := invoke(ctx, t, comp, workE.WorkID, agentSkillShared, "")
		requireDenied(t, e, "a load of a Shared Agent Skill with no grant")
		require.Empty(t, skillLoads(ctx, t, world, workE.MissionID, agentSkillShared), "a refused load must leave no event")

		grantMission(agentSkillShared, workE.MissionID)
		helpers.Eventually(t, time.Minute, "the granted mission loads the Shared Agent Skill", func() (bool, string) {
			got, le := invoke(ctx, t, comp, workE.WorkID, agentSkillShared, "")
			if le != nil {
				return false, le.GetMessage()
			}
			return got.Result.Digest == digestShared && strings.Contains(got.Result.Body, "SHARED-BODY"), got.Result.Digest
		})
		workE.Complete()
		require.Equal(t, "mission_completed", runE.Wait(t, agentSkillMissionTimeout).EventType)
	})

	t.Run("a script of an Agent Skill cannot reach a host outside the egress limit", func(t *testing.T) {
		runD, workD := newMission("agent-skills-exit-d", nil)
		grantMission(agentSkillProbe, workD.MissionID)
		var script string
		helpers.Eventually(t, time.Minute, "the probe Agent Skill loads", func() (bool, string) {
			got, e := invoke(ctx, t, comp, workD.WorkID, agentSkillProbe, "scripts/probe.sh")
			if e != nil {
				return false, e.GetMessage()
			}
			script = got.Result.Content
			return true, ""
		})
		m := regexp.MustCompile(`(?m)^nmap -Pn -p (\d+) (\S+)$`).FindStringSubmatch(script)
		require.NotNil(t, m, "the script must hold the nmap command; got:\n%s", script)
		require.Equal(t, egressPort, m[1], "the script names the port of the workflow")
		require.Equal(t, egressIP, m[2], "the script names the host of the workflow")
		workD.Complete()
		require.Equal(t, "mission_completed", runD.Wait(t, agentSkillMissionTimeout).EventType)

		// The execution tool: the nmap tool in a sandbox runs the command of the
		// script. The mission completes when the sandbox ran the scan. The
		// workflow checks that the network dropped each packet to the host.
		_, serr := membership.SetCatalogEnabled(ctx, &tenantv1.SetCatalogEnabledRequest{ComponentRef: toolComponentRef, Enabled: true})
		require.NoError(t, serr, "SetCatalogEnabled(%s)", toolComponentRef)
		t.Cleanup(func() {
			c, cancel := context.WithTimeout(auth.ContextWithTenantString(context.Background(), agentSkillTenant), 15*time.Second)
			defer cancel()
			_, _ = membership.SetCatalogEnabled(c, &tenantv1.SetCatalogEnabledRequest{ComponentRef: toolComponentRef, Enabled: false})
		})
		cidrTarget, terr := helpers.RegisterTestTargetOfType(ctx, clients.Daemon, "skill-egress-e2e", "network", m[2]+"/32")
		require.NoError(t, terr, "register the target that holds the host of the script")
		t.Cleanup(func() {
			c, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			helpers.DeleteTestTarget(auth.ContextWithTenantString(c, agentSkillTenant), clients.Daemon, cidrTarget)
		})
		defID := createToolMissionDefinitionWithInput(t, ctx, clients.Daemon, "agent-skill-script-e2e", toolName,
			map[string]string{"target": m[2], "ports": m[1], "args": `["-Pn"]`})
		terminal, reason := runProbeMission(t, ctx, clients.Daemon, defID, cidrTarget)
		require.Equal(t, "mission_completed", terminal.EventType,
			"the sandbox must run the command of the script and the scan must end; reason: %s", reason)
	})
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func requireOneOf(t *testing.T, got codes.Code, what string, want ...codes.Code) {
	t.Helper()
	for _, w := range want {
		if got == w {
			return
		}
	}
	t.Fatalf("%s answered %s, want one of %v", what, got, want)
}
