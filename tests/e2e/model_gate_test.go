// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build e2e
// +build e2e

// Package e2e: the model-gate exit test (hosted#358).
//
// In plain words: a member of a tenant runs a mission and its agent gets a
// model through the default grant of the tenant, with no grant written by
// hand. When an administrator revokes the tenant grant on the Model Access
// page, the same mission is refused, and the refusal names the gate. When the
// administrator grants it again, the mission gets a model again.
//
// The parts:
//   - The tenant's provider is the deterministic e2e mock (the fixture provider
//     type, llm.FixtureProviderType), configured through the ProviderService
//     RPC like any provider. The tenant's slot manager serves it, behind the
//     tenant's model gate.
//   - The agent of the mission node is served by this suite: it registers as
//     an outside agent, polls the node's work, calls ComponentService.Complete
//     with the work id, and submits what the completion returned. That is the
//     path of an agent served with sdk.ServeAgent.
//   - Revoke and grant go through ModelAccessService RevokeAccess and
//     GrantAccess, the RPCs of the dashboard Model Access page. The runner is
//     a member and an admin of the tenant (the fixture seed).
//
// It needs GIBSON_TEST_FIXTURES_ENABLED=true and DAEMON_GRPC_ADDR, like the
// other in-cluster suites. exit-test-model-gate.yml runs it.
package e2e

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/gibson/tests/e2e/helpers"
	agentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/agent/v1"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	daemonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

const (
	// modelGateTenant is the tenant that the baseline profile provisions.
	modelGateTenant = "primary"
	// modelGateProvider is the fixture provider type and its registry name.
	modelGateProvider = "mock-llm-e2e-test"
	// modelGateAgent is the outside agent that this suite serves. The name is
	// in no catalog, so an unattested registration may take it.
	modelGateAgent = "e2e-model-probe"
	// modelGateDenied is the word the model gate puts in each refusal
	// (DaemonSlotManager.applyModelGate).
	modelGateDenied = "model_access_denied"
	// modelGateMissionTimeout bounds one mission run.
	modelGateMissionTimeout = 5 * time.Minute
)

// probeAgent serves the agent node of the mission as an outside agent.
type probeAgent struct {
	comp       componentpb.ComponentServiceClient
	instanceID string

	mu      sync.Mutex
	replies []string
	errs    []string
}

// serve polls work until ctx ends. For each work item it calls Complete on the
// primary slot with the work id, and submits the content, or the completion
// error as the work error.
func (p *probeAgent) serve(ctx context.Context, t *testing.T) {
	for ctx.Err() == nil {
		work, err := p.comp.PollWork(ctx, &componentpb.PollWorkRequest{InstanceId: p.instanceID, TimeoutMs: 5000})
		if err != nil {
			if ctx.Err() == nil {
				t.Logf("probe agent: PollWork: %v", err)
				time.Sleep(time.Second)
			}
			continue
		}
		if work.GetWorkId() == "" {
			continue
		}
		resp, cerr := p.comp.Complete(ctx, &componentpb.CompleteRequest{
			WorkId:   work.GetWorkId(),
			Slot:     "primary",
			Messages: []*componentpb.LLMMessage{{Role: "user", Content: "Say the deterministic reply."}},
		})
		submit := &componentpb.SubmitResultRequest{WorkId: work.GetWorkId()}
		if cerr != nil {
			p.mu.Lock()
			p.errs = append(p.errs, cerr.Error())
			p.mu.Unlock()
			submit.Error = &componentpb.ComponentError{Code: "LLM_COMPLETE_FAILED", Message: cerr.Error()}
		} else {
			content := resp.GetResponse().GetContent()
			p.mu.Lock()
			p.replies = append(p.replies, content)
			p.mu.Unlock()
			out, merr := protojson.Marshal(&agentpb.ExecuteResponse{
				Result: &typespb.Result{Status: typespb.ResultStatus_RESULT_STATUS_SUCCESS},
			})
			require.NoError(t, merr)
			submit.Result = out
		}
		if _, err := p.comp.SubmitResult(ctx, submit); err != nil && ctx.Err() == nil {
			t.Logf("probe agent: SubmitResult(%s): %v", work.GetWorkId(), err)
		}
	}
}

// heartbeat keeps the registration alive until ctx ends.
func (p *probeAgent) heartbeat(ctx context.Context) {
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			_, _ = p.comp.Heartbeat(ctx, &componentpb.HeartbeatRequest{InstanceId: p.instanceID, HealthStatus: "healthy"})
		}
	}
}

func (p *probeAgent) last() (reply, errText string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.replies) > 0 {
		reply = p.replies[len(p.replies)-1]
	}
	if len(p.errs) > 0 {
		errText = p.errs[len(p.errs)-1]
	}
	return reply, errText
}

func (p *probeAgent) counts() (replies, errs int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.replies), len(p.errs)
}

// createProbeMissionDefinition creates a mission with one AGENT node that the
// probe agent serves, and returns its id. Each phase of the test runs its own
// mission: a second run of one mission does nothing today (gibson#1217). The
// gate decides for the tenant and the provider, not for the mission, so the
// proof is the same.
func createProbeMissionDefinition(t *testing.T, ctx context.Context, daemon daemonpb.DaemonServiceClient, name string) string {
	t.Helper()
	resp, err := daemon.CreateMissionDefinition(ctx, &daemonpb.CreateMissionDefinitionRequest{
		Definition: &missionpb.MissionDefinition{
			Name:        name,
			Description: "hosted#358 model gate exit test",
			Nodes: map[string]*missionpb.MissionNode{
				"probe": {
					Id:          "probe",
					Name:        "Probe",
					Description: "One completion on the primary slot",
					Type:        missionpb.NodeType_NODE_TYPE_AGENT,
					Config: &missionpb.MissionNode_AgentConfig{
						AgentConfig: &missionpb.AgentNodeConfig{AgentName: modelGateAgent},
					},
				},
			},
		},
	})
	require.NoError(t, err, "CreateMissionDefinition")
	require.NotEmpty(t, resp.GetMissionDefinitionId())
	return resp.GetMissionDefinitionId()
}

// runProbeMission runs the mission to a terminal state and returns the
// terminal event and the failure reason.
func runProbeMission(t *testing.T, ctx context.Context, daemon daemonpb.DaemonServiceClient, defID, targetID string) (helpers.MissionEvent, string) {
	t.Helper()
	runCtx, cancel := context.WithTimeout(ctx, modelGateMissionTimeout)
	defer cancel()
	events, err := helpers.Subscribe(runCtx, daemon, defID, targetID)
	require.NoError(t, err, "RunMission")
	terminal, collected, err := helpers.WaitForTerminal(runCtx, events, modelGateMissionTimeout-30*time.Second)
	require.NoError(t, err, "the mission must reach a terminal state")
	for _, ev := range collected {
		t.Logf("event: %s", ev)
	}
	return terminal, failureReason(terminal, collected)
}

func tenantProviderGrant(tenant string) *tenantv1.AccessGrant {
	return &tenantv1.AccessGrant{
		TenantId:    tenant,
		SubjectKind: tenantv1.GrantSubjectKind_GRANT_SUBJECT_KIND_TENANT,
		SubjectId:   tenant,
		TargetKind:  tenantv1.GrantTargetKind_GRANT_TARGET_KIND_PROVIDER,
		TargetId:    modelGateProvider,
	}
}

// tenantHoldsProviderGrant reports whether the tenant's members hold can_use
// on the mock provider, as the Model Access page lists it.
func tenantHoldsProviderGrant(t *testing.T, ctx context.Context, access tenantv1.ModelAccessServiceClient) bool {
	t.Helper()
	list, err := access.ListAccess(ctx, &tenantv1.ListAccessRequest{
		SubjectKind: tenantv1.GrantSubjectKind_GRANT_SUBJECT_KIND_TENANT,
		SubjectId:   modelGateTenant,
	})
	require.NoError(t, err, "ListAccess for the tenant")
	for _, g := range list.GetGrants() {
		if g.GetTargetKind() == tenantv1.GrantTargetKind_GRANT_TARGET_KIND_PROVIDER && g.GetTargetId() == modelGateProvider {
			return true
		}
	}
	return false
}

// TestModelGate_DefaultGrantRevokeAndGrantAgain is the hosted#358 exit test.
func TestModelGate_DefaultGrantRevokeAndGrantAgain(t *testing.T) {
	checkTestFixturesEnabled(t)
	clients, err := helpers.NewGRPCClients()
	require.NoError(t, err, "dial daemon at DAEMON_GRPC_ADDR")
	t.Cleanup(func() { _ = clients.Close() })
	ctx := auth.ContextWithTenantString(context.Background(), modelGateTenant)

	providers := tenantv1.NewProviderServiceClient(clients.Conn())
	membership := tenantv1.NewMembershipServiceClient(clients.Conn())
	access := tenantv1.NewModelAccessServiceClient(clients.Conn())
	comp := componentpb.NewComponentServiceClient(clients.Conn())

	// The tenant's only provider is the deterministic mock. The window is
	// stated, so the save makes no list call.
	_, err = providers.CreateProvider(ctx, &tenantv1.CreateProviderRequest{Input: &tenantv1.ProviderConfigInput{
		Name: modelGateProvider, Type: modelGateProvider, SetAsDefault: true,
		DefaultModel: "mock-model", DefaultModelContextWindow: 200000,
	}})
	if status.Code(err) != codes.AlreadyExists {
		require.NoError(t, err, "CreateProvider(%s)", modelGateProvider)
	}

	// The probe agent: an outside agent of the tenant, enabled in the
	// tenant's catalog like any agent a member may run.
	reg, err := comp.RegisterComponent(ctx, &componentpb.RegisterComponentRequest{
		Kind: "agent", Name: modelGateAgent, Version: "1.0.0",
	})
	require.NoError(t, err, "RegisterComponent(%s)", modelGateAgent)
	_, err = membership.SetCatalogEnabled(ctx, &tenantv1.SetCatalogEnabledRequest{
		ComponentRef: "agent/" + modelGateAgent, Enabled: true,
	})
	require.NoError(t, err, "SetCatalogEnabled(agent/%s)", modelGateAgent)

	probe := &probeAgent{comp: comp, instanceID: reg.GetInstanceId()}
	agentCtx, stopAgent := context.WithCancel(ctx)
	t.Cleanup(stopAgent)
	go probe.serve(agentCtx, t)
	go probe.heartbeat(agentCtx)

	targetID, err := helpers.RegisterTestTarget(ctx, clients.Daemon, toolTargetName, toolTargetURL)
	require.NoError(t, err, "register the synthetic target")
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		helpers.DeleteTestTarget(auth.ContextWithTenantString(c, modelGateTenant), clients.Daemon, targetID)
	})
	t.Run("a member with no manual grant gets a model through the default tenant grant", func(t *testing.T) {
		defID := createProbeMissionDefinition(t, ctx, clients.Daemon, "model-gate-exit-default-grant")
		terminal, reason := runProbeMission(t, ctx, clients.Daemon, defID, targetID)
		require.Equal(t, "mission_completed", terminal.EventType, "the mission must complete; reason: %s", reason)
		reply, errText := probe.last()
		require.Equal(t, helpers.MockProviderDeterministicResponse, reply,
			"the agent's completion must be served by the mock; last completion error: %s", errText)
		require.True(t, tenantHoldsProviderGrant(t, ctx, access),
			"the model came through the default grant of the tenant, which the Model Access page lists")
	})

	t.Run("after the tenant grant is revoked the gate refuses the same mission", func(t *testing.T) {
		_, err := access.RevokeAccess(ctx, &tenantv1.RevokeAccessRequest{
			SubjectKind: tenantv1.GrantSubjectKind_GRANT_SUBJECT_KIND_TENANT,
			SubjectId:   modelGateTenant,
			TargetKind:  tenantv1.GrantTargetKind_GRANT_TARGET_KIND_PROVIDER,
			TargetId:    modelGateProvider,
		})
		require.NoError(t, err, "RevokeAccess of the tenant grant")
		require.False(t, tenantHoldsProviderGrant(t, ctx, access), "the tenant grant is gone")

		_, errsBefore := probe.counts()
		defID := createProbeMissionDefinition(t, ctx, clients.Daemon, "model-gate-exit-revoked")
		terminal, reason := runProbeMission(t, ctx, clients.Daemon, defID, targetID)
		require.NotEqual(t, "mission_completed", terminal.EventType, "a mission with no model grant must not complete")
		_, errsAfter := probe.counts()
		require.Greater(t, errsAfter, errsBefore, "the agent's completion must be refused")
		_, errText := probe.last()
		require.Contains(t, errText, modelGateDenied, "the completion refusal must name the model gate")
		require.True(t, strings.Contains(reason, modelGateDenied),
			"the mission failure must name the model gate; reason: %s", reason)
	})

	t.Run("after a new grant the mission gets a model again", func(t *testing.T) {
		_, err := access.GrantAccess(ctx, &tenantv1.GrantAccessRequest{Grant: tenantProviderGrant(modelGateTenant)})
		require.NoError(t, err, "GrantAccess of the tenant grant")
		require.True(t, tenantHoldsProviderGrant(t, ctx, access), "the tenant grant is back")

		repliesBefore, _ := probe.counts()
		defID := createProbeMissionDefinition(t, ctx, clients.Daemon, "model-gate-exit-granted-again")
		terminal, reason := runProbeMission(t, ctx, clients.Daemon, defID, targetID)
		require.Equal(t, "mission_completed", terminal.EventType, "the mission must complete again; reason: %s", reason)
		repliesAfter, _ := probe.counts()
		require.Greater(t, repliesAfter, repliesBefore, "the agent's completion must be served again")
		reply, _ := probe.last()
		require.Equal(t, helpers.MockProviderDeterministicResponse, reply)
	})
}
