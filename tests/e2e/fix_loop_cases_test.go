// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build e2e
// +build e2e

// Package e2e: fix_loop_cases_test.go holds case 1 and case 2 of the fix loop exit
// test (gibson#1469). Both run the product path and read the daemon API only:
//
//	scan (the dependency alerts) -> fix agent -> coding job -> open_merge_request
//	  -> merge slot -> merge -> deploy (the auto deploy of the mock) -> health
//	  -> rescan -> verified, or revert and reopen
//
// Case 1: the agent fixes the flaw, the health signal holds, a rescan reads the
// alert as fixed, and the finding is verified with an exposure window.
// Case 2: the fix breaks the service. The daemon reverts it, the finding is open
// again, and the revert rate counts it.
//
// The test never writes a status and never writes a database. The mock forge is
// the stand-in for the tools of the buyer, so the test seeds it and changes its
// health value as the tools would change by themselves. It needs the key and the
// workspace id of the Anthropic provider, as the bank exit test does.
package e2e

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	worldpb "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/world/v1"
	"github.com/zeroroot-ai/gibson/tests/e2e/helpers"
	bankpb "github.com/zeroroot-ai/sdk/api/gen/gibson/bank/v1"
	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	daemonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

const (
	fixLoopFixAgent     = "fix-agent"
	fixLoopFixAgentRef  = "agent/" + fixLoopFixAgent
	fixLoopCaseTimeout  = 70 * time.Minute
	fixLoopScanInterval = 90 * time.Second
	// The advisory of the fixture. The repository requires the library at a
	// version that the range holds. The fix is one line of go.mod.
	fixLoopAdvisory = "GHSA-c2f3-g4h5-j6m7"
	fixLoopLibrary  = "github.com/acme/lib"
)

// seedAdvisoryRepository makes a repository with a go.mod that requires a
// vulnerable version of the library, an automatic deploy of each commit on the
// default branch, and the advisory. The mock derives the Dependabot alert from
// the content of go.mod, and it closes the alert when a commit on the default
// branch moves the requirement out of the range.
func (m *mockForge) seedAdvisoryRepository(t *testing.T, owner, repo string) {
	t.Helper()
	m.call(t, http.MethodPost, "/_mock/repos", map[string]any{
		"owner": owner, "repo": repo,
		"files": map[string]any{
			"go.mod":  "module github.com/" + owner + "/" + repo + "\n\ngo 1.22\n\nrequire " + fixLoopLibrary + " v1.2.0\n",
			"main.go": "package main\n\nfunc main() {}\n",
		},
		"auto_deploy": map[string]any{"environment": "production", "state": "success"},
	})
	m.call(t, http.MethodPost, "/_mock/advisories", map[string]any{
		"ghsa_id": fixLoopAdvisory, "cve_id": "CVE-2026-1111", "package": fixLoopLibrary, "ecosystem": "go",
		"vulnerable_version_range": ">= 1.0.0, < 1.2.4", "first_patched_version": "1.2.4", "severity": "high",
	})
}

// fixLoopWorld holds the clients and the ids that the two cases share.
type fixLoopWorld struct {
	ctx        context.Context
	clients    *helpers.GRPCClientSet
	forge      *mockForge
	daemon     daemonpb.DaemonServiceClient
	world      worldpb.WorldServiceClient
	targetID   string
	bankName   string
	scanParams func(app string) map[string]string
}

// bankName and the provider: the key goes into the provider configuration of the
// tenant through the RPC, and a bank of one catalog Claude member comes up.
func (w *fixLoopWorld) startBank(t *testing.T) {
	t.Helper()
	key := os.Getenv("EXIT_TEST_ANTHROPIC_API_KEY")
	require.NotEmpty(t, key, "EXIT_TEST_ANTHROPIC_API_KEY is not set: the fix agent needs the coding agents of a bank")
	workspace := os.Getenv("EXIT_TEST_ANTHROPIC_WORKSPACE_ID")
	require.NotEmpty(t, workspace, "EXIT_TEST_ANTHROPIC_WORKSPACE_ID is not set: the key works only with the header anthropic-workspace-id")

	providers := tenantv1.NewProviderServiceClient(w.clients.Conn())
	banks := bankpb.NewBankServiceClient(w.clients.Conn())
	_, err := providers.CreateProvider(w.ctx, &tenantv1.CreateProviderRequest{Input: &tenantv1.ProviderConfigInput{
		Name: bankProviderName, Type: "anthropic", SetAsDefault: true,
		Credentials: map[string]string{"api_key": key, "custom_headers": "anthropic-workspace-id: " + workspace},
	}})
	if status.Code(err) == codes.AlreadyExists {
		err = nil
	}
	require.NoError(t, err, "CreateProvider(%s)", bankProviderName)

	created, err := banks.CreateBank(w.ctx, &bankpb.CreateBankRequest{
		Name: w.bankName, DesiredCount: 1,
		LoginShape: bankpb.LoginShape_LOGIN_SHAPE_ANTHROPIC_API_KEY, ProviderConfigName: bankProviderName,
		AgentName: "claude", MaxJobsInFlight: 1,
	})
	require.NoError(t, err, "CreateBank")
	bankID := created.GetBank().GetId()
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(auth.ContextWithTenantString(context.Background(), fixLoopTenant), 30*time.Second)
		defer cancel()
		_, _ = banks.DeleteBank(c, &bankpb.DeleteBankRequest{Id: bankID})
	})
	waitForMembers(t, w.ctx, banks, bankID, 1, bankpb.MemberState_MEMBER_STATE_IDLE, bankMembersReady)
}

// enableFixAgent turns the catalog fix agent on for the tenant.
func (w *fixLoopWorld) enableFixAgent(t *testing.T) {
	t.Helper()
	membership := tenantv1.NewMembershipServiceClient(w.clients.Conn())
	_, err := membership.SetCatalogEnabled(w.ctx, &tenantv1.SetCatalogEnabledRequest{ComponentRef: fixLoopFixAgentRef, Enabled: true})
	require.NoError(t, err, "SetCatalogEnabled(%s)", fixLoopFixAgentRef)
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(auth.ContextWithTenantString(context.Background(), fixLoopTenant), 15*time.Second)
		defer cancel()
		_, _ = membership.SetCatalogEnabled(c, &tenantv1.SetCatalogEnabledRequest{ComponentRef: fixLoopFixAgentRef, Enabled: false})
	})
}

// runScan runs the catalog scan of the Git host: the alerts branch only.
func (w *fixLoopWorld) runScan(t *testing.T, app string) string {
	t.Helper()
	resp, err := w.daemon.RunCatalogMission(w.ctx, &daemonpb.RunCatalogMissionRequest{
		Name: "scan", Params: w.scanParams(app), TargetId: w.targetID,
	})
	require.NoError(t, err, "RunCatalogMission(scan) for %s", app)
	require.NotEmpty(t, resp.GetMissionId())
	return resp.GetMissionId()
}

// findingOf returns the open finding of the Application, or nil. The read is the
// daemon read of the open findings.
func (w *fixLoopWorld) findingOf(t *testing.T, app string) *worldpb.OpenFindingView {
	t.Helper()
	token := ""
	for {
		resp, err := w.world.ListOpenFindings(w.ctx, &worldpb.ListOpenFindingsRequest{PageSize: 200, PageToken: token})
		require.NoError(t, err, "ListOpenFindings")
		for _, f := range resp.GetFindings() {
			for _, p := range f.GetPlaces() {
				if strings.Contains(p.GetKey(), app) && strings.Contains(f.GetTitle(), fixLoopAdvisory) {
					return f
				}
			}
		}
		token = resp.GetNextPageToken()
		if token == "" {
			return nil
		}
	}
}

// startFixAgent runs one pass of the fix agent for the finding. The agent opens
// the coding job on the bank, the merge request, and the merge call that waits for
// the merge slot. The mission ends when the pass ends.
func (w *fixLoopWorld) startFixAgent(t *testing.T, app, findingID string) *helpers.MissionRun {
	t.Helper()
	str := func(v string) *commonpb.TypedValue {
		return &commonpb.TypedValue{Kind: &commonpb.TypedValue_StringValue{StringValue: v}}
	}
	def := &missionpb.MissionDefinition{
		Name:        helpers.RunName(t, "fix-loop-fix-agent"),
		Description: "one pass of the fix agent",
		Nodes: map[string]*missionpb.MissionNode{
			"fix": {
				Id: "fix", Name: "Fix", Type: missionpb.NodeType_NODE_TYPE_AGENT,
				Config: &missionpb.MissionNode_AgentConfig{AgentConfig: &missionpb.AgentNodeConfig{
					AgentName: fixLoopFixAgent,
					Task: &typespb.Task{
						Id: "fix", Goal: "Fix the finding " + findingID + " of " + app,
						Context: map[string]*commonpb.TypedValue{
							"application": str(app), "bank": str(w.bankName), "connector": str("connector/" + fixLoopGitConnector),
							"project": str(app), "base_branch": str("main"), "finding": str(findingID),
							"merge_wait": str("40m"), "timeout": str("30m"),
						},
					},
				}},
			},
		},
		EntryPoints: []string{"fix"},
		// A short hold, so the health signal of the deploy settles within the test.
		Constraints: &missionpb.MissionConstraints{HealthHold: durationpb.New(2 * time.Minute)},
	}
	created, err := w.daemon.CreateMissionDefinition(w.ctx, &daemonpb.CreateMissionDefinitionRequest{Definition: def})
	require.NoError(t, err, "CreateMissionDefinition(fix agent)")
	return helpers.StartMission(w.ctx, t, w.daemon, created.GetMissionDefinitionId(), w.targetID)
}

// statusOf reads the status of the finding. A finding in the open list has its
// status there. A finding that is not in the list is verified only when the
// exposure read says so, and never because the list does not hold it.
func (w *fixLoopWorld) statusOf(t *testing.T, app, id string) (st string, verified bool) {
	t.Helper()
	if f := w.findingOf(t, app); f != nil {
		return f.GetStatus(), false
	}
	exp, err := w.world.GetExposure(w.ctx, &worldpb.GetExposureRequest{FindingId: id})
	require.NoError(t, err, "GetExposure(%s)", id)
	if exp.GetVerified() {
		return "verified", true
	}
	return "not in the open list and not verified", false
}

// TestFixLoopCases is case 1 and case 2. It needs everything TestFixLoop needs, and
// the key and the workspace id of the bank exit test.
func runFixLoopCases(t *testing.T, w *fixLoopWorld) {
	w.startBank(t)
	w.enableFixAgent(t)
	w.scanParams = func(app string) map[string]string {
		return map[string]string{
			"repositoryUrl": w.forge.url + "/" + app, "application": app, "forgeConnector": fixLoopGitConnector,
		}
	}

	t.Run("case 1: the agent fixes the flaw and the finding is verified with an exposure window", func(t *testing.T) {
		app := fixLoopApp
		w.forge.setHealth(t, 1)
		w.forge.seedAdvisoryRepository(t, fixLoopOwner, fixLoopRepo)

		w.runScan(t, app)
		var f *worldpb.OpenFindingView
		helpers.Eventually(t, 10*time.Minute, "the scan raises the finding of the alert", func() (bool, string) {
			f = w.findingOf(t, app)
			return f != nil, "no open finding for " + fixLoopAdvisory + " on " + app
		})
		require.Equal(t, "open", f.GetStatus())
		id := f.GetId()

		run := w.startFixAgent(t, app, id)
		helpers.Eventually(t, fixLoopCaseTimeout, "the finding reaches fixing and then fixed", func() (bool, string) {
			st, verified := w.statusOf(t, app, id)
			return verified || st == "fixed", "status " + st
		})
		_ = run

		// The rescan reads the alert as fixed. The daemon verifies the finding after
		// the health signal held, so the rescan repeats until it does.
		helpers.Eventually(t, fixLoopCaseTimeout, "the finding is verified", func() (bool, string) {
			if _, verified := w.statusOf(t, app, id); verified {
				return true, ""
			}
			w.runScan(t, app)
			time.Sleep(fixLoopScanInterval)
			st, _ := w.statusOf(t, app, id)
			return false, "status " + st
		})

		exp, err := w.world.GetExposure(w.ctx, &worldpb.GetExposureRequest{FindingId: id})
		require.NoError(t, err, "GetExposure")
		require.True(t, exp.GetFound(), "the Timeline holds the finding")
		require.True(t, exp.GetVerified(), "the exposure window ends with the verified event")
		require.Positive(t, exp.GetTotalSeconds(), "the window has a length")
		require.Equal(t, exp.GetTotalSeconds(), exp.GetAgentSeconds()+exp.GetWaitSeconds(), "the window splits into agent time and wait time")
	})

	t.Run("case 2: the fix breaks the service, the daemon reverts it and the finding is open again", func(t *testing.T) {
		app := fixLoopApp2
		before, err := w.world.GetRevertRate(w.ctx, &worldpb.GetRevertRateRequest{})
		require.NoError(t, err, "GetRevertRate")

		// The health value is bad from now on, so the signal after the deploy fails.
		w.forge.setHealth(t, 0)
		w.forge.seedAdvisoryRepository(t, fixLoopOwner, fixLoopRepo2)

		w.runScan(t, app)
		var f *worldpb.OpenFindingView
		helpers.Eventually(t, 10*time.Minute, "the scan raises the finding of the alert", func() (bool, string) {
			f = w.findingOf(t, app)
			return f != nil, "no open finding for " + fixLoopAdvisory + " on " + app
		})
		id := f.GetId()
		w.startFixAgent(t, app, id)

		// The daemon reverts the fix after the failed signal. The revert rate then
		// counts a merged fix and a reverted one, and the finding is open again with
		// no merge request.
		helpers.Eventually(t, fixLoopCaseTimeout, "the revert rate counts the revert", func() (bool, string) {
			rate, rerr := w.world.GetRevertRate(w.ctx, &worldpb.GetRevertRateRequest{})
			if rerr != nil {
				return false, rerr.Error()
			}
			cur := rate.GetCurrent()
			return cur.GetReverted() > before.GetCurrent().GetReverted(),
				fmt.Sprintf("merged %d reverted %d", cur.GetMerged(), cur.GetReverted())
		})
		after, err := w.world.GetRevertRate(w.ctx, &worldpb.GetRevertRateRequest{})
		require.NoError(t, err)
		require.Greater(t, after.GetCurrent().GetMerged(), before.GetCurrent().GetMerged(), "the fix merged before it was reverted")
		helpers.Eventually(t, 10*time.Minute, "the finding is open again", func() (bool, string) {
			g := w.findingOf(t, app)
			if g == nil {
				return false, "the finding is not in the open list"
			}
			return g.GetStatus() == "open" && g.GetMergeRequest() == "", "status " + g.GetStatus() + " merge request " + g.GetMergeRequest()
		})
		exp, err := w.world.GetExposure(w.ctx, &worldpb.GetExposureRequest{FindingId: id})
		require.NoError(t, err, "GetExposure")
		require.False(t, exp.GetVerified(), "a reverted fix is not verified")
	})
}
