// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build e2e
// +build e2e

// Package e2e: finding_evidence_test.go is the exit test of the finding evidence
// epic (gibson#1384).
//
// In plain words: a finding holds all of its evidence in one shape. Evidence
// that names a tool call that the daemon recorded is tier 1, and the daemon
// copies the result from its own record. Evidence that the agent typed is tier
// 2. An agent cannot type a tier 1 item, and it cannot name the tool call of
// another mission.
//
// The agent and the tool of the test are outside components that the suite
// serves itself (see helpers.HeldAgent and helpers.ServeTool). The agent calls
// the tool with ComponentService.CallTool, which records the call and returns its
// id. The agent then submits a finding that names the id.
//
// The 6 points of the epic, and the subtest that holds each one:
//
//	1  a finding that names a recorded call holds the recorded result   "a finding that names ..."
//	2  typed content for that item does not change the recorded content "typed content ..."
//	3  the call of another mission is refused                           "a finding that names a tool call of another mission ..."
//	4  a finding with typed evidence only has tier 2 on each item        "a finding with typed evidence only ..."
//	5  two readers return the same evidence                              "the dashboard API and the export ..."
//	6  a proof and a finding hold the same content                       NOT COVERED, see below
//
// Point 6 is not covered. A proof goes through HarnessCallbackService.SubmitProof.
// It needs a placed bet, a hypothesis and a Domain Pack that binds a predicate. An
// outside agent in pull mode cannot reach that RPC. The one function that builds
// tier 1 evidence for both paths is brain.ReadRecordedEvidence, and its unit tests
// cover it.
//
// The parser finding is not covered either. A tool that returns a finding through
// the parser path (nuclei) needs a target that the sandbox can reach, and the
// sandbox reaches the cluster only through the Edge. The nmap tool returns hosts
// and ports and no finding. The unit test of the discovery processor covers the
// parser items (internal/engine/graphrag/ingest/discovery_evidence_test.go).
//
// It needs GIBSON_TEST_FIXTURES_ENABLED=true and DAEMON_GRPC_ADDR.
package e2e

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/gibson/tests/e2e/helpers"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

const (
	evidenceTenant = "primary"
	evidenceAgent  = "e2e-evidence-agent"
	evidenceTool   = "e2e-evidence-tool"
	// evidenceToolOutput is the text that the tool returns. A recorded item holds it.
	evidenceToolOutput = "EVIDENCE-RECORDED-OUTPUT"
	// evidenceForged is the text that an agent types for an item that it cannot forge.
	evidenceForged = "EVIDENCE-FORGED-CONTENT"
	// evidenceTypedOnly is the content of an item that no tool call backs.
	evidenceTypedOnly = "EVIDENCE-TYPED-ONLY-CONTENT"
	evidenceTimeout   = 6 * time.Minute
)

// evidenceFinding is the JSON that an SDK agent sends in SubmitFinding. The
// daemon reads the tool_call_ids and the typed evidence.
type evidenceFinding struct {
	Title       string             `json:"title"`
	Description string             `json:"description"`
	Category    string             `json:"category"`
	Severity    string             `json:"severity"`
	Confidence  float64            `json:"confidence"`
	Evidence    []evidenceTypedRow `json:"evidence,omitempty"`
	ToolCallIDs []string           `json:"tool_call_ids,omitempty"`
}

type evidenceTypedRow struct {
	Type     string         `json:"type"`
	Title    string         `json:"title"`
	Content  string         `json:"content"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

// submitFinding submits a finding with the work id of an open work item and
// returns the id of the stored finding.
func submitFinding(
	ctx context.Context, comp componentpb.ComponentServiceClient, workID string, f evidenceFinding,
) (string, error) {
	raw, err := json.Marshal(f)
	if err != nil {
		return "", err
	}
	resp, err := comp.SubmitFinding(ctx, &componentpb.SubmitFindingRequest{WorkId: workID, Finding: raw})
	if err != nil {
		return "", err
	}
	return resp.GetFindingId(), nil
}

// callEvidenceTool calls the tool of the test and returns the id that the daemon
// recorded for the call.
func callEvidenceTool(
	ctx context.Context, t *testing.T, comp componentpb.ComponentServiceClient, workID, query string,
) string {
	t.Helper()
	resp, err := comp.CallTool(ctx, &componentpb.CallToolRequest{
		WorkId: workID, ToolName: evidenceTool, InputJson: `{"q":"` + query + `"}`,
	})
	require.NoError(t, err, "CallTool(%s)", evidenceTool)
	require.Nil(t, resp.GetError(), "the tool must answer: %v", resp.GetError())
	require.Contains(t, resp.GetOutputJson(), evidenceToolOutput, "the tool output reached the agent")
	require.NotEmpty(t, resp.GetToolCallId(), "the daemon must record the call and return its id")
	return resp.GetToolCallId()
}

// storedFinding reads a finding until it is there. The writer is synchronous,
// so a short wait only covers a replica that reads a moment later.
func storedFinding(
	ctx context.Context, t *testing.T, tenant tenantv1.TenantServiceClient, id string,
) *tenantv1.FindingDetail {
	t.Helper()
	var f *tenantv1.FindingDetail
	helpers.Eventually(t, 30*time.Second, "the finding "+id+" is readable", func() (bool, string) {
		resp, err := tenant.GetFinding(ctx, &tenantv1.GetFindingRequest{FindingId: id})
		if err != nil {
			return false, err.Error()
		}
		f = resp.GetFinding()
		return f != nil, "no finding"
	})
	return f
}

// TestFindingEvidence is the exit test of gibson#1384.
func TestFindingEvidence(t *testing.T) {
	checkTestFixturesEnabled(t)
	clients, err := helpers.NewGRPCClients()
	require.NoError(t, err, "dial daemon at DAEMON_GRPC_ADDR")
	t.Cleanup(func() { _ = clients.Close() })
	ctx := auth.ContextWithTenantString(context.Background(), evidenceTenant)

	comp := componentpb.NewComponentServiceClient(clients.Conn())
	membership := tenantv1.NewMembershipServiceClient(clients.Conn())
	tenant := tenantv1.NewTenantServiceClient(clients.Conn())

	targetID, err := helpers.RegisterTestTarget(ctx, clients.Daemon, toolTargetName, toolTargetURL)
	require.NoError(t, err, "register the synthetic target")
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		helpers.DeleteTestTarget(auth.ContextWithTenantString(c, evidenceTenant), clients.Daemon, targetID)
	})

	helpers.ServeTool(ctx, t, comp, evidenceTool, func(payload []byte) ([]byte, error) {
		return []byte(`{"output":"` + evidenceToolOutput + `","input":` + string(payload) + `}`), nil
	})
	agent := helpers.StartHeldAgent(ctx, t, comp, membership, evidenceAgent)

	// Mission 1 holds the findings of points 1, 2, 4 and 5.
	defID1 := helpers.CreateAgentMission(ctx, t, clients.Daemon, "finding-evidence-exit-1", evidenceAgent, nil)
	run1 := helpers.StartMission(ctx, t, clients.Daemon, defID1, targetID)
	work1 := agent.Next(t, evidenceTimeout)
	callID1 := callEvidenceTool(ctx, t, comp, work1.WorkID, "one")

	var recordedFindingID, forgedFindingID string

	t.Run("a finding that names a recorded tool call holds the recorded result", func(t *testing.T) {
		id, serr := submitFinding(ctx, comp, work1.WorkID, evidenceFinding{
			Title: "recorded evidence", Description: "A finding that names one recorded tool call",
			Category: "e2e", Severity: "high", Confidence: 0.9, ToolCallIDs: []string{callID1},
		})
		require.NoError(t, serr, "SubmitFinding with a recorded tool call")
		recordedFindingID = id
		f := storedFinding(ctx, t, tenant, id)
		var tier1 []*typespb.Evidence
		for _, e := range f.GetEvidence() {
			if e.GetTier() == typespb.EvidenceTier_EVIDENCE_TIER_RECORDED {
				tier1 = append(tier1, e)
			}
		}
		require.Len(t, tier1, 1, "the finding must hold one tier 1 item for the one named call")
		require.Equal(t, callID1, tier1[0].GetToolCallId(), "the tier 1 item must name its tool call")
		require.Contains(t, tier1[0].GetContent(), evidenceToolOutput, "the tier 1 item must hold the recorded result")
	})

	t.Run("typed content for a recorded item does not change the recorded content", func(t *testing.T) {
		// The agent types an item with the content that it wants, and it tries to
		// claim the tool call in the metadata of the item. It also names the call
		// in tool_call_ids.
		id, serr := submitFinding(ctx, comp, work1.WorkID, evidenceFinding{
			Title: "forged evidence", Description: "A finding with typed content that claims a recorded call",
			Category: "e2e", Severity: "high", Confidence: 0.9, ToolCallIDs: []string{callID1},
			Evidence: []evidenceTypedRow{{
				Type: "log", Title: "forged item", Content: evidenceForged,
				Metadata: map[string]any{"tool_call_id": callID1, "tier": "1"},
			}},
		})
		require.NoError(t, serr, "SubmitFinding with typed content")
		forgedFindingID = id
		f := storedFinding(ctx, t, tenant, id)
		sawRecorded, sawTyped := false, false
		for _, e := range f.GetEvidence() {
			switch e.GetTier() {
			case typespb.EvidenceTier_EVIDENCE_TIER_RECORDED:
				sawRecorded = true
				require.Equal(t, callID1, e.GetToolCallId())
				require.Contains(t, e.GetContent(), evidenceToolOutput, "a reader must get the recorded content")
				require.NotContains(t, e.GetContent(), evidenceForged, "typed content must not replace the recorded content")
			case typespb.EvidenceTier_EVIDENCE_TIER_TYPED:
				sawTyped = true
				require.Contains(t, e.GetContent(), evidenceForged)
				require.Empty(t, e.GetToolCallId(), "a typed item has no tool call id, whatever the agent claims")
			default:
				t.Fatalf("an item has the tier %s, want tier 1 or tier 2", e.GetTier())
			}
		}
		require.True(t, sawRecorded, "the finding must hold the recorded item")
		require.True(t, sawTyped, "the finding must hold the typed item as tier 2")
	})

	var typedFindingID string
	t.Run("a finding with typed evidence only has tier 2 on each item", func(t *testing.T) {
		id, serr := submitFinding(ctx, comp, work1.WorkID, evidenceFinding{
			Title: "typed evidence", Description: "A finding with typed evidence and no tool call",
			Category: "e2e", Severity: "medium", Confidence: 0.5,
			Evidence: []evidenceTypedRow{
				{Type: "log", Title: "first", Content: evidenceTypedOnly + "-1"},
				{Type: "other", Title: "second", Content: evidenceTypedOnly + "-2"},
			},
		})
		require.NoError(t, serr, "SubmitFinding with typed evidence only")
		typedFindingID = id
		f := storedFinding(ctx, t, tenant, id)
		require.Len(t, f.GetEvidence(), 2, "the finding must hold the two typed items")
		for _, e := range f.GetEvidence() {
			require.Equal(t, typespb.EvidenceTier_EVIDENCE_TIER_TYPED, e.GetTier(), "item %q must be tier 2", e.GetTitle())
			require.Empty(t, e.GetToolCallId(), "item %q must name no tool call", e.GetTitle())
		}
	})

	t.Run("the dashboard API and the export return the same evidence", func(t *testing.T) {
		for _, id := range []string{recordedFindingID, forgedFindingID, typedFindingID} {
			f := storedFinding(ctx, t, tenant, id)
			resp, eerr := tenant.ExportFindings(ctx, &tenantv1.ExportFindingsRequest{
				Format: "json", FindingIds: []string{id}, IncludeEvidence: true,
			})
			require.NoError(t, eerr, "ExportFindings(%s)", id)
			require.Equal(t, int32(1), resp.GetCount(), "the export of one id must hold one finding")
			var doc struct {
				Findings []struct {
					Evidence []struct {
						Title      string `json:"title"`
						Content    string `json:"content"`
						Tier       int    `json:"tier"`
						ToolCallID string `json:"toolCallId"`
					} `json:"evidence"`
				} `json:"findings"`
			}
			require.NoError(t, json.Unmarshal(resp.GetData(), &doc), "decode the export: %s", resp.GetData())
			require.Len(t, doc.Findings, 1)
			got := doc.Findings[0].Evidence
			require.Len(t, got, len(f.GetEvidence()), "both readers must return the same number of items")
			for i, want := range f.GetEvidence() {
				require.Equal(t, want.GetTitle(), got[i].Title, "item %d title", i)
				require.Equal(t, want.GetContent(), got[i].Content, "item %d content", i)
				require.Equal(t, int(want.GetTier()), got[i].Tier, "item %d tier", i)
				require.Equal(t, want.GetToolCallId(), got[i].ToolCallID, "item %d tool call id", i)
			}
		}
	})

	work1.Complete()
	require.Equal(t, "mission_completed", run1.Wait(t, evidenceTimeout).EventType, "mission 1 must complete")

	t.Run("a finding that names a tool call of another mission is refused", func(t *testing.T) {
		defID2 := helpers.CreateAgentMission(ctx, t, clients.Daemon, "finding-evidence-exit-2", evidenceAgent, nil)
		run2 := helpers.StartMission(ctx, t, clients.Daemon, defID2, targetID)
		work2 := agent.Next(t, evidenceTimeout)
		require.NotEqual(t, work1.MissionID, work2.MissionID, "the second mission must be a new mission")
		callID2 := callEvidenceTool(ctx, t, comp, work2.WorkID, "two")
		require.NotEqual(t, callID1, callID2)

		// The control: the call of this mission is accepted.
		okID, serr := submitFinding(ctx, comp, work2.WorkID, evidenceFinding{
			Title: "control", Description: "A finding that names a call of its own mission",
			Category: "e2e", Severity: "low", Confidence: 0.5, ToolCallIDs: []string{callID2},
		})
		require.NoError(t, serr, "the call of the same mission must be accepted")
		require.NotEmpty(t, okID)

		// The call of mission 1 is refused, and the whole submit fails.
		_, serr = submitFinding(ctx, comp, work2.WorkID, evidenceFinding{
			Title: "cross mission", Description: "A finding that names a call of another mission",
			Category: "e2e", Severity: "low", Confidence: 0.5, ToolCallIDs: []string{callID1},
		})
		require.Error(t, serr, "a tool call of another mission must be refused")
		require.Equal(t, codes.NotFound, status.Code(serr), "the daemon answers NotFound: %v", serr)

		// A call that never existed gets the same answer, so the answer does not
		// say whether a call of another mission exists.
		_, serr = submitFinding(ctx, comp, work2.WorkID, evidenceFinding{
			Title: "unknown call", Description: "A finding that names no call", Category: "e2e",
			Severity: "low", Confidence: 0.5, ToolCallIDs: []string{"e2e-no-such-call"},
		})
		require.Error(t, serr)
		require.Equal(t, codes.NotFound, status.Code(serr), "the daemon answers NotFound: %v", serr)
		require.NotContains(t, strings.ToLower(serr.Error()), "other mission", "the answer must not name another mission")

		work2.Complete()
		require.Equal(t, "mission_completed", run2.Wait(t, evidenceTimeout).EventType, "mission 2 must complete")
	})
}
