// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package a2aserver

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/finding"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
)

// decodedResult decodes the data part of the findings artifact.
type decodedResult struct {
	MissionID string `json:"mission_id"`
	Summary   struct {
		Total      int            `json:"total"`
		BySeverity map[string]int `json:"by_severity"`
	} `json:"summary"`
	Findings []struct {
		ID       string `json:"id"`
		Title    string `json:"title"`
		Severity string `json:"severity"`
		Target   string `json:"target"`
		Evidence []struct {
			Tier       string            `json:"tier"`
			ToolCallID string            `json:"tool_call_id"`
			Type       string            `json:"type"`
			Title      string            `json:"title"`
			Content    string            `json:"content"`
			Metadata   map[string]string `json:"metadata"`
		} `json:"evidence"`
		Repro []struct {
			Step           int    `json:"step"`
			Description    string `json:"description"`
			ExpectedResult string `json:"expected_result"`
			EvidenceRef    string `json:"evidence_ref"`
		} `json:"reproduction_steps"`
	} `json:"findings"`
}

func decode(t *testing.T, raw any) decodedResult {
	t.Helper()
	body, err := json.Marshal(raw)
	require.NoError(t, err)
	var out decodedResult
	require.NoError(t, json.Unmarshal(body, &out))
	return out
}

func sampleFindings() (finding.EnhancedFinding, finding.EnhancedFinding) {
	target := types.NewID()
	rawOutput := "PORT 22/tcp open\n\x00 raw bytes, secrets: AKIAEXAMPLE password=hunter2"
	full := finding.EnhancedFinding{
		Finding: agent.Finding{
			ID: types.NewID(), Title: "Open SSH", Description: "port 22", Severity: agent.SeverityHigh, TargetID: &target,
			Evidence: []*typespb.Evidence{
				{Title: "nmap", Type: typespb.EvidenceType_EVIDENCE_TYPE_UNSPECIFIED, Content: rawOutput,
					Tier: typespb.EvidenceTier_EVIDENCE_TIER_RECORDED, ToolCallId: "call-1", Metadata: map[string]string{"k": "v"}},
				{Title: "note", Content: "the agent typed this", Tier: typespb.EvidenceTier_EVIDENCE_TIER_TYPED},
			},
		},
		ReproSteps: []finding.ReproStep{{StepNumber: 1, Description: "run nmap", ExpectedResult: "port 22 open", EvidenceRef: "nmap"}},
	}
	bare := finding.EnhancedFinding{Finding: agent.Finding{ID: types.NewID(), Title: "Banner", Severity: agent.SeverityLow}}
	return full, bare
}

// The result holds the summary, and for each finding its ID, title, severity,
// target, all of its evidence in raw form with the tier of each item, and its
// reproduction steps.
func TestFindingsArtifact_HoldsEachFindingWithAllEvidenceAndTheTierOfEachItem(t *testing.T) {
	full, bare := sampleFindings()

	art, err := FindingsArtifact("m-1", []finding.EnhancedFinding{full, bare}, MaxInboundResultBytes)

	require.NoError(t, err)
	assert.Equal(t, FindingsArtifactName, art.Name)
	require.Len(t, art.Parts, 1)
	got := decode(t, art.Parts[0].Data())
	assert.Equal(t, "m-1", got.MissionID)
	assert.Equal(t, 2, got.Summary.Total)
	assert.Equal(t, map[string]int{"high": 1, "low": 1}, got.Summary.BySeverity)
	require.Len(t, got.Findings, 2)

	f := got.Findings[0]
	assert.Equal(t, full.ID.String(), f.ID)
	assert.Equal(t, "Open SSH", f.Title)
	assert.Equal(t, "high", f.Severity)
	assert.Equal(t, full.TargetID.String(), f.Target)
	require.Len(t, f.Evidence, 2, "all evidence goes out")
	assert.Equal(t, "EVIDENCE_TIER_RECORDED", f.Evidence[0].Tier, "the tier of a recorded item")
	assert.Equal(t, "call-1", f.Evidence[0].ToolCallID)
	assert.Equal(t, full.Evidence[0].Content, f.Evidence[0].Content, "the content is raw: no filter and no redaction")
	assert.Equal(t, map[string]string{"k": "v"}, f.Evidence[0].Metadata)
	assert.Equal(t, "EVIDENCE_TIER_TYPED", f.Evidence[1].Tier, "the tier of a typed item")
	assert.Empty(t, f.Evidence[1].ToolCallID)
	require.Len(t, f.Repro, 1)
	assert.Equal(t, 1, f.Repro[0].Step)
	assert.Equal(t, "run nmap", f.Repro[0].Description)
	assert.Equal(t, "port 22 open", f.Repro[0].ExpectedResult)
	assert.Equal(t, "nmap", f.Repro[0].EvidenceRef)

	b := got.Findings[1]
	assert.Empty(t, b.Target, "a finding with no target names none")
	assert.Empty(t, b.Evidence)
	assert.Empty(t, b.Repro)
}

func TestFindingsArtifact_ForAMissionWithNoFindingHoldsAnEmptyResult(t *testing.T) {
	art, err := FindingsArtifact("m-1", nil, MaxInboundResultBytes)
	require.NoError(t, err)
	got := decode(t, art.Parts[0].Data())
	assert.Equal(t, 0, got.Summary.Total)
	assert.NotNil(t, got.Findings, "the list is empty and not null")
}

// A result over the size limit fails with a clear error. The daemon never
// truncates it and never drops evidence.
func TestFindingsArtifact_AResultOverTheLimitFailsAndIsNeverTruncated(t *testing.T) {
	full, _ := sampleFindings()
	full.Evidence[0].Content = strings.Repeat("A", 4096)

	art, err := FindingsArtifact("m-1", []finding.EnhancedFinding{full}, 1024)

	require.ErrorIs(t, err, ErrResultTooLarge)
	assert.Nil(t, art, "no partial result")
	assert.Contains(t, err.Error(), "limit 1024 bytes")

	// The same result passes when the limit holds it.
	_, err = FindingsArtifact("m-1", []finding.EnhancedFinding{full}, MaxInboundResultBytes)
	require.NoError(t, err)
}
