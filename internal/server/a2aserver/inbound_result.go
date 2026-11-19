// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package a2aserver

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/a2aproject/a2a-go/v2/a2a"

	"github.com/zeroroot-ai/gibson/internal/engine/finding"
)

// MaxInboundResultBytes is the size limit of the findings in the result of a Task.
// A result over the limit fails with ErrResultTooLarge. The daemon never
// truncates it, never drops evidence and never replaces it by a summary.
const MaxInboundResultBytes = 16 << 20

// ErrResultTooLarge reports a Task result that is over MaxInboundResultBytes.
var ErrResultTooLarge = errors.New("a2a: the findings of the mission are over the size limit of a Task result")

// FindingsArtifactName is the name of the artifact that holds the findings.
const FindingsArtifactName = "findings"

// inboundResult is the data of the findings artifact.
type inboundResult struct {
	MissionID string           `json:"mission_id"`
	Summary   inboundSummary   `json:"summary"`
	Findings  []inboundFinding `json:"findings"`
}

type inboundSummary struct {
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity"`
}

type inboundFinding struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	// Target is the ID of the target of the finding. It is empty when the finding
	// names none.
	Target    string            `json:"target"`
	Evidence  []inboundEvidence `json:"evidence"`
	Reproduce []inboundRepro    `json:"reproduction_steps"`
}

// inboundEvidence is one evidence item, as stored. The tier says who made the
// item: "EVIDENCE_TIER_RECORDED" for the output of a tool call that the daemon
// recorded, and "EVIDENCE_TIER_TYPED" for the text that the agent typed.
type inboundEvidence struct {
	Tier       string            `json:"tier"`
	ToolCallID string            `json:"tool_call_id,omitempty"`
	Type       string            `json:"type"`
	Title      string            `json:"title"`
	Content    string            `json:"content"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

type inboundRepro struct {
	Step           int    `json:"step"`
	Description    string `json:"description"`
	ExpectedResult string `json:"expected_result"`
	EvidenceRef    string `json:"evidence_ref,omitempty"`
}

// FindingsArtifact builds the artifact that holds the findings of one mission:
// a summary, and for each finding its ID, title, severity, target, all of its
// evidence with the tier of each item, and its reproduction steps. The caller
// passes the findings of that one mission, with the evidence from the one read
// function. The builder adds no filter, no summary of the evidence and no
// redaction. It returns ErrResultTooLarge when the encoded data is over limit.
func FindingsArtifact(missionID string, findings []finding.EnhancedFinding, limit int) (*a2a.Artifact, error) {
	res := inboundResult{
		MissionID: missionID,
		Summary:   inboundSummary{Total: len(findings), BySeverity: map[string]int{}},
		Findings:  make([]inboundFinding, 0, len(findings)),
	}
	for _, f := range findings {
		res.Summary.BySeverity[string(f.Severity)]++
		out := inboundFinding{
			ID: f.ID.String(), Title: f.Title, Description: f.Description, Severity: string(f.Severity),
			Evidence: make([]inboundEvidence, 0, len(f.Evidence)), Reproduce: make([]inboundRepro, 0, len(f.ReproSteps)),
		}
		if f.TargetID != nil {
			out.Target = f.TargetID.String()
		}
		for _, e := range f.Evidence {
			out.Evidence = append(out.Evidence, inboundEvidence{
				Tier: e.GetTier().String(), ToolCallID: e.GetToolCallId(), Type: e.GetType().String(),
				Title: e.GetTitle(), Content: e.GetContent(), Metadata: e.GetMetadata(),
			})
		}
		for _, s := range f.ReproSteps {
			out.Reproduce = append(out.Reproduce, inboundRepro{
				Step: s.StepNumber, Description: s.Description, ExpectedResult: s.ExpectedResult, EvidenceRef: s.EvidenceRef,
			})
		}
		res.Findings = append(res.Findings, out)
	}
	body, err := json.Marshal(res)
	if err != nil {
		return nil, fmt.Errorf("encode the findings of mission %s: %w", missionID, err)
	}
	if len(body) > limit {
		return nil, fmt.Errorf("%w: %d bytes, limit %d bytes", ErrResultTooLarge, len(body), limit)
	}
	return &a2a.Artifact{
		ID: a2a.NewArtifactID(), Name: FindingsArtifactName,
		Parts: a2a.ContentParts{a2a.NewDataPart(json.RawMessage(body))},
	}, nil
}
