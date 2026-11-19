// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package a2aserver

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/a2aproject/a2a-go/v2/a2a"

	"github.com/zeroroot-ai/gibson/internal/engine/finding"
)

// FindingsArtifactName is the name of the artifact that holds the findings.
const FindingsArtifactName = "findings"

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

// ResultBuilder builds the findings artifact of one mission, one finding at a
// time. It encodes each finding when the reader hands it over, and it keeps the
// encoded text only, so the memory is the size of the result plus one finding. The
// result has no size limit: it always holds all findings with all of their
// evidence, with the tier of each item, in raw form. The A2A Task type holds the
// artifact as one value and the JSON-RPC layer encodes the whole Task before it
// writes, so the result cannot be written to the caller as it is read.
type ResultBuilder struct {
	id       string
	buf      bytes.Buffer
	count    int
	severity map[string]int
}

// NewResultBuilder returns a builder for the mission.
func NewResultBuilder(missionID string) (*ResultBuilder, error) {
	id, err := json.Marshal(missionID)
	if err != nil {
		return nil, fmt.Errorf("encode the mission ID %q: %w", missionID, err)
	}
	b := &ResultBuilder{id: missionID, severity: map[string]int{}}
	b.buf.WriteString(`{"mission_id":`)
	b.buf.Write(id)
	b.buf.WriteString(`,"findings":[`)
	return b, nil
}

// Add encodes one finding: its ID, title, severity, target, all of its evidence with
// the tier of each item, and its reproduction steps. It adds no filter, no summary
// of the evidence and no redaction.
func (b *ResultBuilder) Add(f finding.EnhancedFinding) error {
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
	raw, err := json.Marshal(out)
	if err != nil {
		return fmt.Errorf("encode finding %s of mission %s: %w", f.ID, b.id, err)
	}
	if b.count > 0 {
		b.buf.WriteByte(',')
	}
	b.buf.Write(raw)
	b.count++
	b.severity[string(f.Severity)]++
	return nil
}

// Artifact closes the result with its summary and returns the artifact and the
// size of its data in bytes.
func (b *ResultBuilder) Artifact() (*a2a.Artifact, int, error) {
	summary, err := json.Marshal(inboundSummary{Total: b.count, BySeverity: b.severity})
	if err != nil {
		return nil, 0, fmt.Errorf("encode the summary of mission %s: %w", b.id, err)
	}
	b.buf.WriteString(`],"summary":`)
	b.buf.Write(summary)
	b.buf.WriteByte('}')
	body := b.buf.Bytes()
	return &a2a.Artifact{
		ID: a2a.NewArtifactID(), Name: FindingsArtifactName,
		Parts: a2a.ContentParts{a2a.NewDataPart(json.RawMessage(body))},
	}, len(body), nil
}
