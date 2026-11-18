// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package ingest

import (
	"context"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/finding"
	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// fakeRecords is a brain.ToolCallRecord with a fixed set of calls. A call
// appears after the given number of reads, so the test covers the wait.
type fakeRecords struct {
	mu        sync.Mutex
	calls     map[string]brain.AgentToolCallSnapshot
	appearsAt int
	reads     int
	tenants   []string
}

func (f *fakeRecords) RecordedToolCalls(
	ctx context.Context, _ string, ids []string,
) ([]brain.AgentToolCallSnapshot, []string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	if t, ok := auth.TenantFromContext(ctx); ok {
		f.tenants = append(f.tenants, t.String())
	}
	var found []brain.AgentToolCallSnapshot
	var missing []string
	for _, id := range ids {
		c, ok := f.calls[id]
		if !ok || f.reads <= f.appearsAt {
			missing = append(missing, id)
			continue
		}
		found = append(found, c)
	}
	return found, missing, nil
}

type writtenFinding struct {
	raised   brain.FindingRaised
	evidence []*typespb.Evidence
}

func evidenceProcessor(rec brain.ToolCallRecord, out *[]writtenFinding) DiscoveryProcessor {
	writer := func(_ context.Context, _ string, f brain.FindingRaised, ev []*typespb.Evidence) error {
		*out = append(*out, writtenFinding{raised: f, evidence: ev})
		return nil
	}
	opts := []Option{WithFindingWriter(writer)}
	if rec != nil {
		opts = append(opts, WithToolCallRecord(rec))
	}
	return NewDiscoveryProcessor(func(string, brain.Event) {}, discardLogger(), opts...)
}

func parserItem(content string) *typespb.Evidence {
	return &typespb.Evidence{
		Title:      "parser item",
		Type:       typespb.EvidenceType_EVIDENCE_TYPE_LOG,
		Content:    content,
		Tier:       typespb.EvidenceTier_EVIDENCE_TIER_RECORDED, // a parser value, the daemon ignores it
		ToolCallId: "forged",
		Metadata:   map[string]string{"k": "v", ParserSourceKey: "agent"},
	}
}

func TestProcess_ParserEvidenceMatchesTheOriginalAndTheDerivedID(t *testing.T) {
	origID := "finding-a" // not a UUID, so the derived ID differs
	f := &graphragpb.Finding{Id: &origID, Title: "open redirect", Severity: "high"}
	derived := findingID("m1", f)
	if derived == origID {
		t.Fatal("test needs a derived id that differs from the original")
	}
	d := &graphragpb.DiscoveryResult{
		Findings: []*graphragpb.Finding{f},
		FindingEvidence: []*graphragpb.FindingEvidence{
			{FindingId: origID, Evidence: parserItem("by original id")},
			{FindingId: derived, Evidence: parserItem("by derived id")},
			{FindingId: "unknown", Evidence: parserItem("no finding")},
			{FindingId: origID, Evidence: nil},
		},
	}
	var written []writtenFinding
	p := evidenceProcessor(nil, &written)
	res, err := p.Process(context.Background(),
		ExecContext{MissionID: "m1", TenantID: auth.MustNewTenantID("acme")}, d)
	if err != nil {
		t.Fatal(err)
	}
	if len(written) != 1 || written[0].raised.ID != derived {
		t.Fatalf("written = %+v", written)
	}
	ev := written[0].evidence
	if len(ev) != 2 {
		t.Fatalf("want 2 parser items, got %d", len(ev))
	}
	for _, e := range ev {
		if e.GetTier() != typespb.EvidenceTier_EVIDENCE_TIER_TYPED || e.GetToolCallId() != "" {
			t.Errorf("the daemon must set tier 2 and clear the tool call id: %+v", e)
		}
		if e.GetMetadata()[ParserSourceKey] != ParserSource || e.GetMetadata()["k"] != "v" {
			t.Errorf("metadata = %v", e.GetMetadata())
		}
	}
	if len(res.Errors) != 2 {
		t.Errorf("want 2 problems for the unknown finding and the empty item, got %v", res.Errors)
	}
	// The input of the parser is not changed.
	if d.FindingEvidence[0].Evidence.ToolCallId != "forged" {
		t.Error("the processor changed the proto of the caller")
	}
}

func TestProcess_AddsOneTierOneItemOfTheParsedToolCall(t *testing.T) {
	callID := uuid.NewString()
	rec := &fakeRecords{
		calls:     map[string]brain.AgentToolCallSnapshot{callID: {ToolCallID: callID, ToolName: "nmap", Result: "raw output"}},
		appearsAt: 2, // the record shows up on the third read
	}
	d := &graphragpb.DiscoveryResult{
		Findings:        []*graphragpb.Finding{{Title: "t1", Severity: "low"}, {Title: "t2", Severity: "low"}},
		FindingEvidence: nil,
	}
	var written []writtenFinding
	p := evidenceProcessor(rec, &written)
	res, err := p.Process(context.Background(),
		ExecContext{MissionID: "m1", ToolExecutionID: callID, TenantID: auth.MustNewTenantID("acme")}, d)
	if err != nil || res.HasErrors() {
		t.Fatalf("err = %v, result errors = %v", err, res.Errors)
	}
	if rec.reads != 3 {
		t.Errorf("reads = %d, want 3", rec.reads)
	}
	if len(rec.tenants) == 0 || rec.tenants[0] != "acme" {
		t.Errorf("the record was read for tenants %v, want acme", rec.tenants)
	}
	if len(written) != 2 {
		t.Fatalf("want 2 findings, got %d", len(written))
	}
	for _, w := range written {
		if len(w.evidence) != 1 {
			t.Fatalf("want one item, got %d", len(w.evidence))
		}
		e := w.evidence[0]
		if e.GetTier() != typespb.EvidenceTier_EVIDENCE_TIER_RECORDED || e.GetToolCallId() != callID ||
			e.GetContent() != "raw output" {
			t.Errorf("tier 1 item = %+v", e)
		}
	}
}

func TestProcess_ATierOneItemComesBeforeTheParserItems(t *testing.T) {
	callID := uuid.NewString()
	rec := &fakeRecords{calls: map[string]brain.AgentToolCallSnapshot{callID: {ToolCallID: callID, Result: "r"}}}
	id := "11111111-1111-4111-8111-111111111111"
	d := &graphragpb.DiscoveryResult{
		Findings:        []*graphragpb.Finding{{Id: &id, Title: "t", Severity: "low"}},
		FindingEvidence: []*graphragpb.FindingEvidence{{FindingId: id, Evidence: parserItem("p")}},
	}
	var written []writtenFinding
	_, err := evidenceProcessor(rec, &written).Process(context.Background(),
		ExecContext{MissionID: "m1", ToolExecutionID: callID, TenantID: auth.MustNewTenantID("acme")}, d)
	if err != nil {
		t.Fatal(err)
	}
	ev := written[0].evidence
	if len(ev) != 2 || ev[0].GetTier() != typespb.EvidenceTier_EVIDENCE_TIER_RECORDED ||
		ev[1].GetTier() != typespb.EvidenceTier_EVIDENCE_TIER_TYPED {
		t.Fatalf("evidence order = %+v", ev)
	}
}

func TestProcess_AMissingRecordStillWritesTheFinding(t *testing.T) {
	rec := &fakeRecords{calls: map[string]brain.AgentToolCallSnapshot{}}
	d := &graphragpb.DiscoveryResult{Findings: []*graphragpb.Finding{{Title: "t", Severity: "low"}}}
	var written []writtenFinding
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the wait ends at once
	res, err := evidenceProcessor(rec, &written).Process(ctx,
		ExecContext{MissionID: "m1", ToolExecutionID: "gone", TenantID: auth.MustNewTenantID("acme")}, d)
	if err != nil {
		t.Fatal(err)
	}
	if len(written) != 1 || len(written[0].evidence) != 0 {
		t.Fatalf("written = %+v", written)
	}
	if !res.HasErrors() {
		t.Error("a missing record must show in the result")
	}
}

func TestParserEvidence_DropsAnItemOverTheSizeLimit(t *testing.T) {
	if maxParserEvidenceBytes != finding.MaxEvidenceContentBytes {
		t.Fatalf("the limits differ: %d and %d", maxParserEvidenceBytes, finding.MaxEvidenceContentBytes)
	}
	f := &graphragpb.Finding{Title: "t", Severity: "low"}
	id := findingID("m1", f)
	big := make([]byte, maxParserEvidenceBytes+1)
	d := &graphragpb.DiscoveryResult{
		Findings:        []*graphragpb.Finding{f},
		FindingEvidence: []*graphragpb.FindingEvidence{{FindingId: id, Evidence: parserItem(string(big))}},
	}
	got, errs := parserEvidence(ExecContext{MissionID: "m1"}, d)
	if len(got[id]) != 0 || len(errs) != 1 {
		t.Fatalf("got %v, errs %v", got, errs)
	}
}
