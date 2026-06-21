package daemon

import (
	"context"
	"testing"
	"time"

	gibsonagent "github.com/zeroroot-ai/gibson/internal/agent"
	"github.com/zeroroot-ai/gibson/internal/brain"
	"github.com/zeroroot-ai/gibson/internal/daemon/api"
	"github.com/zeroroot-ai/gibson/internal/harness"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// TestIngestToBrain_FeedsWorld: daemon mission events translate into brain
// domain events and populate the tenant's live World (the capture path that
// makes the brain — and the Scroller — live).
func TestIngestToBrain_FeedsWorld(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)

	ingestToBrain(reg, "acme", api.EventData{
		EventType:    "mission.started",
		MissionEvent: &api.MissionEventData{MissionID: "m1", Payload: map[string]interface{}{"mission_name": "exfiltrate PII"}},
	})
	ingestToBrain(reg, "acme", api.EventData{
		EventType:    "node.started",
		MissionEvent: &api.MissionEventData{MissionID: "m1", NodeID: "recon"},
	})
	ingestToBrain(reg, "acme", api.EventData{
		EventType:    "finding.discovered",
		FindingEvent: &api.FindingEventData{Finding: api.FindingData{ID: "f1", Title: "exposed jenkins", Severity: "high"}},
	})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		eng := reg.For("acme")
		ms, work, fs := eng.Missions(), eng.Work(), eng.Findings()
		if len(ms) == 1 && ms[0].Goal == "exfiltrate PII" && len(work) == 1 && len(fs) == 1 {
			// Isolation: another tenant sees nothing.
			if len(reg.For("other").Missions()) != 0 {
				t.Fatal("cross-tenant leak")
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	eng := reg.For("acme")
	t.Fatalf("brain not fed: missions=%+v work=%+v findings=%+v", eng.Missions(), eng.Work(), eng.Findings())
}

// TestIngestLLMCall_FeedsWorld: a completed ExecuteLLM call is folded into the
// calling tenant's World as an LlmCall entity (gibson#755), routed by the call's
// own tenant (multi-tenant correct), with no cross-tenant leak.
func TestIngestLLMCall_FeedsWorld(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	sink := ingestLLMCall(reg)

	sink(ctx, "acme", api.LLMCallRecord{
		CallID: "call-1", Model: "claude-haiku-4-5", PromptTokens: 100, CompletionTokens: 40,
	})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		calls := reg.For("acme").LlmCalls()
		if len(calls) == 1 && calls[0].Model == "claude-haiku-4-5" && calls[0].TotalTokens() == 140 {
			if len(reg.For("other").LlmCalls()) != 0 {
				t.Fatal("cross-tenant LLM-call leak")
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("LLM call not captured: %+v", reg.For("acme").LlmCalls())
}

// TestIngestLLMCall_NilSafe: a nil registry and an empty CallID are no-ops, never
// a panic (capture is best-effort and must not break ExecuteLLM).
func TestIngestLLMCall_NilSafe(t *testing.T) {
	ingestLLMCall(nil)(context.Background(), "acme", api.LLMCallRecord{CallID: "c1"})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	ingestLLMCall(reg)(ctx, "acme", api.LLMCallRecord{CallID: ""}) // empty id ignored
	time.Sleep(50 * time.Millisecond)
	if got := reg.For("acme").LlmCalls(); len(got) != 0 {
		t.Fatalf("empty CallID must be ignored, got %+v", got)
	}
}

// TestIngestToBrain_AgentFindingSubmitted: agent-submitted findings (event type
// agent.finding_submitted) reach the World — they previously did not (the ingest
// only matched finding.submitted), which is why findings were direct-written to
// the graph instead of flowing World→projector (gibson#837). Description carries.
func TestIngestToBrain_AgentFindingSubmitted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)

	ingestToBrain(reg, "acme", api.EventData{
		EventType: "agent.finding_submitted",
		FindingEvent: &api.FindingEventData{Finding: api.FindingData{
			ID: "f7", Title: "SSRF", Description: "blind SSRF in /proxy", Severity: "high",
		}},
	})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		fs := reg.For("acme").Findings()
		if len(fs) == 1 && fs[0].Description == "blind SSRF in /proxy" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("agent.finding_submitted not folded into the World: %+v", reg.For("acme").Findings())
}

// TestIngestComponentFinding: the component finding path routes findings into the
// World (sole-writer convergence, gibson#837) instead of a direct graph write.
func TestIngestComponentFinding(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)

	sink := ingestComponentFinding(reg)
	sink(ctx, "acme", gibsonagent.Finding{ID: types.NewID(), Title: "RCE", Description: "unauth RCE", Severity: gibsonagent.SeverityCritical})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		fs := reg.For("acme").Findings()
		if len(fs) == 1 && fs[0].Title == "RCE" && fs[0].Severity == "critical" {
			if len(reg.For("other").Findings()) != 0 {
				t.Fatal("cross-tenant leak")
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("component finding not folded into the World: %+v", reg.For("acme").Findings())
}

// TestIngestDelegation: an agent delegation folds both the parent and child run
// into the World (run-provenance), with the parent link carried so the projector
// can draw DELEGATED_TO — replacing the old direct graph write (gibson#837).
func TestIngestDelegation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)

	sink := ingestDelegation(reg)
	sink(ctx, harness.DelegationObserved{
		Tenant: "acme", Scope: "m1",
		ParentRunID: "run-parent", ParentAgent: "orchestrator",
		ChildRunID: "run-child", ChildAgent: "recon",
	})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		runs := reg.For("acme").AgentRuns()
		if len(runs) == 2 {
			if len(reg.For("other").AgentRuns()) != 0 {
				t.Fatal("cross-tenant leak")
			}
			var child brain.AgentRunSnapshot
			for _, r := range runs {
				if r.RunID == "run-child" {
					child = r
				}
			}
			if child.ParentRunID != "run-parent" || child.AgentName != "recon" {
				t.Fatalf("child run missing parent link: %+v", runs)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("delegation not folded into the World: %+v", reg.For("acme").AgentRuns())
}
