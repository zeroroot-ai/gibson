// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"testing"
	"time"

	gibsonagent "github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/brain/braintest"
	"github.com/zeroroot-ai/gibson/internal/engine/finding"
	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
)

// TestIngestLLMCall_FeedsWorld: a completed ExecuteLLM call is folded into the
// calling tenant's World as an LlmCall entity (gibson#755), routed by the call's
// own tenant (multi-tenant correct), with no cross-tenant leak.
func TestIngestLLMCall_FeedsWorld(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())
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
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())
	ingestLLMCall(reg)(ctx, "acme", api.LLMCallRecord{CallID: ""}) // empty id ignored
	time.Sleep(50 * time.Millisecond)
	if got := reg.For("acme").LlmCalls(); len(got) != 0 {
		t.Fatalf("empty CallID must be ignored, got %+v", got)
	}
}

// TestIngestComponentFinding: the component finding path routes findings into the
// World (sole-writer convergence, gibson#837) instead of a direct graph write.
func TestIngestComponentFinding(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())

	sink := ingestComponentFinding(reg)
	sink(ctx, "acme", finding.NewEnhancedFinding(gibsonagent.Finding{
		ID: types.NewID(), Title: "RCE", Description: "unauth RCE", Severity: gibsonagent.SeverityCritical,
		SubmittedBy: "agent_principal:sa-1", EnrolledBy: "user-9",
	}, "", "zerocool-demo"), "")

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		fs := reg.For("acme").Findings()
		if len(fs) == 1 && fs[0].Title == "RCE" && fs[0].Severity == "critical" {
			if len(reg.For("other").Findings()) != 0 {
				t.Fatal("cross-tenant leak")
			}
			// The verified submitter rides the World event (gibson#208).
			if fs[0].SubmittedBy != "agent_principal:sa-1" || fs[0].AgentName != "zerocool-demo" || fs[0].EnrolledBy != "user-9" {
				t.Fatalf("submitter not folded: %+v", fs[0])
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("component finding not folded into the World: %+v", reg.For("acme").Findings())
}

// TestIngestComponentFinding_MissionStamped: a component finding submitted within
// a mission carries the mission id through the sink (gibson#1078) so it attaches
// to that mission's frame — the mission-evidence edge — while a finding with no
// mission context stays tenant-ambient (attaches to no mission frame).
func TestIngestComponentFinding_MissionStamped(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())

	sink := ingestComponentFinding(reg)
	sink(ctx, "acme", finding.NewEnhancedFinding(gibsonagent.Finding{
		ID: types.NewID(), Title: "SQLi", Description: "auth bypass", Severity: gibsonagent.SeverityHigh,
	}, "m-7", ""), "")
	sink(ctx, "acme", finding.NewEnhancedFinding(gibsonagent.Finding{
		ID: types.NewID(), Title: "ambient", Description: "no mission", Severity: gibsonagent.SeverityLow,
	}, "", ""), "")

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(reg.For("acme").Findings()) == 2 {
			// Mission m-7's slice contains only the mission-stamped finding; the
			// ambient finding (empty MissionID) stays tenant-ambient (no bleed).
			var titles []string
			for _, ev := range reg.For("acme").MissionEvents("m-7") {
				if fr, ok := ev.(brain.FindingRaised); ok {
					if fr.MissionID != "m-7" {
						t.Fatalf("finding in m-7 slice has MissionID %q, want m-7", fr.MissionID)
					}
					titles = append(titles, fr.Title)
				}
			}
			if len(titles) != 1 || titles[0] != "SQLi" {
				t.Fatalf("mission m-7 findings = %v, want [SQLi]", titles)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("findings not folded into the World: %+v", reg.For("acme").Findings())
}

// TestIngestLLMCall_MissionStamped: an ExecuteLLM call carrying mission context
// (gibson#1078) is folded with its MissionID so it attaches to that mission's
// frame, while a call with no mission context (e.g. dashboard chat) stays
// tenant-ambient and attaches to no mission frame.
func TestIngestLLMCall_MissionStamped(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())
	sink := ingestLLMCall(reg)

	sink(ctx, "acme", api.LLMCallRecord{CallID: "c-mission", MissionID: "m-9", Model: "m", PromptTokens: 10, CompletionTokens: 5})
	sink(ctx, "acme", api.LLMCallRecord{CallID: "c-ambient", Model: "m", PromptTokens: 1, CompletionTokens: 1})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(reg.For("acme").LlmCalls()) == 2 {
			var ids []string
			for _, ev := range reg.For("acme").MissionEvents("m-9") {
				if lc, ok := ev.(brain.LlmCallObserved); ok {
					if lc.MissionID != "m-9" {
						t.Fatalf("llm call in m-9 slice has MissionID %q, want m-9", lc.MissionID)
					}
					ids = append(ids, lc.CallID)
				}
			}
			if len(ids) != 1 || ids[0] != "c-mission" {
				t.Fatalf("mission m-9 llm calls = %v, want [c-mission]", ids)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("llm calls not folded into the World: %+v", reg.For("acme").LlmCalls())
}

// TestIngestLLMCall_CarriesToolCallsFullFidelity is the gibson#271
// flight-recorder unit at the daemon-wiring boundary: an api.LLMCallRecord's
// tool calls (both a historical prompt message's and the completion's own)
// must survive the api → brain translation ingestLLMCall performs.
func TestIngestLLMCall_CarriesToolCallsFullFidelity(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())
	sink := ingestLLMCall(reg)

	sink(ctx, "acme", api.LLMCallRecord{
		CallID: "c1", Model: "m",
		Messages: []api.LLMMessage{
			{Role: "assistant", ToolCalls: []api.LLMToolCall{
				{ID: "tc1", Type: "function", Name: "nmap", Arguments: `{"host":"x"}`},
			}},
		},
		CompletionToolCalls: []api.LLMToolCall{
			{ID: "tc2", Type: "function", Name: "nikto", Arguments: `{"host":"x"}`},
		},
		RecordedAtUnixNano: 12345,
	})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		calls := reg.For("acme").LlmCalls()
		if len(calls) == 1 {
			c := calls[0]
			if len(c.Messages) == 1 && len(c.Messages[0].ToolCalls) == 1 &&
				c.Messages[0].ToolCalls[0].Name == "nmap" &&
				len(c.CompletionToolCalls) == 1 && c.CompletionToolCalls[0].Name == "nikto" &&
				c.RecordedAtUnixNano == 12345 {
				return
			}
			t.Fatalf("tool calls not carried full-fidelity: %+v", c)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("llm call not folded into the World")
}

// TestHarnessLLMCallToAPI_PreservesFullFidelity is a direct unit test for the
// callback→api LLM-call mapping daemon.go's wiring uses (gibson#271),
// extracted as a pure function so it is unit-testable without a live daemon.
func TestHarnessLLMCallToAPI_PreservesFullFidelity(t *testing.T) {
	got := harnessLLMCallToAPI(harness.LLMCallRecord{
		CallID: "c1", MissionID: "m1", RunID: "r1", Model: "m",
		PromptTokens: 10, CompletionTokens: 5,
		Messages: []harness.LLMCallMessage{
			{Role: "assistant", ToolCalls: []harness.LLMCallToolCall{
				{ID: "tc1", Type: "function", Name: "nmap", Arguments: `{"host":"x"}`},
			}},
		},
		Completion: "done",
		CompletionToolCalls: []harness.LLMCallToolCall{
			{ID: "tc2", Type: "function", Name: "nikto", Arguments: `{"host":"x"}`},
		},
		RecordedAtUnixNano: 42,
	})

	if got.CallID != "c1" || got.MissionID != "m1" || got.RunID != "r1" || got.Model != "m" {
		t.Fatalf("identity/provenance fields not mapped: %+v", got)
	}
	if got.PromptTokens != 10 || got.CompletionTokens != 5 || got.Completion != "done" {
		t.Fatalf("metadata/completion not mapped: %+v", got)
	}
	if len(got.Messages) != 1 || len(got.Messages[0].ToolCalls) != 1 || got.Messages[0].ToolCalls[0].Name != "nmap" {
		t.Fatalf("prompt message tool calls not mapped: %+v", got.Messages)
	}
	if len(got.CompletionToolCalls) != 1 || got.CompletionToolCalls[0].Name != "nikto" {
		t.Fatalf("completion tool calls not mapped: %+v", got.CompletionToolCalls)
	}
	if got.RecordedAtUnixNano != 42 {
		t.Fatalf("RecordedAtUnixNano not mapped: %+v", got)
	}
}

// TestToAPIToolCalls_PreservesFullFidelity is a direct unit test for the
// harness→api tool-call bridge daemon.go's callback wiring uses (gibson#271):
// exercised here directly since the wiring closure itself is startup glue,
// not unit-testable in isolation.
func TestToAPIToolCalls_PreservesFullFidelity(t *testing.T) {
	got := toAPIToolCalls([]harness.LLMCallToolCall{
		{ID: "tc1", Type: "function", Name: "nmap", Arguments: `{"host":"x"}`},
	})
	if len(got) != 1 || got[0].ID != "tc1" || got[0].Name != "nmap" || got[0].Arguments != `{"host":"x"}` {
		t.Fatalf("tool calls not preserved full-fidelity: %+v", got)
	}
	if got := toAPIToolCalls(nil); got != nil {
		t.Fatalf("empty input must return nil, got %+v", got)
	}
}

// TestIngestToolCall_FeedsWorld is the gibson#271 flight-recorder unit for the
// tool-I/O half: a completed CallToolProto invocation folds into the calling
// tenant's brain World as an AgentToolCall entity, routed by tenant.
func TestIngestToolCall_FeedsWorld(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())
	sink := ingestToolCall(reg)

	sink(ctx, "acme", harness.ToolCallRecord{
		ToolCallID: "tc1", MissionID: "m1", ToolName: "nmap",
		Arguments: `{"host":"x"}`, Result: `{"ports":[22]}`,
	})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		calls := reg.For("acme").AgentToolCalls()
		if len(calls) == 1 && calls[0].ToolName == "nmap" {
			if len(reg.For("other").AgentToolCalls()) != 0 {
				t.Fatal("cross-tenant tool-call leak")
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("tool call not captured: %+v", reg.For("acme").AgentToolCalls())
}

// TestIngestToolCall_NilSafe ensures a nil registry and an empty ToolCallID are
// no-ops, never a panic (capture is best-effort and must not break a tool call).
func TestIngestToolCall_NilSafe(t *testing.T) {
	ingestToolCall(nil)(context.Background(), "acme", harness.ToolCallRecord{ToolCallID: "tc1"})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())
	ingestToolCall(reg)(ctx, "acme", harness.ToolCallRecord{ToolCallID: ""})
	time.Sleep(50 * time.Millisecond)
	if got := reg.For("acme").AgentToolCalls(); len(got) != 0 {
		t.Fatalf("empty ToolCallID must be ignored, got %+v", got)
	}
}

// TestIngestDelegation: an agent delegation folds both the parent and child run
// into the World (run-provenance), with the parent link carried so the projector
// can draw DELEGATED_TO — replacing the old direct graph write (gibson#837).
func TestIngestDelegation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())

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

// The sinks carry the run of the mission onto the evidence they fold. Evidence
// that a finished run reports late is kept, and the World detaches it from the
// mission (gibson#1217).
func TestIngestSinks_CarryTheMissionRun(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())
	eng := reg.For("acme")
	eng.Submit(brain.MissionProjected{ID: "m1", RunID: "run-2"})

	ingestToolCall(reg)(ctx, "acme", harness.ToolCallRecord{ToolCallID: "late", MissionID: "m1", MissionRunID: "run-1"})
	ingestToolCall(reg)(ctx, "acme", harness.ToolCallRecord{ToolCallID: "now", MissionID: "m1", MissionRunID: "run-2"})
	ingestLLMCall(reg)(ctx, "acme", api.LLMCallRecord{CallID: "late", MissionID: "m1", MissionRunID: "run-1"})
	ingestComponentFinding(reg)(ctx, "acme", finding.NewEnhancedFinding(gibsonagent.Finding{
		ID: types.NewID(), Title: "late",
	}, types.ID("m1"), "agent"), "run-1")

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(eng.AgentToolCalls()) == 2 && len(eng.LlmCalls()) == 1 && len(eng.Findings()) == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := eng.AgentToolCalls(); len(got) != 2 {
		t.Errorf("tool calls = %+v, want the late call kept beside the call of run 2", got)
	}
	if got := eng.LlmCalls(); len(got) != 1 {
		t.Errorf("LLM calls = %+v, want the late call kept", got)
	}
	got := eng.Findings()
	if len(got) != 1 {
		t.Fatalf("findings = %+v, want the late finding kept", got)
	}
	if got[0].ScanScope != "" || got[0].LastScan != "" {
		t.Errorf("the late finding has scan provenance %q %q, want none", got[0].ScanScope, got[0].LastScan)
	}
}
