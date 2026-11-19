// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"fmt"
	"testing"
	"time"

	gibsonagent "github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/brain/braintest"
	"github.com/zeroroot-ai/gibson/internal/engine/finding"
	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

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
	ingestComponentFinding(reg)(ctx, "acme", finding.NewEnhancedFinding(gibsonagent.Finding{
		ID: types.NewID(), Title: "late",
	}, types.ID("m1"), "agent"), "run-1")

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(eng.AgentToolCalls()) == 2 && len(eng.Findings()) == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := eng.AgentToolCalls(); len(got) != 2 {
		t.Errorf("tool calls = %+v, want the late call kept beside the call of run 2", got)
	}
	got := eng.Findings()
	if len(got) != 1 {
		t.Fatalf("findings = %+v, want the late finding kept", got)
	}
	if got[0].ScanScope != "" || got[0].LastScan != "" {
		t.Errorf("the late finding has scan provenance %q %q, want none", got[0].ScanScope, got[0].LastScan)
	}
}

// TestIngestSkillLoad_FeedsTheTimeline proves that one successful load gives one
// event on the Timeline of the tenant, with the agent, the mission and the
// digest, and that another tenant sees nothing.
func TestIngestSkillLoad_FeedsTheTimeline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())
	sink := ingestSkillLoad(reg)

	err := sink(ctx, "acme", harness.SkillLoadRecord{
		MissionID: "m1", RunID: "r1", Agent: "agent_principal:a1", Name: "web-recon",
		Digest: "sha256:aa", RecordedAtUnixNano: 5,
	})
	if err != nil {
		t.Fatalf("sink: %v", err)
	}
	// An empty digest is not a load, and a missing Timeline refuses the load.
	if err := sink(ctx, "acme", harness.SkillLoadRecord{MissionID: "m1", Name: "web-recon"}); err == nil {
		t.Error("a load with no digest must be refused")
	}
	if err := ingestSkillLoad(nil)(ctx, "acme", harness.SkillLoadRecord{Digest: "sha256:aa"}); err == nil {
		t.Error("a load with no Timeline must be refused")
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		loads := reg.For("acme").AgentSkillLoads()
		if len(loads) == 1 {
			if loads[0].Digest != "sha256:aa" || loads[0].MissionID != "m1" || loads[0].Agent != "agent_principal:a1" {
				t.Fatalf("load = %+v", loads[0])
			}
			if len(reg.For("other").AgentSkillLoads()) != 0 {
				t.Fatal("cross-tenant load leak")
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("load not recorded: %+v", reg.For("acme").AgentSkillLoads())
}

// The sink returns after the engine folded the record. A finding that cites the
// id of the call reads the record at once, so a record that is not there yet
// would refuse a correct finding.
func TestIngestToolCall_TheRecordIsReadableWhenTheSinkReturns(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())
	sink := ingestToolCall(reg)

	for i := range 50 {
		id := fmt.Sprintf("call-%d", i)
		sink(ctx, "acme", harness.ToolCallRecord{ToolCallID: id, MissionID: "m1", ToolName: "nmap"})
		if _, missing := reg.For("acme").RecordedToolCalls("m1", []string{id}); len(missing) != 0 {
			t.Fatalf("the record of %s is not readable when the sink returned", id)
		}
	}
}
