package daemon

import (
	"context"
	"testing"
	"time"

	gibsonagent "github.com/zeroroot-ai/gibson/internal/agent"
	"github.com/zeroroot-ai/gibson/internal/brain"
	"github.com/zeroroot-ai/gibson/internal/daemon/api"
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
