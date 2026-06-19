package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/brain"
	"github.com/zeroroot-ai/gibson/internal/daemon/api"
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
