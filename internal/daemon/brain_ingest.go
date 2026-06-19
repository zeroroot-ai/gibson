// Package daemon — brain_ingest.go
//
// ingestToBrain bridges the daemon's mission event stream into the ECS brain
// (epic ecs-brain). It is the "capture path" from ADR-0001: the brain is fed by
// the existing event bus, not by a parallel execution path. The orchestrator
// event-bus adapter calls this for every published event with the tenant in
// hand, so each tenant's brain World fills from its real mission execution and
// the WorldService / Scroller show live data.
//
// This is the additive feed that makes the brain live; the wholesale cutover
// (agents emitting directly via the reshaped Harness, sdk#341, and retiring the
// old orchestrator, gibson#755/#756) replaces it later.
package daemon

import (
	"context"

	"github.com/zeroroot-ai/gibson/internal/brain"
	"github.com/zeroroot-ai/gibson/internal/daemon/api"
	"github.com/zeroroot-ai/gibson/internal/harness"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
)

// ingestObservation returns the callback service's observation sink (ADR-0007):
// it translates a typed agent observation into a brain Timeline event and submits
// it to the tenant's World engine. The reducer + scope-relative identity
// (ADR-0002) resolve the entity and its topology — the agent authors neither.
//
// Scope is taken from the mission context (each mission is a World partition for
// now); a later slice refines this to the mission's declared scope / agent vantage.
func ingestObservation(reg *brain.Registry, tenant string) harness.ObservationSink {
	return func(_ context.Context, req *harnesspb.ObserveRequest) error {
		if reg == nil || req == nil {
			return nil
		}
		scope := ""
		if req.Context != nil {
			scope = req.Context.MissionId
		}
		if h := req.GetHost(); h != nil {
			var openPorts []int
			var services map[int]brain.ServiceInfo
			for _, p := range h.Ports {
				openPorts = append(openPorts, int(p.Number))
				svc := brain.ServiceInfo{Protocol: p.Protocol, Name: p.Service, Product: p.Product, Version: p.Version}
				if (svc != brain.ServiceInfo{}) {
					if services == nil {
						services = map[int]brain.ServiceInfo{}
					}
					services[int(p.Number)] = svc
				}
			}
			reg.For(tenant).Submit(brain.HostObserved{
				ScopeID:    scope,
				Address:    h.Address,
				SSHHostKey: h.SshHostKey,
				CloudID:    h.CloudId,
				OpenPorts:  openPorts,
				Services:   services,
			})
		}
		return nil
	}
}

func payloadString(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// ingestToBrain translates a daemon EventData into brain domain events and
// submits them to the tenant's engine. No-op when the registry is nil.
func ingestToBrain(reg *brain.Registry, tenant string, ed api.EventData) {
	if reg == nil {
		return
	}
	eng := reg.For(tenant)

	switch ed.EventType {
	case "mission.started":
		if m := ed.MissionEvent; m != nil {
			eng.Submit(brain.MissionStarted{ID: m.MissionID, Goal: payloadString(m.Payload, "mission_name")})
		}
	case "mission.completed":
		if m := ed.MissionEvent; m != nil {
			eng.Submit(brain.MissionDone{ID: m.MissionID, Reason: "completed"})
		}
	case "mission.failed":
		if m := ed.MissionEvent; m != nil {
			reason := "failed"
			if m.Error != "" {
				reason = "failed: " + m.Error
			}
			eng.Submit(brain.MissionDone{ID: m.MissionID, Reason: reason})
		}
	case "node.started":
		if m := ed.MissionEvent; m != nil {
			eng.Submit(brain.WorkDispatched{ID: m.MissionID + "/" + m.NodeID, ItemKind: "node", Target: m.NodeID})
		}
	case "node.completed":
		if m := ed.MissionEvent; m != nil {
			eng.Submit(brain.WorkCompleted{ID: m.MissionID + "/" + m.NodeID})
		}
	case "node.failed":
		if m := ed.MissionEvent; m != nil {
			eng.Submit(brain.WorkCompleted{ID: m.MissionID + "/" + m.NodeID, Err: m.Error})
		}
	case "finding.discovered", "finding.submitted":
		if fe := ed.FindingEvent; fe != nil {
			eng.Submit(brain.FindingRaised{
				ID:       fe.Finding.ID,
				Title:    fe.Finding.Title,
				Severity: fe.Finding.Severity,
			})
		}
	}
}
