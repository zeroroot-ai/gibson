// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

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
	"fmt"
	"time"

	gibsonagent "github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/graphrag/ingest"
	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/engine/harness/sandboxed"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
)

// ingestComponentFinding returns the component finding submitter's World sink
// (ADR-0007): a finding submitted over the component path is folded into the
// tenant World as a Finding so the graph projector — the sole writer of finding
// nodes — materializes it. Replaces the old direct StoreAsync graph write.
func ingestComponentFinding(reg *brain.Registry) component.WorldFindingSink {
	return func(_ context.Context, tenant, missionID string, f gibsonagent.Finding) {
		if reg == nil {
			return
		}
		reg.For(tenant).Submit(brain.FindingRaised{
			ID:          f.ID.String(),
			Title:       f.Title,
			Description: f.Description,
			Severity:    string(f.Severity),
			// Mission-evidence edge (gibson#1078): the submitter resolves the mission
			// id from the work-item context and passes it through, so a component-path
			// finding attaches to the mission that produced it. Empty = tenant-ambient.
			MissionID: missionID,
		})
	}
}

// ingestDiscovery returns the World sink for the DiscoveryResult ingest path
// (ADR-0012 step 8, gibson#1266). A tool that reports discovered entities in
// proto field 100 reaches the knowledge graph the same way every other producer
// does: Timeline event → World → graph projector. The path used to run through
// `graphrag/loader`, which built Cypher out of the payload's own labels and
// property names; that package is gone.
//
// tenant is empty on the dispatch paths that never resolved one (the harness
// callback and the sandboxed executor both carry mission context, not tenancy),
// so it falls back to the daemon's registry tenant exactly as ingestObservation
// does on the same callback surface. Resolving it properly is gibson#1256.
func ingestDiscovery(reg *brain.Registry, fallbackTenant string) ingest.WorldSink {
	return func(tenant string, ev brain.Event) {
		if tenant == "" {
			tenant = fallbackTenant
		}
		if tenant == "" {
			return
		}
		reg.For(tenant).Submit(ev)
	}
}

// newDiscoveryProcessor builds the daemon's single DiscoveryResult processor.
//
// All three dispatch paths that can carry a DiscoveryResult — the harness
// callback service, the sandboxed (Setec) executor and the ComponentService's
// SubmitResult — share this one instance, so there is one translation and one
// World sink rather than three.
//
// It is total: the brain registry is constructed unconditionally in Start
// before any of the three wiring sites runs, so there is no "no World to fold
// into" state to degrade into at request time. A constructor that could return
// nil would put that decision back at each call site, which is how the ingest
// path came to be imported in seven files and wired in none (gibson#1266).
func (d *daemonImpl) newDiscoveryProcessor() ingest.DiscoveryProcessor {
	return ingest.NewDiscoveryProcessor(
		ingestDiscovery(d.brainRegistry, d.registryTenant),
		d.logger.WithComponent("discovery-ingest").Slog(),
	)
}

// discoveryProcessorAdapter widens ingest.DiscoveryProcessor's typed
// (*ProcessResult, error) return to the (interface{}, error) signature that the
// harness, sandboxed and component packages each declare locally. Those packages
// keep their own narrow interface so they do not import the ingest package's
// result type; this is the single point of contact.
type discoveryProcessorAdapter struct {
	inner ingest.DiscoveryProcessor
}

func (a *discoveryProcessorAdapter) Process(
	ctx context.Context,
	execCtx ingest.ExecContext,
	discovery *graphragpb.DiscoveryResult,
) (interface{}, error) {
	res, err := a.inner.Process(ctx, execCtx, discovery)
	if err != nil {
		return nil, fmt.Errorf("discovery ingest: %w", err)
	}
	return res, nil
}

// The adapter must satisfy all three consumers. Asserting it here means a
// signature drift in any of them breaks the build at the seam rather than
// leaving one dispatch path quietly unwired, which is the failure mode
// gibson#1266 exists to remove.
var (
	_ harness.DiscoveryProcessor         = (*discoveryProcessorAdapter)(nil)
	_ sandboxed.DiscoveryProcessor       = (*discoveryProcessorAdapter)(nil)
	_ component.ResultDiscoveryProcessor = (*discoveryProcessorAdapter)(nil)
)

// ingestDelegation returns the harness DelegationSink (ADR-0007): an agent
// delegation is folded into the tenant World as AgentRunObserved events for both
// the parent and child run, so the graph projector — the sole writer — materializes
// the :AgentRun nodes and the DELEGATED_TO edge. Replaces the old direct
// CreateRelationship write in the harness (gibson#837). The parent observation also
// covers the root run, which is never itself delegated-to.
func ingestDelegation(reg *brain.Registry) harness.DelegationSink {
	return func(_ context.Context, d harness.DelegationObserved) {
		if reg == nil || d.Tenant == "" {
			return
		}
		eng := reg.For(d.Tenant)
		if d.ParentRunID != "" {
			eng.Submit(brain.AgentRunObserved{
				RunID: d.ParentRunID, AgentName: d.ParentAgent, ScopeID: d.Scope,
			})
		}
		if d.ChildRunID != "" {
			eng.Submit(brain.AgentRunObserved{
				RunID: d.ChildRunID, ParentRunID: d.ParentRunID, AgentName: d.ChildAgent, ScopeID: d.Scope,
			})
		}
	}
}

// ingestObservation returns the callback service's observation sink (ADR-0007):
// it translates a typed agent observation into a brain Timeline event and submits
// it to the tenant's World engine. The reducer + scope-relative identity
// (ADR-0002) resolve the entity and its topology — the agent authors neither.
//
// Tenant and scope arrive already resolved in attr (ADR-0012). The callback
// service read both off the daemon's mission record, so this sink neither takes
// a tenant at construction — it used to close over one process-wide value, which
// put every tenant's observations in one World — nor reads either from req. The
// request is consulted only for the observation itself.
func ingestObservation(reg *brain.Registry) harness.ObservationSink {
	return func(_ context.Context, attr harness.ObservationAttribution, req *harnesspb.ObserveRequest) error {
		if reg == nil || req == nil {
			return nil
		}
		tenant := attr.Tenant
		// Scope is the mission's target, not the mission: two runs over the same
		// network merge onto the same hosts (recurrence is signal), and two
		// networks stay distinct even inside one mission.
		scope := attr.ScopeID
		// Mission-evidence edge (gibson#1075): carry the mission id so the brain
		// can attribute the discovered host to the mission that found it. Kept
		// separate from scope so the two concepts do not re-conflate.
		missionID := attr.MissionID
		switch o := req.Observation.(type) {
		case *harnesspb.ObserveRequest_Host:
			h := o.Host
			var openPorts []int
			var services map[int]brain.ServiceInfo
			var endpoints map[int][]brain.EndpointInfo
			var technologies map[int][]brain.TechnologyInfo
			var certificates map[int]brain.CertificateInfo
			for _, p := range h.Ports {
				num := int(p.Number)
				openPorts = append(openPorts, num)
				svc := brain.ServiceInfo{Protocol: p.Protocol, Name: p.Service, Product: p.Product, Version: p.Version}
				if (svc != brain.ServiceInfo{}) {
					if services == nil {
						services = map[int]brain.ServiceInfo{}
					}
					services[num] = svc
				}
				for _, e := range p.Endpoints {
					if endpoints == nil {
						endpoints = map[int][]brain.EndpointInfo{}
					}
					endpoints[num] = append(endpoints[num], brain.EndpointInfo{Path: e.Path, Status: int(e.Status)})
				}
				for _, tch := range p.Technologies {
					if technologies == nil {
						technologies = map[int][]brain.TechnologyInfo{}
					}
					technologies[num] = append(technologies[num], brain.TechnologyInfo{Name: tch.Name, Version: tch.Version})
				}
				if c := p.Certificate; c != nil {
					if certificates == nil {
						certificates = map[int]brain.CertificateInfo{}
					}
					certificates[num] = brain.CertificateInfo{Fingerprint: c.Fingerprint, Subject: c.Subject, Issuer: c.Issuer, NotAfter: c.NotAfter}
				}
			}
			reg.For(tenant).Submit(brain.HostObserved{
				MissionID:    missionID,
				ScopeID:      scope,
				Address:      h.Address,
				SSHHostKey:   h.SshHostKey,
				CloudID:      h.CloudId,
				OpenPorts:    openPorts,
				Services:     services,
				Endpoints:    endpoints,
				Technologies: technologies,
				Certificates: certificates,
			})
		case *harnesspb.ObserveRequest_Domain:
			reg.For(tenant).Submit(brain.DomainObserved{ScopeID: scope, Name: o.Domain.Name})
		case *harnesspb.ObserveRequest_Credential:
			c := o.Credential
			reg.For(tenant).Submit(brain.CredentialObserved{
				ScopeID: scope, SecretHash: c.SecretHash, Username: c.Username, CredentialKind: c.Kind,
			})
		case *harnesspb.ObserveRequest_Account:
			a := o.Account
			reg.For(tenant).Submit(brain.AccountObserved{ScopeID: scope, Identifier: a.Identifier, AccountKind: a.Kind})
		case *harnesspb.ObserveRequest_Subdomain:
			s := o.Subdomain
			reg.For(tenant).Submit(brain.SubdomainObserved{
				ScopeID: scope, FQDN: s.Fqdn, Domain: s.Domain, Addresses: s.Addresses,
			})
		case *harnesspb.ObserveRequest_LifecycleEntity:
			// A typed application-lifecycle entity an agent reported (sdk#537).
			// It translates through the SAME mapping a tool's CustomNode uses,
			// so the two reporters cannot disagree about what a label or an
			// edge means (ADR-0027).
			//
			// A sighting the Taxonomy does not admit falls through to the gate
			// below rather than being dropped: the reporter still saw
			// something, and an Observation keeps it queryable.
			e := o.LifecycleEntity
			sighting := ingest.EntitySighting{
				Label:        e.GetLabel(),
				IDProperties: e.GetIdProperties(),
				Properties:   e.GetProperties(),
			}
			for _, edge := range e.GetEdges() {
				if edge == nil {
					continue
				}
				sighting.Edges = append(sighting.Edges, ingest.EntitySightingEdge{
					Type:               edge.GetType(),
					TargetLabel:        edge.GetTargetLabel(),
					TargetIDProperties: edge.GetTargetIdProperties(),
				})
			}
			if ev, _, ok := ingest.EntityObservedFromSighting(sighting, scope, missionID); ok {
				reg.For(tenant).Submit(ev)
			} else if obs, gated := gateObservation(req, scope, missionID, time.Now()); gated {
				reg.For(tenant).Submit(obs)
			}
		default:
			// The Taxonomy gate (ADR-0012). A shape no typed case claimed is
			// out of the Taxonomy, so it lands as an Observation rather than
			// falling out of the bottom of this switch and being lost.
			if obs, ok := gateObservation(req, scope, missionID, time.Now()); ok {
				reg.For(tenant).Submit(obs)
			}
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
	case "finding.discovered", "finding.submitted", "agent.finding_submitted":
		if fe := ed.FindingEvent; fe != nil {
			eng.Submit(brain.FindingRaised{
				ID:          fe.Finding.ID,
				Title:       fe.Finding.Title,
				Description: fe.Finding.Description,
				Severity:    fe.Finding.Severity,
				// Mission-evidence edge (gibson#1075): the mission-event carries the
				// mission id, so the finding attaches to the mission that raised it.
				MissionID: fe.MissionID,
			})
		}
	}
}

// ingestLLMCall returns the DaemonServer's LLM-call capture sink (gibson#755):
// it folds a completed ExecuteLLM call into the calling tenant's brain World as
// an LlmCall entity — the World replacement for the Langfuse trace/cost views.
// Unlike ingestObservation (single dev tenant), this routes by the tenant the
// call ran under, so it is multi-tenant correct.
func ingestLLMCall(reg *brain.Registry) api.LLMCallSink {
	return func(_ context.Context, tenant string, call api.LLMCallRecord) {
		if reg == nil || call.CallID == "" {
			return
		}
		msgs := make([]brain.LlmMessage, 0, len(call.Messages))
		for _, m := range call.Messages {
			msgs = append(msgs, brain.LlmMessage{Role: m.Role, Content: m.Content})
		}
		reg.For(tenant).Submit(brain.LlmCallObserved{
			CallID:  call.CallID,
			RunID:   call.RunID,
			Model:   call.Model,
			ScopeID: call.ScopeID,
			// Mission-evidence edge (gibson#1078): a mission-aware ExecuteLLM caller
			// stamps mission_id on the request; the handler carries it onto the record
			// so the call attaches to its mission's frame. Empty = tenant-ambient (e.g.
			// dashboard chat), which never attaches to a mission frame.
			MissionID:        call.MissionID,
			PromptTokens:     call.PromptTokens,
			CompletionTokens: call.CompletionTokens,
			Messages:         msgs,
			Completion:       call.Completion,
		})
	}
}
