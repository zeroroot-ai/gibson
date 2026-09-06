// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"encoding/json"
	"fmt"
	"sort"
)

// worldSnapshotData is the JSON-serializable content of a WorldSnapshot.
// It captures all entity stores as stable snapshot slices plus the
// monotonic ID counters needed to reproduce replay-deterministic IDs.
type worldSnapshotData struct {
	Hosts        []HostSnapshot        `json:"hosts"`
	Missions     []MissionSnapshot     `json:"missions"`
	Work         []WorkSnapshot        `json:"work"`
	Findings     []FindingSnapshot     `json:"findings"`
	Labels       []LabelSnapshot       `json:"labels"`
	Domains      []DomainSnapshot      `json:"domains"`
	Subdomains   []SubdomainSnapshot   `json:"subdomains"`
	Credentials  []CredentialSnapshot  `json:"credentials"`
	Accounts     []AccountSnapshot     `json:"accounts"`
	AgentRuns    []AgentRunSnapshot    `json:"agent_runs"`
	LlmCalls     []LlmCallSnapshot     `json:"llm_calls"`
	Decisions    []DecisionSnapshot    `json:"decisions"`
	Observations []ObservationSnapshot `json:"observations"`
	Entities     []EntitySnapshot      `json:"entities"`

	// Monotonic ID counters (replay-deterministic; must be restored exactly).
	NextHostID        uint64 `json:"next_host_id"`
	NextDomainID      uint64 `json:"next_domain_id"`
	NextSubdomainID   uint64 `json:"next_subdomain_id"`
	NextCredentialID  uint64 `json:"next_credential_id"`
	NextAccountID     uint64 `json:"next_account_id"`
	NextObservationID uint64 `json:"next_observation_id"`
	NextEntityID      uint64 `json:"next_entity_id"`
}

// SnapshotWorld serializes the current World into a WorldSnapshot at atSeq.
// atSeq is the Timeline sequence ID of the last event folded into the snapshot.
func SnapshotWorld(w *World, atSeq string) WorldSnapshot {
	data := worldSnapshotData{
		Hosts:        w.Snapshot(),
		Missions:     w.MissionSnapshot(),
		Work:         w.WorkSnapshot(),
		Findings:     w.FindingSnapshot(),
		Labels:       w.LabelSnapshot(),
		Domains:      w.DomainSnapshot(),
		Subdomains:   w.SubdomainSnapshot(),
		Credentials:  w.CredentialSnapshot(),
		Accounts:     w.AccountSnapshot(),
		AgentRuns:    w.AgentRunSnapshot(),
		LlmCalls:     w.LlmCallSnapshot(),
		Decisions:    w.DecisionSnapshot(),
		Observations: w.ObservationSnapshot(),
		Entities:     w.EntitySnapshot(),

		NextHostID:        w.nextHostID,
		NextDomainID:      w.nextDomainID,
		NextSubdomainID:   w.nextSubdomainID,
		NextCredentialID:  w.nextCredentialID,
		NextAccountID:     w.nextAccountID,
		NextObservationID: w.nextObservationID,
		NextEntityID:      w.nextEntityID,
	}
	b, _ := json.Marshal(data)
	return WorldSnapshot{AtSeq: atSeq, Data: b}
}

// RestoreWorld reconstructs a World from a WorldSnapshot by replaying synthetic
// domain events that reproduce the snapshotted entity state. Monotonic counters
// are restored directly (same package — unexported fields accessible).
func RestoreWorld(snap WorldSnapshot, tenant string) (*World, error) {
	var data worldSnapshotData
	if err := json.Unmarshal(snap.Data, &data); err != nil {
		return nil, fmt.Errorf("brain/snapshot: unmarshal snapshot data: %w", err)
	}

	w := NewWorld(tenant)

	// Replay hosts — sorted by ID (creation order) to reproduce deterministic IDs.
	sort.Slice(data.Hosts, func(i, j int) bool { return data.Hosts[i].ID < data.Hosts[j].ID })
	for _, h := range data.Hosts {
		ev := HostObserved{
			MissionID:    h.MissionID,
			ScopeID:      h.ScopeID,
			Address:      h.Address,
			SSHHostKey:   h.SSHHostKey,
			CloudID:      h.CloudID,
			OpenPorts:    append([]int(nil), h.OpenPorts...),
			Services:     h.Services,
			Endpoints:    h.Endpoints,
			Technologies: h.Technologies,
			Certificates: h.Certificates,
		}
		Reduce(w, ev)
	}

	// Replay missions — carry display metadata (ADR-0011/gibson#1118) so the
	// restored World is the single source of truth for status + identity.
	for _, m := range data.Missions {
		startEv := MissionStarted{
			ID:          m.ID,
			Goal:        m.Goal,
			BeliefModel: m.BeliefModel,
			Name:        m.Name,
			Description: m.Description,
			TargetID:    m.TargetID,
			TenantID:    m.TenantID,
		}
		Reduce(w, startEv)
		switch m.Status {
		case MissionPaused:
			Reduce(w, MissionPauseRequested{ID: m.ID})
		case MissionCompleted:
			Reduce(w, MissionDone{ID: m.ID, Reason: m.Reason, Outcome: MissionCompleted})
		case MissionFailed:
			Reduce(w, MissionDone{ID: m.ID, Reason: m.Reason, Outcome: MissionFailed})
		}
	}

	// Replay work items. WorkDispatched creates them as running with Attempts=1.
	for _, wi := range data.Work {
		dsp := WorkDispatched{
			ID:        wi.ID,
			MissionID: wi.MissionID,
			ItemKind:  wi.Kind,
			Target:    wi.Target,
			Input:     wi.Input,
			Timeout:   wi.Timeout,
		}
		Reduce(w, dsp)
		switch wi.State {
		case WorkDone:
			Reduce(w, WorkCompleted{ID: wi.ID, Result: wi.Result})
		case WorkFailed:
			Reduce(w, WorkCompleted{ID: wi.ID, Err: wi.Err})
		case WorkPending:
			// WorkRetried re-arms a failed WorkItem to pending. Use
			// WorkCompleted(err) first so the retry path applies.
			Reduce(w, WorkCompleted{ID: wi.ID, Err: "restore:pending"})
			Reduce(w, WorkRetried{ID: wi.ID})
		case WorkSkipped:
			// No direct WorkSkipped event path; restore as done (close enough — the
			// tail replay will correct any scheduler state that depends on this).
			Reduce(w, WorkCompleted{ID: wi.ID, Result: wi.Result})
			// WorkRunning: already created as running by WorkDispatched — no extra event.
		}
	}

	// Replay findings.
	for _, f := range data.Findings {
		Reduce(w, FindingRaised{
			ID:              f.ID,
			Title:           f.Title,
			Description:     f.Description,
			ScopeID:         f.ScopeID,
			Address:         f.Address,
			Severity:        f.Severity,
			Status:          f.Status,
			VulnerabilityID: f.VulnerabilityID,
		})
	}

	// Replay labels.
	for _, l := range data.Labels {
		Reduce(w, LabelApplied{
			TargetID: l.TargetID,
			Verdict:  l.Verdict,
			Severity: l.Severity,
			Category: l.Category,
			UserID:   l.UserID,
		})
	}

	// Replay domains.
	for _, d := range data.Domains {
		Reduce(w, DomainObserved{ScopeID: d.ScopeID, Name: d.Name})
	}

	// Replay subdomains.
	for _, s := range data.Subdomains {
		Reduce(w, SubdomainObserved{
			ScopeID:   s.ScopeID,
			FQDN:      s.FQDN,
			Domain:    s.DomainName,
			Addresses: append([]string(nil), s.Addresses...),
		})
	}

	// Replay credentials.
	for _, c := range data.Credentials {
		Reduce(w, CredentialObserved{
			ScopeID:        c.ScopeID,
			SecretHash:     c.SecretHash,
			Username:       c.Username,
			CredentialKind: c.Kind,
		})
	}

	// Replay accounts.
	for _, a := range data.Accounts {
		Reduce(w, AccountObserved{
			ScopeID:     a.ScopeID,
			Identifier:  a.Identifier,
			AccountKind: a.Kind,
		})
	}

	// Replay agent runs.
	for _, r := range data.AgentRuns {
		Reduce(w, AgentRunObserved{
			RunID:       r.RunID,
			ParentRunID: r.ParentRunID,
			AgentName:   r.AgentName,
			ScopeID:     r.ScopeID,
		})
	}

	// Replay LLM calls.
	for _, c := range data.LlmCalls {
		Reduce(w, LlmCallObserved{
			CallID:           c.CallID,
			RunID:            c.RunID,
			Model:            c.Model,
			ScopeID:          c.ScopeID,
			PromptTokens:     c.PromptTokens,
			CompletionTokens: c.CompletionTokens,
			Messages:         append([]LlmMessage(nil), c.Messages...),
			Completion:       c.Completion,
		})
	}

	// Replay decisions in deterministic (ID) order.
	// Each DecisionRequested opens an episode; DecisionCompleted closes it.
	for _, d := range data.Decisions {
		Reduce(w, DecisionRequested{MissionID: d.MissionID, Cursor: d.Cursor})
		if d.Status == decisionCompleted {
			Reduce(w, DecisionCompleted{MissionID: d.MissionID})
		}
	}

	// Replay observations in their original assignment order (by world id).
	// Identity is the Timeline event id, so any deterministic order reproduces
	// the same Neo4j nodes (ADR-0012) — but the world id rides along to the
	// graph as :Observation.brain_id, and replaying in event-id order would
	// renumber it whenever the two orders disagree. Restoring in id order keeps
	// that property stable across a snapshot round trip.
	sort.Slice(data.Observations, func(i, j int) bool {
		return data.Observations[i].ID < data.Observations[j].ID
	})
	for _, o := range data.Observations {
		Reduce(w, ObservationRecorded{
			EventID:    o.EventID,
			ScopeID:    o.ScopeID,
			MissionID:  o.MissionID,
			Shape:      o.Shape,
			Payload:    o.Payload,
			ObservedAt: o.ObservedAt,
		})
	}

	// Restore monotonic ID counters directly (same package; unexported).
	w.nextHostID = data.NextHostID
	w.nextDomainID = data.NextDomainID
	w.nextSubdomainID = data.NextSubdomainID
	w.nextCredentialID = data.NextCredentialID
	w.nextAccountID = data.NextAccountID
	w.nextObservationID = data.NextObservationID

	// Replay entities in id order for the same reason as observations: the
	// world id rides along to the graph, so the order must not renumber it.
	sort.Slice(data.Entities, func(i, j int) bool {
		return data.Entities[i].ID < data.Entities[j].ID
	})
	for _, e := range data.Entities {
		Reduce(w, EntityObserved{
			Label:     e.Label,
			Key:       e.Key,
			ScopeID:   e.ScopeID,
			MissionID: e.MissionID,
			Props:     e.Props,
			Edges:     e.Edges,
		})
	}
	w.nextEntityID = data.NextEntityID

	return w, nil
}
