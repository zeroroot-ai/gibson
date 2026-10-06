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
	// Hypotheses is the Hypothesis provenance class (ADR-0121, gibson#265):
	// an agent's proposed, unproven claim. Snapshotted separately from every
	// Evidence store and from Belief — the three provenance classes stay
	// distinct across a snapshot round trip too.
	Hypotheses []HypothesisSnapshot `json:"hypotheses"`
	// BetSettlements is the proof-of-demonstration outcome store (ADR-0131,
	// gibson#278). Snapshotted like AgentRuns — an externally-keyed record
	// with no monotonic id counter of its own.
	BetSettlements []BetSettlementSnapshot `json:"bet_settlements"`
	// NodeBeliefs backs BeliefSubstrate for every non-Host node kind
	// (NodeKindClaim, NodeKindTechniqueEnvironment — ADR-0129, gibson#272's
	// substrate seam). Externally-keyed by NodeRef, like BetSettlements — no
	// monotonic id counter of its own.
	NodeBeliefs []NodeBeliefSnapshot `json:"node_beliefs"`
	// EdgeOutcomes is the per-enablement-edge-type outcome statistic
	// (gibson#613), keyed by edge type like NodeBeliefs is keyed by ref.
	EdgeOutcomes []EdgeOutcomeSnapshot `json:"edge_outcomes"`
	// DestructiveActions is the destructive-proof authorization queue
	// (ADR-0132, gibson#336), pending and decided alike. Snapshotted like
	// BetSettlements — an externally-keyed record with no monotonic id
	// counter of its own.
	DestructiveActions []DestructiveActionSnapshot `json:"destructive_actions"`
	// VoIPlans is the per-mission VoI planning state (ADR-0126, gibson#283),
	// pending and completed alike. Snapshotted like BetSettlements — an
	// externally-keyed (MissionID) record with no monotonic id counter of
	// its own. Missing this field silently dropped in-flight VoI planning
	// state across a snapshot-and-trim cycle (gibson#341).
	VoIPlans []VoIPlanSnapshot `json:"voi_plans"`
	// AgentToolCalls + FlightRecorderPolicy: the flight recorder's captured
	// tool I/O and the tenant's retention/redaction policy (ADR-0120,
	// gibson#271). The policy must be snapshotted too, or a tenant's
	// opt-in redaction/retention setting would silently reset to the
	// capture-everything default across a snapshot+trim cycle.
	AgentToolCalls       []AgentToolCallSnapshot `json:"agent_tool_calls"`
	FlightRecorderPolicy FlightRecorderPolicy    `json:"flight_recorder_policy"`

	// DomainPacks is the tenant's currently enabled Domain Packs (ADR-0133,
	// gibson#381). Must be snapshotted like FlightRecorderPolicy above, or a
	// tenant's enabled packs would silently vanish across a snapshot+trim
	// cycle even though the World fold never disabled them.
	DomainPacks []DomainPackSnapshot `json:"domain_packs"`

	// MissionLineage is the lineage of each mission that a component
	// originated (gibson#734). The snapshot must hold it, or the lineage is
	// gone after the trim removes the mission.originated events.
	MissionLineage []MissionLineage `json:"mission_lineage,omitempty"`

	// ProofReviews is the proofs with agent-typed evidence that wait for a
	// human review (proof_review.go). Without it a pending review would
	// vanish across a snapshot and trim cycle.
	ProofReviews []ProofReviewSnapshot `json:"proof_reviews"`

	// MissionRewinds is the parent of each mission that a rewind started
	// (ADR-0170). Without it the link from a rewound mission to its earlier
	// run would vanish across a snapshot and trim cycle.
	MissionRewinds []MissionRewind `json:"mission_rewinds"`

	// Monotonic ID counters (replay-deterministic; must be restored exactly).
	NextHostID        uint64 `json:"next_host_id"`
	NextDomainID      uint64 `json:"next_domain_id"`
	NextSubdomainID   uint64 `json:"next_subdomain_id"`
	NextCredentialID  uint64 `json:"next_credential_id"`
	NextAccountID     uint64 `json:"next_account_id"`
	NextObservationID uint64 `json:"next_observation_id"`
	NextEntityID      uint64 `json:"next_entity_id"`
	NextHypothesisID  uint64 `json:"next_hypothesis_id"`
	NextCompletedSeq  uint64 `json:"next_completed_seq"`
}

// SnapshotWorld serializes the current World into a WorldSnapshot at atSeq.
// atSeq is the Timeline sequence ID of the last event folded into the snapshot.
func SnapshotWorld(w *World, atSeq string) WorldSnapshot {
	data := worldSnapshotData{
		Hosts:              w.Snapshot(),
		Missions:           w.MissionSnapshot(),
		Work:               w.WorkSnapshot(),
		Findings:           w.FindingSnapshot(),
		Labels:             w.LabelSnapshot(),
		Domains:            w.DomainSnapshot(),
		Subdomains:         w.SubdomainSnapshot(),
		Credentials:        w.CredentialSnapshot(),
		Accounts:           w.AccountSnapshot(),
		AgentRuns:          w.AgentRunSnapshot(),
		LlmCalls:           w.LlmCallSnapshot(),
		Decisions:          w.DecisionSnapshot(),
		Observations:       w.ObservationSnapshot(),
		Entities:           w.EntitySnapshot(),
		Hypotheses:         w.HypothesisSnapshot(),
		BetSettlements:     w.BetSettlementSnapshot(),
		NodeBeliefs:        w.NodeBeliefSnapshot(),
		EdgeOutcomes:       w.EdgeOutcomeSnapshot(),
		DestructiveActions: w.DestructiveActionSnapshot(),
		VoIPlans:           w.VoIPlanSnapshot(),

		AgentToolCalls:       w.AgentToolCallSnapshot(),
		FlightRecorderPolicy: w.flightRecorderPolicy,
		DomainPacks:          w.DomainPackSnapshot(),
		MissionLineage:       w.MissionLineageSnapshot(),
		ProofReviews:         w.ProofReviewSnapshot(),
		MissionRewinds:       w.MissionRewindSnapshot(),

		NextHostID:        w.nextHostID,
		NextDomainID:      w.nextDomainID,
		NextSubdomainID:   w.nextSubdomainID,
		NextCredentialID:  w.nextCredentialID,
		NextAccountID:     w.nextAccountID,
		NextObservationID: w.nextObservationID,
		NextEntityID:      w.nextEntityID,
		NextHypothesisID:  w.nextHypothesisID,
		NextCompletedSeq:  w.nextCompletedSeq,
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

	// Restore the flight recorder's retention/redaction policy FIRST (gibson#271):
	// it must be in force before any LlmCall/AgentToolCall replay below, exactly
	// as it was live when the snapshot was taken (redaction is applied once, at
	// fold time, so folding order matters for a faithful restore).
	Reduce(w, FlightRecorderPolicySet{
		Redact:        data.FlightRecorderPolicy.Redact,
		RetentionDays: data.FlightRecorderPolicy.RetentionDays,
	})

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

	// Replay missions — carry display metadata (ADR-0163/gibson#1118) so the
	// restored World is the single source of truth for status + identity.
	for _, m := range data.Missions {
		if m.Status == MissionPending {
			Reduce(w, MissionCreated{ID: m.ID, Name: m.Name, Description: m.Description, TargetID: m.TargetID, TenantID: m.TenantID, CreatedBy: m.CreatedBy})
			continue
		}
		startEv := MissionStarted{
			ID:          m.ID,
			Goal:        m.Goal,
			BeliefModel: m.BeliefModel,
			Name:        m.Name,
			Description: m.Description,
			TargetID:    m.TargetID,
			TenantID:    m.TenantID,
			CreatedBy:   m.CreatedBy,
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
			Group:     wi.Group,
			Limit:     wi.Limit,
			Network:   wi.Network,
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
		// The restore replays completions in snapshot order, which is not the
		// Timeline order a join's FIRST/LAST read. Put the recorded order back.
		if ent, ok := findWork(w, wi.ID); ok {
			w.work.Get(ent).CompletedSeq = wi.CompletedSeq
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

	// Replay bet settlements (ADR-0131/0123, gibson#278/#279/#280). Order
	// does not matter: identity is HypothesisID, not a world-assigned
	// counter, so there is no id-renumbering hazard the way there is for
	// observations/entities. Dispatch on the recorded Method, not Verdict:
	// Method alone determines which event type reproduces the fact exactly
	// (a HITL settlement can carry either verdict, so switching on Verdict
	// alone could replay a HITL FALSE as a bounded-exhaustion FALSE with no
	// budget/reason recorded).
	for _, s := range data.BetSettlements {
		switch s.Method {
		case SettlementMethodPredicate:
			Reduce(w, BetSettledTrue{
				HypothesisID:         s.HypothesisID,
				Technique:            s.Technique,
				PredicateType:        s.PredicateType,
				EvidenceDigest:       s.EvidenceDigest,
				PredictedProbability: s.PredictedProbability,
				BrierScore:           s.BrierScore,
				ScopeID:              s.ScopeID,
				MissionID:            s.MissionID,
			})
		case SettlementMethodExhaustion:
			Reduce(w, BetSettledFalse{
				HypothesisID:         s.HypothesisID,
				AttemptBudget:        s.AttemptBudget,
				AttemptsMade:         s.AttemptsMade,
				Reason:               s.Reason,
				PredictedProbability: s.PredictedProbability,
				BrierScore:           s.BrierScore,
				ScopeID:              s.ScopeID,
				MissionID:            s.MissionID,
			})
		case SettlementMethodHITL:
			Reduce(w, BetSettledByHITL{
				HypothesisID:         s.HypothesisID,
				Verdict:              s.Verdict,
				UserID:               s.UserID,
				PredictedProbability: s.PredictedProbability,
				BrierScore:           s.BrierScore,
				ScopeID:              s.ScopeID,
				MissionID:            s.MissionID,
			})
		}
	}

	// Replay non-Host node beliefs (ADR-0129, gibson#272's substrate
	// seam). Order does not matter: identity is NodeRef, not a
	// world-assigned counter, same as BetSettlements above.
	for _, nb := range data.NodeBeliefs {
		Reduce(w, NodeBeliefSet(nb))
	}

	// Restore the edge outcome counts (gibson#613). They are a folded
	// statistic, not a record list, so they are set rather than replayed.
	for _, eo := range data.EdgeOutcomes {
		w.edgeOutcomes[eo.EdgeType] = EdgeOutcomeCount{Alpha: eo.Alpha, Beta: eo.Beta}
	}

	// Replay destructive-proof authorization actions (ADR-0132, gibson#336):
	// always replay the request first, then the decision if one landed —
	// applyDestructiveActionDecided is a no-op without a matching request, so
	// order here matters, unlike the order-independent BetSettlements loop
	// above (whose identity is likewise HypothesisID, but which never has a
	// second, dependent event to sequence after the first).
	for _, a := range data.DestructiveActions {
		Reduce(w, DestructiveActionRequested{
			HypothesisID:      a.HypothesisID,
			Tenant:            a.Tenant,
			ScopeID:           a.ScopeID,
			MissionID:         a.MissionID,
			Technique:         a.Technique,
			PredicateType:     a.PredicateType,
			BlastRadius:       a.BlastRadius,
			Reversibility:     a.Reversibility,
			RequestedAtUnixMS: a.RequestedAtUnixMS,
		})
		if a.Decided {
			Reduce(w, DestructiveActionDecided{
				HypothesisID:    a.HypothesisID,
				Approved:        a.Approved,
				UserID:          a.UserID,
				DecidedAtUnixMS: a.DecidedAtUnixMS,
			})
		}
	}

	// Replay VoI plan state (ADR-0126, gibson#283/#341): always replay the
	// request first, then the completed round if one landed —
	// applyVoIPlanned's defensive branch would otherwise create a second,
	// duplicate entity when findVoIPlanState's lookup runs before the
	// request has been replayed.
	for _, p := range data.VoIPlans {
		Reduce(w, VoIPlanRequested{MissionID: p.MissionID, Cursor: p.Cursor})
		if !p.InFlight {
			Reduce(w, VoIPlanned{
				MissionID:  p.MissionID,
				Cursor:     p.Cursor,
				Candidates: p.Candidates,
			})
		}
	}

	// Replay the proofs that wait for a review. Content was redacted when it
	// was first folded, and the redaction is stable on a second pass.
	for _, r := range data.ProofReviews {
		Reduce(w, BetProofSubmittedForReview{
			HypothesisID:        r.HypothesisID,
			MissionID:           r.MissionID,
			ScopeID:             r.ScopeID,
			Technique:           r.Technique,
			Evidence:            append([]ProofReviewEvidence(nil), r.Evidence...),
			SubmittedAtUnixNano: r.SubmittedAtUnixNano,
		})
	}

	// Replay the parent of each rewound mission (ADR-0170).
	for _, r := range data.MissionRewinds {
		Reduce(w, MissionRewound(r))
	}

	// Replay the lineage of each originated mission (gibson#734). Identity is
	// the mission id, so the order does not matter.
	for _, l := range data.MissionLineage {
		Reduce(w, MissionOriginated(l))
	}

	// Replay enabled Domain Packs (ADR-0133, gibson#381). Order does not
	// matter: identity is Name, not a world-assigned counter, same as
	// BetSettlements above — a disabled pack is simply absent from
	// data.DomainPacks, so only currently-enabled packs replay here.
	for _, p := range data.DomainPacks {
		Reduce(w, DomainPackEnabled{
			Name:                      p.Name,
			Version:                   p.Version,
			TaxonomyNodeLabels:        append([]string(nil), p.TaxonomyNodeLabels...),
			TaxonomyRelationshipTypes: append([]string(nil), p.TaxonomyRelationshipTypes...),
			Predicates:                clonePredicateMap(p.Predicates),
			NonDestructivePredicates:  append([]string(nil), p.NonDestructivePredicates...),
		})
	}

	// Replay LLM calls.
	for _, c := range data.LlmCalls {
		Reduce(w, LlmCallObserved{
			CallID:              c.CallID,
			RunID:               c.RunID,
			Model:               c.Model,
			ScopeID:             c.ScopeID,
			PromptTokens:        c.PromptTokens,
			CompletionTokens:    c.CompletionTokens,
			Messages:            append([]LlmMessage(nil), c.Messages...),
			Completion:          c.Completion,
			CompletionToolCalls: append([]LlmToolCall(nil), c.CompletionToolCalls...),
			RecordedAtUnixNano:  c.RecordedAtUnixNano,
		})
	}

	// Replay tool calls (ADR-0120, gibson#271). AgentToolCallSnapshot and
	// AgentToolCallObserved share identical fields, so a direct conversion
	// replaces the field-by-field literal.
	for _, c := range data.AgentToolCalls {
		Reduce(w, AgentToolCallObserved(c))
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
	// the same Neo4j nodes (ADR-0112) — but the world id rides along to the
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

	// Replay hypotheses in id order for the same reason as entities and
	// observations: the world id rides along to the graph projection, so the
	// order must not renumber it. HypothesisID (the agent-chosen join key,
	// gibson#339) is a separate field and replays unaffected by this order.
	sort.Slice(data.Hypotheses, func(i, j int) bool {
		return data.Hypotheses[i].ID < data.Hypotheses[j].ID
	})
	for _, h := range data.Hypotheses {
		Reduce(w, HypothesisObserved{
			MissionID:    h.MissionID,
			RunID:        h.RunID,
			ScopeID:      h.ScopeID,
			Proposer:     h.Proposer,
			Confidence:   h.Confidence,
			Claim:        h.Claim,
			HypothesisID: h.HypothesisID,
			Technique:    h.Technique,
			References:   h.References,
		})
	}
	w.nextHypothesisID = data.NextHypothesisID
	w.nextCompletedSeq = data.NextCompletedSeq

	return w, nil
}
