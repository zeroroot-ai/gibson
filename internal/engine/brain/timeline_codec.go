// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package brain — event codec for durable Timeline serialisation (ADR-0163).
package brain

import (
	"encoding/json"
	"fmt"
)

// eventEnvelope is the wire format for a persisted brain.Event.
//
// Encoding:
//
//	{"kind":"<Event.Kind()>","payload":<json of concrete type>}
//
// "kind" drives type reconstruction on replay. Every concrete brain.Event is
// registered in eventRegistry via registerEvent (called from init). The codec
// is the ONLY place that maps kind → Go type; Reduce is the ONLY place that
// maps kind → World mutation.
type eventEnvelope struct {
	Kind    string          `json:"kind"`
	Payload json.RawMessage `json:"payload"`
}

// eventRegistry maps Event.Kind() → constructor for the concrete type.
// Populated by registerEvent in init below.
var eventRegistry = map[string]func() Event{}

// registerEvent adds one kind → constructor entry to the registry. Called
// from init; panics on duplicate registration (a programming error).
func registerEvent(kind string, ctor func() Event) {
	if _, dup := eventRegistry[kind]; dup {
		panic(fmt.Sprintf("brain/codec: duplicate event registration for kind %q", kind))
	}
	eventRegistry[kind] = ctor
}

func init() {
	// brain.go
	registerEvent("host.observed", func() Event { return &HostObserved{} })

	// domain.go
	registerEvent("domain.observed", func() Event { return &DomainObserved{} })
	registerEvent("subdomain.observed", func() Event { return &SubdomainObserved{} })

	// credential.go
	registerEvent("credential.observed", func() Event { return &CredentialObserved{} })
	registerEvent("account.observed", func() Event { return &AccountObserved{} })

	// observation.go
	registerEvent("observation.recorded", func() Event { return &ObservationRecorded{} })

	// work.go
	registerEvent("work.dispatched", func() Event { return &WorkDispatched{} })
	registerEvent("work.retried", func() Event { return &WorkRetried{} })
	registerEvent("work.completed", func() Event { return &WorkCompleted{} })

	// condition.go
	registerEvent("condition.resolved", func() Event { return &ConditionResolved{} })

	// decider.go
	registerEvent("decision.requested", func() Event { return &DecisionRequested{} })
	registerEvent("decision.completed", func() Event { return &DecisionCompleted{} })

	// budget.go
	registerEvent("token.used", func() Event { return &TokenUsed{} })

	// orchestrator.go
	registerEvent("mission.created", func() Event { return &MissionCreated{} })
	registerEvent("mission.started", func() Event { return &MissionStarted{} })
	registerEvent("mission.projected", func() Event { return &MissionProjected{} })
	registerEvent("mission.pause", func() Event { return &MissionPauseRequested{} })
	registerEvent("mission.resume", func() Event { return &MissionResumed{} })
	registerEvent("mission.done", func() Event { return &MissionDone{} })

	// mission_rewind.go
	registerEvent("mission.rewound", func() Event { return &MissionRewound{} })

	// belief.go
	registerEvent("belief.requested", func() Event { return &BeliefScoreRequested{} })
	registerEvent("belief.scored", func() Event { return &BeliefScored{} })

	// belief_slice_gate.go (ADR-0129, gibson#275): registered for codec
	// completeness like every other Event, though the live graph-coupled
	// pipeline (WireSliceBelief/SliceBeliefWorker) drives SliceGate.Apply
	// directly rather than through Engine.Submit/Reduce today — the belief
	// write itself lands via BeliefSubstrate.SetBelief, not a World mutation
	// Reduce would apply. Registering the codec still matters: it is what a
	// future Submit-based caller (or a replay of a differently-produced
	// Timeline) needs to decode these kinds at all.
	registerEvent("belief.slice_requested", func() Event { return &SliceScoreRequested{} })
	registerEvent("belief.slice_scored", func() Event { return &SliceScored{} })

	// node_belief.go
	registerEvent("node_belief.set", func() Event { return &NodeBeliefSet{} })

	// attention.go
	registerEvent("finding.raised", func() Event { return &FindingRaised{} })
	registerEvent("finding.status_changed", func() Event { return &FindingStatusChanged{} })

	// rescan.go
	registerEvent("scan.reconciled", func() Event { return &ScanReconciled{} })

	// entity.go
	registerEvent("entity.observed", func() Event { return &EntityObserved{} })

	// label.go
	registerEvent("label.applied", func() Event { return &LabelApplied{} })

	// provenance.go
	registerEvent("agent_run.observed", func() Event { return &AgentRunObserved{} })

	// hypothesis.go
	registerEvent("hypothesis.observed", func() Event { return &HypothesisObserved{} })

	// bet_settlement.go
	registerEvent("bet.settled_true", func() Event { return &BetSettledTrue{} })
	registerEvent("bet.settled_false", func() Event { return &BetSettledFalse{} })
	registerEvent("bet.settled_by_hitl", func() Event { return &BetSettledByHITL{} })

	// edge_outcome.go
	registerEvent("edge.outcome_observed", func() Event { return &EdgeOutcomeObserved{} })

	// destructive_authz.go
	registerEvent("destructive_action.requested", func() Event { return &DestructiveActionRequested{} })
	registerEvent("destructive_action.decided", func() Event { return &DestructiveActionDecided{} })

	// voi_planner.go
	registerEvent("voi.plan.requested", func() Event { return &VoIPlanRequested{} })
	registerEvent("voi.plan.completed", func() Event { return &VoIPlanned{} })

	// llm_call.go
	registerEvent("llm_call.observed", func() Event { return &LlmCallObserved{} })

	// tool_call.go
	registerEvent("agent_tool_call.observed", func() Event { return &AgentToolCallObserved{} })

	// flight_recorder.go
	registerEvent("flight_recorder.policy_set", func() Event { return &FlightRecorderPolicySet{} })
	registerEvent("flight_recorder.retention_swept", func() Event { return &FlightRecorderRetentionSwept{} })

	// domain_pack.go
	registerEvent("mission.originated", func() Event { return &MissionOriginated{} })
	registerEvent("domain_pack.enabled", func() Event { return &DomainPackEnabled{} })
	registerEvent("domain_pack.disabled", func() Event { return &DomainPackDisabled{} })

	// proof_review.go
	registerEvent("bet.proof_submitted_for_review", func() Event { return &BetProofSubmittedForReview{} })

	// ontology_extension.go
	registerEvent("ontology_extension.proposed", func() Event { return &OntologyExtensionProposed{} })
	registerEvent("ontology_extension.approved", func() Event { return &OntologyExtensionApproved{} })
	registerEvent("ontology_extension.rejected", func() Event { return &OntologyExtensionRejected{} })
}

// EncodeEvent serialises ev as a JSON envelope. The envelope preserves the
// event kind so DecodeEvent can reconstruct the concrete type without external
// context.
func EncodeEvent(ev Event) ([]byte, error) {
	payload, err := json.Marshal(ev)
	if err != nil {
		return nil, fmt.Errorf("brain/codec: marshal payload for kind %q: %w", ev.Kind(), err)
	}
	env := eventEnvelope{
		Kind:    ev.Kind(),
		Payload: json.RawMessage(payload),
	}
	b, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("brain/codec: marshal envelope for kind %q: %w", ev.Kind(), err)
	}
	return b, nil
}

// DecodeEvent deserialises a JSON envelope produced by EncodeEvent into the
// concrete brain.Event value. Returns an error if the kind is unknown or
// the payload cannot be unmarshalled.
func DecodeEvent(data []byte) (Event, error) {
	var env eventEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("brain/codec: unmarshal envelope: %w", err)
	}
	ctor, ok := eventRegistry[env.Kind]
	if !ok {
		return nil, fmt.Errorf("brain/codec: unknown event kind %q", env.Kind)
	}
	target := ctor()
	if err := json.Unmarshal(env.Payload, target); err != nil {
		return nil, fmt.Errorf("brain/codec: unmarshal payload for kind %q: %w", env.Kind, err)
	}
	// Dereference the pointer target to return the concrete value type, which
	// satisfies the Event interface the same way the original does (value
	// receiver Kind() methods work on both pointer and value).
	return dereferenceEvent(target), nil
}

// dereferenceEvent converts a *ConcreteType back to ConcreteType so callers
// receive the same value-typed Event the reducer switch operates on.
func dereferenceEvent(ev Event) Event {
	switch v := ev.(type) {
	case *HostObserved:
		return *v
	case *DomainObserved:
		return *v
	case *SubdomainObserved:
		return *v
	case *CredentialObserved:
		return *v
	case *AccountObserved:
		return *v
	case *ObservationRecorded:
		return *v
	case *WorkDispatched:
		return *v
	case *WorkRetried:
		return *v
	case *WorkCompleted:
		return *v
	case *ConditionResolved:
		return *v
	case *DecisionRequested:
		return *v
	case *DecisionCompleted:
		return *v
	case *TokenUsed:
		return *v
	case *MissionCreated:
		return *v
	case *MissionStarted:
		return *v
	case *MissionProjected:
		return *v
	case *MissionPauseRequested:
		return *v
	case *MissionResumed:
		return *v
	case *MissionDone:
		return *v
	case *MissionRewound:
		return *v
	case *BeliefScoreRequested:
		return *v
	case *BeliefScored:
		return *v
	case *NodeBeliefSet:
		return *v
	case *FindingRaised:
		return *v
	case *ScanReconciled:
		return *v
	case *LabelApplied:
		return *v
	case *AgentRunObserved:
		return *v
	case *HypothesisObserved:
		return *v
	case *BetSettledTrue:
		return *v
	case *BetSettledFalse:
		return *v
	case *BetSettledByHITL:
		return *v
	case *EdgeOutcomeObserved:
		return *v
	case *DestructiveActionRequested:
		return *v
	case *DestructiveActionDecided:
		return *v
	case *VoIPlanRequested:
		return *v
	case *VoIPlanned:
		return *v
	case *LlmCallObserved:
		return *v
	case *AgentToolCallObserved:
		return *v
	case *FlightRecorderPolicySet:
		return *v
	case *FlightRecorderRetentionSwept:
		return *v
	case *MissionOriginated:
		return *v
	case *DomainPackEnabled:
		return *v
	case *DomainPackDisabled:
		return *v
	case *BetProofSubmittedForReview:
		return *v
	case *OntologyExtensionProposed:
		return *v
	case *OntologyExtensionApproved:
		return *v
	case *OntologyExtensionRejected:
		return *v
	default:
		// Unknown pointer type — return as-is; the caller will surface the
		// error when Reduce ignores an unrecognised event.
		return ev
	}
}
