//go:build !embedder_tests

// Package brain — event codec for durable Timeline serialisation (ADR-0011).
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
	registerEvent("mission.started", func() Event { return &MissionStarted{} })
	registerEvent("mission.projected", func() Event { return &MissionProjected{} })
	registerEvent("mission.pause", func() Event { return &MissionPauseRequested{} })
	registerEvent("mission.resume", func() Event { return &MissionResumed{} })
	registerEvent("mission.done", func() Event { return &MissionDone{} })

	// belief.go
	registerEvent("belief.scored", func() Event { return &BeliefScored{} })

	// attention.go
	registerEvent("finding.raised", func() Event { return &FindingRaised{} })

	// label.go
	registerEvent("label.applied", func() Event { return &LabelApplied{} })

	// provenance.go
	registerEvent("agent_run.observed", func() Event { return &AgentRunObserved{} })

	// llm_call.go
	registerEvent("llm_call.observed", func() Event { return &LlmCallObserved{} })
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
	case *BeliefScored:
		return *v
	case *FindingRaised:
		return *v
	case *LabelApplied:
		return *v
	case *AgentRunObserved:
		return *v
	case *LlmCallObserved:
		return *v
	default:
		// Unknown pointer type — return as-is; the caller will surface the
		// error when Reduce ignores an unrecognised event.
		return ev
	}
}
