package brain

import "github.com/mlange-42/ark/ecs"

// Belief is the attack-path belief over a target (ADR-0005): the one field with
// three uses (juicy-target score, prioritization, attention scope). It is derived
// from evidence by a BeliefProvider and recorded on the entity. Model pins the
// model version that produced it (replay reproduces; missions pin their version).
type Belief struct {
	Juicy       float64
	Exploitable float64
	Reachable   float64
	Model       string
}

// BeliefProvider scores a host's attack-path beliefs from its evidence.
//
// The real implementation is a **pgmpy sidecar** (ADR-0005): a probabilistic
// graphical model doing exact, read-only, deterministic inference, trained
// offline and versioned. This interface is the seam; placeholderBelief is a
// deterministic Go stand-in so attention (#751) and the Decider can consume
// belief now — it is replaced by the pgmpy-backed provider in a later slice.
type BeliefProvider interface {
	Score(h Host) Belief
}

// BeliefScored records a (re)computed belief for the host at (ScopeID, Address).
// Belief is derived + deterministic, but flows through an event so it is logged
// and replay-reproducible like everything else.
type BeliefScored struct {
	ScopeID string
	Address string
	Belief  Belief
}

func (BeliefScored) Kind() string { return "belief.scored" }

func applyBeliefScored(w *World, e BeliefScored) {
	if ent, ok := findHostByCoord(w, e.ScopeID, e.Address); ok {
		w.hosts.Get(ent).Belief = e.Belief
	}
}

// BeliefSystem returns the engine System that keeps the belief field current. It
// re-scores every host and emits a BeliefScored only when the score changed
// (so it is quiescent and the log stays lean — belief is recomputed on evidence
// change, not stored per tick).
func BeliefSystem(p BeliefProvider) System {
	return func(w *World) []Event {
		var out []Event
		q := ecs.NewFilter1[Host](w.ecs).Query()
		for q.Next() {
			h := q.Get()
			if b := p.Score(*h); b != h.Belief {
				out = append(out, BeliefScored{ScopeID: h.ScopeID, Address: h.Address, Belief: b})
			}
		}
		return out
	}
}

// placeholderBelief is a deterministic stand-in for the pgmpy provider (ADR-0005).
// A reachable host with more open ports scores higher exploitability/juiciness.
// NOT the real model — swapped for the pgmpy sidecar.
type placeholderBelief struct{}

func (placeholderBelief) Score(h Host) Belief {
	open := 0
	for _, p := range h.Ports {
		if p.Open {
			open++
		}
	}
	reachable := 0.0
	if open > 0 {
		reachable = 1.0
	}
	exploitable := float64(open) / (float64(open) + 1.0) // 0,0.5,0.67,… monotonic in open ports
	return Belief{
		Juicy:       reachable * exploitable,
		Exploitable: exploitable,
		Reachable:   reachable,
		Model:       "placeholder-v0",
	}
}

// PlaceholderBeliefProvider returns the deterministic stand-in provider.
func PlaceholderBeliefProvider() BeliefProvider { return placeholderBelief{} }
