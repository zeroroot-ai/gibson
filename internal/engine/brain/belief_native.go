// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"strconv"

	"github.com/zeroroot-ai/gibson/internal/engine/brain/beliefvi"
)

// belief_native.go is the real BeliefProvider (ADR-0129, ADR-0134): exact,
// read-only Bayesian inference over the attack-path network, computed
// IN-PROCESS by internal/engine/brain/beliefvi and returning the three
// posteriors (P(juicy)/P(exploitable)/P(reachable)).
//
// This replaces the Python pgmpy sidecar and its HTTP round-trip (ADR-0134,
// gibson#377, hard cutover per ADR-0027): beliefvi is a line-for-line port
// of the sidecar's exact-inference algorithm (variable elimination), parity-
// tested to 1e-12 against the pgmpy/numpy reference sidecar/belief/infer.py
// already held to pgmpy (internal/engine/brain/beliefvi's TestPgmpyParity).
// pgmpy itself never runs anywhere near this binary or any runtime image —
// it stays strictly an offline training / parity-oracle dependency under
// sidecar/belief.
//
// Inference is exact (variable elimination) so the field is deterministic
// and replay-reproducible, and read-only — the model never learns online
// (training is a separate offline batch job, ADR-0129, run by braintrain).
//
// The provider records the model's version in Belief.Model, so each scored
// host carries the version that produced it and replay reproduces it
// (missions pin their version — see Mission.BeliefModel / MissionProjected).
type nativeBelief struct {
	model  *beliefvi.BeliefModel
	priors PriorProvider
}

// NativeBeliefProvider returns a BeliefProvider backed by model, scoring
// in-process via beliefvi (ADR-0134). priors (optional) supplies LLM
// priors for novel nodes; nil disables that path.
func NativeBeliefProvider(model *beliefvi.BeliefModel, priors PriorProvider) BeliefProvider {
	return &nativeBelief{model: model, priors: priors}
}

// Score runs exact inference in-process and returns the posteriors. On any
// error (e.g. impossible evidence under the model) it returns a zero Belief
// (no score rather than a wrong score), mirroring the old sidecar-backed
// provider's fail-quiet contract exactly; the belief gate asks again on the
// next evidence change.
func (p *nativeBelief) Score(ev BeliefEvidence) Belief {
	biEv := beliefvi.Evidence{
		OpenPorts:           ev.OpenPorts,
		Services:            ev.Services,
		Reachable:           ev.Reachable,
		FindingCritical:     ev.FindingCritical,
		FindingHigh:         ev.FindingHigh,
		ExploitDemonstrated: ev.ExploitDemonstrated,
	}

	result, err := p.model.Score(biEv, nil)
	if err != nil {
		return Belief{} // fail-quiet: no score rather than a wrong score
	}

	// Novel nodes: the model had no table. Ask the prior provider (the LLM
	// seam), then re-score once with the injected priors. A single re-pass
	// keeps the call pattern bounded and deterministic (no unbounded
	// prior/score ping-pong) — the same shape the old sidecar-backed
	// provider used, now without a second network round-trip.
	if len(result.Novel) > 0 && p.priors != nil {
		priors := make(map[string]beliefvi.NodePrior, len(result.Novel))
		for _, reason := range result.Novel {
			n := NovelNode{Reason: reason}
			np := p.priors.PriorFor(n)
			priors[novelKey(n)] = beliefvi.NodePrior{
				Juicy:       np.Juicy,
				Exploitable: np.Exploitable,
				Reachable:   np.Reachable,
			}
		}
		if r2, err := p.model.Score(biEv, priors); err == nil {
			result = r2
		}
	}

	return Belief{
		Juicy:       result.Juicy,
		Exploitable: result.Exploitable,
		Reachable:   result.Reachable,
		Model:       result.Version,
	}
}

// Version is the model artifact this provider scores against, for mission
// pinning (ADR-0134) and daemon startup logging.
func (p *nativeBelief) Version() string { return p.model.Version() }

// PriorProvider supplies a prior for a *novel* node the network has no CPT for
// (ADR-0134: "the LLM fills gaps, not the math"). The native provider passes
// any node the model reports as novel to this seam; the returned priors feed
// the next inference. A nil PriorProvider means novel nodes keep the model's
// uninformed default — the math still runs, just without an LLM-estimated prior.
//
// It is deliberately small and side-effect-free: replay determinism requires the
// prior to be a pure function of the evidence it is given (no clock, no network
// fan-out that varies run-to-run). A live LLM-backed implementation must cache /
// log its estimates through the Timeline to stay reproducible — that wiring is
// out of scope here; the seam exists so the novel-node path is not a dead end.
type PriorProvider interface {
	// PriorFor returns P(juicy)/P(exploitable)/P(reachable) priors in [0,1] for a
	// node the model has no table for, keyed by the node's evidence fingerprint.
	PriorFor(node NovelNode) NodePrior
}

// NovelNode describes a node the model could not score because the trained
// network has no CPT covering its evidence shape.
//
// HostID/Address/Evidence are populated by a caller that has that context;
// beliefvi.BeliefModel.Score itself reports novelty only as a reason string
// (matching what the old sidecar wire response ever actually carried — its
// novel entries were {"reason": ...} only, so these three fields were already
// always zero-valued in practice before this port and remain so here).
type NovelNode struct {
	HostID  uint64
	Address string
	Reason  string // e.g. "unknown variable: svc_weird"
}

// NodePrior is an LLM-estimated prior for a novel node, each value in [0,1].
type NodePrior struct {
	Juicy       float64
	Exploitable float64
	Reachable   float64
}

// novelKey is the stable label a novel node is addressed by in the priors map.
func novelKey(n NovelNode) string {
	if n.Address != "" {
		return n.Address
	}
	return "host-" + strconv.FormatUint(n.HostID, 10)
}
