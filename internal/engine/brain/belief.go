// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/mlange-42/ark/ecs"
)

// belief.go is the belief field (ADR-0005) and the evidence-change gate that
// keeps it current.
//
// Inference is slow — the real provider is an HTTP call to the pgmpy sidecar —
// and the tick is ~50ms, so belief follows the same async-by-observation pattern
// as the Decider (ADR-0004/0009):
//
//   - BeliefSystem (mechanical, in-tick, quiescent) compares each host's current
//     evidence with the evidence its outstanding score was requested for, and
//     emits a BeliefScoreRequested only when the two differ.
//   - BeliefWorker (off-tick, live tap) calls the BeliefProvider and Submits the
//     posteriors back as a BeliefScored event.
//
// The provider is therefore consulted once per evidence change per host, never
// per tick, and inference never runs under the tick's write lock. A result whose
// evidence moved on while the model was scoring is stale, and the reducer drops
// it (the digest on the event no longer matches the host's outstanding request).

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

// BeliefEvidence is the deterministic, order-stable evidence one host presents to
// the belief model. It is derived purely from the Host component, so the same Host
// always yields the same evidence — and therefore the same posteriors, which exact
// inference and 1:1 replay both require.
type BeliefEvidence struct {
	OpenPorts []int    `json:"open_ports"`
	Services  []string `json:"services"`  // "<port>/<name>", sorted
	Reachable bool     `json:"reachable"` // any open port observed
}

// evidenceOf derives the belief evidence from a Host. Only open ports count;
// ports and services are sorted, so identical Hosts yield identical evidence.
func evidenceOf(h Host) BeliefEvidence {
	var ports []int
	var svcs []string
	for _, port := range h.Ports {
		if !port.Open {
			continue
		}
		ports = append(ports, port.Number)
		if port.Service.Name != "" {
			svcs = append(svcs, fmt.Sprintf("%d/%s", port.Number, port.Service.Name))
		}
	}
	sort.Ints(ports)
	sort.Strings(svcs)
	return BeliefEvidence{
		OpenPorts: ports,
		Services:  svcs,
		Reachable: len(ports) > 0,
	}
}

// evidenceDigest is the fingerprint of a BeliefEvidence: the SHA-256 of its
// canonical JSON encoding. The World records the digest and the Timeline carries
// it, so it must be stable across processes and across a replay of the same
// Timeline. BeliefEvidence holds only ordered, JSON-native fields, so it is.
func evidenceDigest(ev BeliefEvidence) string {
	b, err := json.Marshal(ev)
	if err != nil {
		// Unreachable: BeliefEvidence holds only JSON-native types. An empty
		// digest never matches a recorded one, so the host is simply re-requested.
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// BeliefProvider scores attack-path beliefs from a host's evidence.
//
// The real implementation is a **pgmpy sidecar** (ADR-0005): a probabilistic
// graphical model doing exact, read-only, deterministic inference, trained
// offline and versioned. This interface is the seam; placeholderBelief is a
// deterministic Go stand-in so attention (#751) and the Decider can consume
// belief now — it is replaced by the pgmpy-backed provider in a later slice.
//
// Score runs off the tick, in the BeliefWorker, so it may block on network I/O.
type BeliefProvider interface {
	Score(ev BeliefEvidence) Belief
	// Version is the model artifact the provider currently scores against, so a
	// mission can pin it at launch (ADR-0005 §5) and replay reproduces. The
	// pgmpy provider returns its pinned/served version; the placeholder returns
	// its static stand-in id.
	Version() string
}

// BeliefScoreRequested records that a host's belief-relevant evidence changed and
// that a score for exactly this evidence was asked for. It carries the evidence,
// so the Timeline states what was scored and the off-tick worker needs no
// read-back of the World.
type BeliefScoreRequested struct {
	HostID   uint64
	Evidence BeliefEvidence
}

func (BeliefScoreRequested) Kind() string { return "belief.requested" }

func applyBeliefScoreRequested(w *World, e BeliefScoreRequested) {
	if ent, ok := findHostByID(w, e.HostID); ok {
		w.hosts.Get(ent).EvidenceDigest = evidenceDigest(e.Evidence)
	}
}

// BeliefScored records a (re)computed belief for a host (by stable id — a
// coordinate is not unique after an identity contradiction). Belief is derived +
// deterministic, but flows through an event so it is logged and replay-reproducible.
// EvidenceDigest is the fingerprint of the evidence that produced it.
type BeliefScored struct {
	HostID         uint64
	Belief         Belief
	EvidenceDigest string
}

func (BeliefScored) Kind() string { return "belief.scored" }

func applyBeliefScored(w *World, e BeliefScored) {
	ent, ok := findHostByID(w, e.HostID)
	if !ok {
		return
	}
	h := w.hosts.Get(ent)
	if h.EvidenceDigest != e.EvidenceDigest {
		// Stale: the evidence changed again while the model was scoring, so a
		// newer request is outstanding. Drop this result; the newer one lands.
		return
	}
	h.Belief = e.Belief
}

// BeliefSystem is the engine System that keeps the belief field current. It is
// mechanical and quiescent: it emits a BeliefScoreRequested for a host only when
// the host's evidence differs from the evidence its outstanding score was
// requested for. It never calls the provider, so a tick never blocks on inference.
func BeliefSystem(w *World) []Event {
	var out []Event
	q := ecs.NewFilter1[Host](w.ecs).Query()
	for q.Next() {
		h := q.Get()
		ev := evidenceOf(*h)
		if evidenceDigest(ev) == h.EvidenceDigest {
			continue
		}
		out = append(out, BeliefScoreRequested{HostID: h.ID, Evidence: ev})
	}
	return out
}

// beliefScoreConcurrency bounds how many inferences one Drain runs at once. A
// single scan can discover many hosts in one tick; scoring them strictly in turn
// would queue every sidecar round-trip behind the one before it, while an
// unbounded fan-out would flood the sidecar.
const beliefScoreConcurrency = 8

// BeliefWorker drives the off-tick inference. Tap buffers BeliefScoreRequested
// (live only — Replay re-folds the recorded BeliefScored instead of re-scoring);
// Drain calls the provider and Submits the posteriors.
type BeliefWorker struct {
	eng      *Engine
	provider BeliefProvider

	mu      sync.Mutex
	pending []BeliefScoreRequested
}

// NewBeliefWorker builds a worker that scores eng's hosts with p.
func NewBeliefWorker(eng *Engine, p BeliefProvider) *BeliefWorker {
	return &BeliefWorker{eng: eng, provider: p}
}

// Tap is the engine subscriber (in-tick, no I/O): buffer the request.
func (bw *BeliefWorker) Tap(ev Event) {
	r, ok := ev.(BeliefScoreRequested)
	if !ok {
		return
	}
	bw.mu.Lock()
	bw.pending = append(bw.pending, r)
	bw.mu.Unlock()
}

// Drain scores every buffered request off the tick and Submits the results.
// Returns the number scored.
func (bw *BeliefWorker) Drain() int {
	bw.mu.Lock()
	reqs := bw.pending
	bw.pending = nil
	bw.mu.Unlock()

	sem := make(chan struct{}, beliefScoreConcurrency)
	var wg sync.WaitGroup
	for _, r := range reqs {
		wg.Add(1)
		sem <- struct{}{}
		go func(r BeliefScoreRequested) {
			defer wg.Done()
			defer func() { <-sem }()
			bw.eng.Submit(BeliefScored{
				HostID:         r.HostID,
				Belief:         bw.provider.Score(r.Evidence),
				EvidenceDigest: evidenceDigest(r.Evidence),
			})
		}(r)
	}
	wg.Wait()
	return len(reqs)
}

// WireBelief subscribes the belief worker's tap to eng and starts a single drain
// goroutine (bound to ctx) that runs inference off the tick. interval <= 0 uses
// TickInterval. This is for belief what WireExecutor is for dispatch and decisions.
func WireBelief(ctx context.Context, eng *Engine, p BeliefProvider, interval time.Duration) {
	if interval <= 0 {
		interval = TickInterval
	}
	bw := NewBeliefWorker(eng, p)
	eng.Subscribe(bw.Tap)

	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				bw.Drain()
				return
			case <-t.C:
				bw.Drain()
			}
		}
	}()
}

// placeholderBelief is a deterministic stand-in for the pgmpy provider (ADR-0005).
// A reachable host with more open ports scores higher exploitability/juiciness.
// NOT the real model — swapped for the pgmpy sidecar.
type placeholderBelief struct{}

func (placeholderBelief) Score(ev BeliefEvidence) Belief {
	open := len(ev.OpenPorts)
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

// Version is the placeholder's static stand-in id.
func (placeholderBelief) Version() string { return "placeholder-v0" }

// PlaceholderBeliefProvider returns the deterministic stand-in provider.
func PlaceholderBeliefProvider() BeliefProvider { return placeholderBelief{} }
