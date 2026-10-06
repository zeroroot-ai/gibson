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
	"strings"
	"sync"
	"time"

	"github.com/mlange-42/ark/ecs"
)

// belief.go is the belief field (ADR-0129) and the evidence-change gate that
// keeps it current.
//
// Inference is slow — the real provider is an HTTP call to the pgmpy sidecar —
// and the tick is ~50ms, so belief follows the same async-by-observation pattern
// as the Decider (ADR-0104/0109):
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

// Belief is the attack-path belief over a target (ADR-0129): the one field with
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
// the belief model. It is derived from the Host component plus the findings and
// demonstrated exploits that correlate to the same host (gibson#478), so the same
// World always yields the same evidence — and therefore the same posteriors, which
// exact inference and 1:1 replay both require.
//
// FindingCritical/FindingHigh/ExploitDemonstrated are discrete, order-stable and
// JSON-native, so evidenceDigest stays canonical. They default false, so a host
// with no finding evidence hashes and scores exactly as it did before gibson#478.
type BeliefEvidence struct {
	OpenPorts []int    `json:"open_ports"`
	Services  []string `json:"services"`  // "<port>/<name>", sorted
	Reachable bool     `json:"reachable"` // any open port observed

	// FindingCritical / FindingHigh report the highest severity of a confirmed,
	// still-active finding on this host (gibson#478). ExploitDemonstrated reports
	// that a bet settled TRUE against this host — a proof-of-demonstration
	// exploit (ADR-0131), the strongest evidence for exploitable.
	FindingCritical     bool `json:"finding_critical"`
	FindingHigh         bool `json:"finding_high"`
	ExploitDemonstrated bool `json:"exploit_demonstrated"`
}

// evidenceOf derives the belief evidence from a Host. Only open ports count;
// ports and services are sorted, so identical Hosts yield identical evidence.
func evidenceOf(h Host) BeliefEvidence {
	// Both slices are preallocated, so a host with no open ports yields `[]`
	// rather than `null`, keeping the JSON encoding (and therefore the evidence
	// digest) canonical: a nil and an empty slice must not hash differently.
	ports := make([]int, 0, len(h.Ports))
	svcs := make([]string, 0, len(h.Ports))
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
	// BeliefEvidence holds only ordered, JSON-native fields, so Marshal cannot
	// fail and its encoding is canonical.
	b, _ := json.Marshal(ev)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// BeliefProvider scores attack-path beliefs from a host's evidence.
//
// The real implementation is nativeBelief (belief_native.go, ADR-0129,
// ADR-0134): exact, read-only Bayesian inference computed in-process via
// internal/engine/brain/beliefvi — the native Go port that replaced the old
// Python pgmpy sidecar (ADR-0027 hard cutover, gibson#377). This interface
// is the seam attention (#751) and the Decider consume belief through.
//
// Score runs off the tick, in the BeliefWorker, so it may block on network I/O.
type BeliefProvider interface {
	Score(ev BeliefEvidence) Belief
	// Version is the model artifact the provider currently scores against, so a
	// mission can pin it at launch (ADR-0134) and replay reproduces. The
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

// Kind is the event's Timeline kind.
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
	// CauseEdgeTypes are the slice edge types that fed the host when this
	// belief was scored (gibson#613); empty for a single-host slice.
	CauseEdgeTypes []string
}

// Kind is the event's Timeline kind.
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
	h.CauseEdgeTypes = append([]string(nil), e.CauseEdgeTypes...)
}

// hostEvidenceKey is the scope-relative identity a finding or a demonstrated
// exploit is correlated to a host by (gibson#478): the (ScopeID, Address) pair a
// Finding carries and a Host is addressed by (ADR-0102, scope-relative identity).
func hostEvidenceKey(scopeID, address string) string {
	return scopeID + "\x00" + address
}

// findingSeverityByHost reports, per host key, whether a confirmed, still-active
// finding of critical or high severity sits on that host (gibson#478). A finding
// is active while its status is open or fixing: a fixed or verified finding is no
// longer evidence that the host is exploitable, so it drops out of the evidence
// (and the belief recomputes down, as a status change must).
func findingSeverityByHost(w *World) (critical, high map[string]bool) {
	critical = map[string]bool{}
	high = map[string]bool{}
	for _, f := range w.FindingSnapshot() {
		if f.Address == "" {
			continue // no host to correlate to
		}
		if f.Status == FindingStatusFixed || f.Status == FindingStatusVerified {
			continue
		}
		key := hostEvidenceKey(f.ScopeID, f.Address)
		switch strings.ToLower(f.Severity) {
		case "critical":
			critical[key] = true
		case "high":
			high[key] = true
		}
	}
	return critical, high
}

// demonstratedExploitByHost reports, per host key, whether a bet settled TRUE on
// that host — a demonstrated exploit, the strongest evidence for exploitable
// (ADR-0131 proof-of-demonstration, gibson#478). A BetSettlement is keyed by
// HypothesisID (bet_settlement.go), and a Hypothesis names the host its claim is
// about through its References (hypothesis.go). The join is therefore
// settlement -> (HypothesisID) hypothesis -> (a reference whose id-property value
// is a host's scope-relative address) host. Matching on the property VALUE, not a
// guessed key, keeps the join robust to the agent-supplied reference shape, and
// the ScopeID bound plus the host lookup in BeliefSystem mean only a real host at
// that address in that scope is ever marked.
func demonstratedExploitByHost(w *World) map[string]bool {
	hypByID := map[string]HypothesisSnapshot{}
	for _, h := range w.HypothesisSnapshot() {
		if h.HypothesisID != "" {
			hypByID[h.HypothesisID] = h
		}
	}
	out := map[string]bool{}
	for _, s := range w.BetSettlementSnapshot() {
		if s.Verdict != SettlementVerdictTrue {
			continue
		}
		hyp, ok := hypByID[s.HypothesisID]
		if !ok {
			continue
		}
		for _, ref := range hyp.References {
			for _, v := range ref.IDProperties {
				if v == "" {
					continue
				}
				out[hostEvidenceKey(hyp.ScopeID, v)] = true
			}
		}
	}
	return out
}

// BeliefSystem is the engine System that keeps the belief field current. It is
// mechanical and quiescent: it emits a BeliefScoreRequested for a host only when
// the host's evidence differs from the evidence its outstanding score was
// requested for. It never calls the provider, so a tick never blocks on inference.
//
// Evidence is the host's own ports/services (evidenceOf) plus the finding-derived
// evidence that correlates to the same host (gibson#478): a confirmed finding at a
// severity, and a demonstrated exploit. A finding landing on a host changes that
// host's evidence digest, so the belief recomputes; a finding on another host, or
// a re-raise carrying nothing new, leaves the digest unchanged and is suppressed.
func BeliefSystem(w *World) []Event {
	var out []Event
	forEachHostEvidence(w, func(h *Host, ev BeliefEvidence) {
		if evidenceDigest(ev) == h.EvidenceDigest {
			return
		}
		out = append(out, BeliefScoreRequested{HostID: h.ID, Evidence: ev})
	})
	return out
}

// forEachHostEvidence calls fn with each host and the belief evidence it
// presents: its own ports and services (evidenceOf) plus the finding-derived
// evidence that correlates to the same host (gibson#478). BeliefSystem and
// BeliefEvidenceByHost both read the evidence here, so inference and training
// see the same evidence for one host.
func forEachHostEvidence(w *World, fn func(h *Host, ev BeliefEvidence)) {
	critical, high := findingSeverityByHost(w)
	exploited := demonstratedExploitByHost(w)

	q := ecs.NewFilter1[Host](w.ecs).Query()
	for q.Next() {
		h := q.Get()
		ev := evidenceOf(*h)
		key := hostEvidenceKey(h.ScopeID, h.Address)
		ev.FindingCritical = critical[key]
		ev.FindingHigh = high[key]
		ev.ExploitDemonstrated = exploited[key]
		fn(h, ev)
	}
}

// BeliefEvidenceByHost returns the belief evidence of each host, keyed by the
// stable host id. The belief trainer derives its training rows from it
// (braintrain.RowsFromWorld, gibson#614), so a row holds exactly the evidence
// that inference scores.
func (w *World) BeliefEvidenceByHost() map[uint64]BeliefEvidence {
	out := make(map[uint64]BeliefEvidence)
	forEachHostEvidence(w, func(h *Host, ev BeliefEvidence) {
		out[h.ID] = ev
	})
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
