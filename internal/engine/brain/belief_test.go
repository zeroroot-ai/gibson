// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"reflect"
	"sync"
	"testing"
	"time"
)

// countingBelief is a BeliefProvider that counts how often the model was
// consulted and records the evidence of each call. delay makes it a slow sidecar;
// release, when set, blocks Score until the channel is closed.
type countingBelief struct {
	mu      sync.Mutex
	calls   int
	seen    []BeliefEvidence
	delay   time.Duration
	release chan struct{}
}

func (c *countingBelief) Score(ev BeliefEvidence) Belief {
	c.mu.Lock()
	c.calls++
	c.seen = append(c.seen, ev)
	delay, release := c.delay, c.release
	c.mu.Unlock()

	if release != nil {
		<-release
	}
	if delay > 0 {
		time.Sleep(delay)
	}
	open := float64(len(ev.OpenPorts))
	return Belief{Juicy: open, Exploitable: open, Reachable: 1, Model: "counting-v0"}
}

func (c *countingBelief) Version() string { return "counting-v0" }

func (c *countingBelief) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

// beliefEngine builds an engine with the belief gate installed as a System and
// the belief worker subscribed as a live tap — the wiring WireBelief performs,
// with the drain driven by the test instead of a ticker.
func beliefEngine(p BeliefProvider) (*Engine, *BeliefWorker) {
	e := NewEngine("t")
	e.AddSystem(BeliefSystem)
	bw := NewBeliefWorker(e, p)
	e.Subscribe(bw.Tap)
	return e, bw
}

// settle runs rounds of tick → drain → tick. The first tick asks for the scores,
// the drain runs the inference off the tick, the second tick folds the results.
func settle(e *Engine, bw *BeliefWorker, rounds int) {
	for i := 0; i < rounds; i++ {
		e.Tick()
		bw.Drain()
		e.Tick()
	}
}

// hostDigest returns the evidence digest the World holds for a host, i.e. the
// evidence its outstanding score was requested for.
func hostDigest(w *World, id uint64) string {
	ent, ok := findHostByID(w, id)
	if !ok {
		return ""
	}
	return w.hosts.Get(ent).EvidenceDigest
}

// TestBeliefSystem_ConsultsProviderOnEvidenceChange proves the documented
// invariant (ADR-0005, gibson#25): the provider is consulted once per host per
// evidence change, never once per tick.
func TestBeliefSystem_ConsultsProviderOnEvidenceChange(t *testing.T) {
	host := func(addr string, ports ...int) HostObserved {
		return HostObserved{ScopeID: "s", Address: addr, OpenPorts: ports}
	}

	tests := []struct {
		name      string
		first     []HostObserved
		then      []HostObserved
		rounds    int
		wantCalls int
	}{
		{
			name:      "unchanged evidence scores a host once, not once per tick",
			first:     []HostObserved{host("10.0.0.5", 22)},
			rounds:    5,
			wantCalls: 1,
		},
		{
			name:      "each host is scored once, not once per host per tick",
			first:     []HostObserved{host("10.0.0.5", 22), host("10.0.0.6", 80, 443)},
			rounds:    5,
			wantCalls: 2,
		},
		{
			name:      "an evidence change scores exactly once more",
			first:     []HostObserved{host("10.0.0.5", 22)},
			then:      []HostObserved{host("10.0.0.5", 22, 80)},
			rounds:    4,
			wantCalls: 2,
		},
		{
			name:      "a repeated observation carrying the same evidence does not re-score",
			first:     []HostObserved{host("10.0.0.5", 22)},
			then:      []HostObserved{host("10.0.0.5", 22)},
			rounds:    4,
			wantCalls: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &countingBelief{}
			e, bw := beliefEngine(p)

			for _, ev := range tc.first {
				e.Submit(ev)
			}
			settle(e, bw, tc.rounds)
			for _, ev := range tc.then {
				e.Submit(ev)
			}
			settle(e, bw, tc.rounds)

			if got := p.count(); got != tc.wantCalls {
				t.Fatalf("provider consulted %d times over %d rounds, want %d", got, 2*tc.rounds, tc.wantCalls)
			}
			// Every host carries a score, so the gate did not simply stop working.
			for _, h := range e.World.Snapshot() {
				if h.Belief.Model != "counting-v0" {
					t.Fatalf("host %s was never scored: %+v", h.Address, h.Belief)
				}
			}
			// Replay reproduces the field (BeliefScored is logged).
			if r := Replay("t", e.Timeline); !reflect.DeepEqual(r.Snapshot(), e.World.Snapshot()) {
				t.Fatalf("replay diverged:\n got %+v\nwant %+v", r.Snapshot(), e.World.Snapshot())
			}
		})
	}
}

// TestBeliefScored_StaleResultIsDropped proves the reducer keeps only a score
// whose evidence digest still matches the host's outstanding request.
func TestBeliefScored_StaleResultIsDropped(t *testing.T) {
	tests := []struct {
		name      string
		stale     bool
		wantJuicy float64
	}{
		{name: "a result for the current evidence is applied", stale: false, wantJuicy: 42},
		{name: "a result for superseded evidence is dropped", stale: true, wantJuicy: 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &countingBelief{}
			e, bw := beliefEngine(p)
			e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.5", OpenPorts: []int{22}})
			settle(e, bw, 1)

			hosts := e.World.Snapshot()
			if len(hosts) != 1 || hosts[0].Belief.Juicy != 1 {
				t.Fatalf("setup: host not scored: %+v", hosts)
			}

			digest := hostDigest(e.World, hosts[0].ID)
			if tc.stale {
				digest = "digest-of-evidence-the-host-has-moved-past"
			}
			e.Submit(BeliefScored{
				HostID:         hosts[0].ID,
				Belief:         Belief{Juicy: 42, Model: "counting-v0"},
				EvidenceDigest: digest,
			})
			e.Tick()

			if got := e.World.Snapshot()[0].Belief.Juicy; got != tc.wantJuicy {
				t.Fatalf("juicy = %v, want %v", got, tc.wantJuicy)
			}
		})
	}
}

// TestBeliefWorker_SupersededResultIsDropped drives the real race the digest
// guards: the evidence changes while the model is scoring, so the in-flight
// result is stale by the time it lands and the newer score replaces it.
func TestBeliefWorker_SupersededResultIsDropped(t *testing.T) {
	release := make(chan struct{})
	p := &countingBelief{release: release}
	e, bw := beliefEngine(p)

	// One open port: ask for a score, then hold the model inside Score.
	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.5", OpenPorts: []int{22}})
	e.Tick()
	done := make(chan struct{})
	go func() { defer close(done); bw.Drain() }()
	waitFor(t, func() bool { return p.count() == 1 })

	// A second port lands while the first score is still in flight. The gate
	// records the new evidence, so the in-flight result is now stale.
	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.5", OpenPorts: []int{22, 80}})
	e.Tick()

	close(release)
	<-done
	e.Tick() // folds the stale result

	if got := e.World.Snapshot()[0].Belief; got != (Belief{}) {
		t.Fatalf("stale score was applied: %+v", got)
	}

	// The score for the current evidence lands next and is kept.
	settle(e, bw, 1)
	if got := e.World.Snapshot()[0].Belief.Juicy; got != 2 {
		t.Fatalf("current score not applied: juicy = %v, want 2 (two open ports)", got)
	}
	if got := p.count(); got != 2 {
		t.Fatalf("provider consulted %d times, want 2 (one per evidence change)", got)
	}
}

// TestBeliefWorker_SlowProviderDoesNotStallTick proves inference runs off the
// tick: a provider that sleeps far longer than TickInterval never holds the
// engine's write lock, so ticks keep completing while it thinks.
func TestBeliefWorker_SlowProviderDoesNotStallTick(t *testing.T) {
	const (
		scoreDelay = 10 * TickInterval // 500ms — far longer than one tick
		ticks      = 20
	)
	p := &countingBelief{delay: scoreDelay}
	e, bw := beliefEngine(p)

	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.5", OpenPorts: []int{22}})
	e.Tick() // asks for the score; the tap buffers it

	done := make(chan struct{})
	go func() { defer close(done); bw.Drain() }()
	waitFor(t, func() bool { return p.count() == 1 }) // the model is now sleeping

	start := time.Now()
	for i := 0; i < ticks; i++ {
		e.Tick()
	}
	elapsed := time.Since(start)
	if elapsed >= scoreDelay {
		t.Fatalf("%d ticks took %v while one score slept %v — the tick loop waited on inference", ticks, elapsed, scoreDelay)
	}

	<-done
	e.Tick()
	if got := e.World.Snapshot()[0].Belief.Model; got != "counting-v0" {
		t.Fatalf("score never landed after the slow provider returned: %q", got)
	}
}

// TestBelief_TracksEvidence: as evidence changes (a new open port), belief is
// recomputed (higher exploitability).
func TestBelief_TracksEvidence(t *testing.T) {
	e, bw := beliefEngine(PlaceholderBeliefProvider())

	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.5", OpenPorts: []int{22}})
	settle(e, bw, 1)
	first := e.World.Snapshot()[0].Belief.Exploitable // 1/2 = 0.5

	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.5", OpenPorts: []int{22, 80}})
	settle(e, bw, 1)
	second := e.World.Snapshot()[0].Belief.Exploitable // 2/3 ≈ 0.667

	if !(second > first) {
		t.Fatalf("exploitability did not rise with evidence: %v -> %v", first, second)
	}
}

// TestBelief_ScoredQuiescentReplay proves the belief field is computed by a
// BeliefProvider off the tick, recorded on the host, quiescent once current, and
// reproduced by replay.
func TestBelief_ScoredQuiescentReplay(t *testing.T) {
	e, bw := beliefEngine(PlaceholderBeliefProvider())

	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.5", OpenPorts: []int{22, 80, 443}})
	settle(e, bw, 1)

	snap := e.World.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("got %d hosts, want 1", len(snap))
	}
	// placeholder: 3 open ports -> exploitable 3/4, reachable 1, juicy 0.75
	want := Belief{Juicy: 0.75, Exploitable: 0.75, Reachable: 1.0, Model: "placeholder-v0"}
	if snap[0].Belief != want {
		t.Fatalf("belief = %+v, want %+v", snap[0].Belief, want)
	}

	// Quiescent: the gate asks for nothing and the worker scores nothing.
	if n := e.Tick(); n != 0 {
		t.Fatalf("extra tick applied %d events, want 0 (belief not quiescent)", n)
	}
	if n := bw.Drain(); n != 0 {
		t.Fatalf("drain scored %d hosts, want 0 (nothing was requested)", n)
	}

	// Replay reproduces belief (BeliefScored was logged).
	if r := Replay("t", e.Timeline); !reflect.DeepEqual(r.Snapshot(), e.World.Snapshot()) {
		t.Fatalf("replay diverged:\n got %+v\nwant %+v", r.Snapshot(), e.World.Snapshot())
	}
}
