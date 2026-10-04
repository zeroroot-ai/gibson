// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"context"
	"reflect"
	"sync"
	"testing"
)

// fakeBeliefSubstrate is a minimal, in-memory BeliefSubstrate used only to
// prove the interface is satisfiable and that its documented semantics hold
// (round-trip, kind independence, exact overwrite). It is deliberately
// test-only (see belief_substrate.go): a production BeliefSubstrate belongs to
// whichever lane builds a real view (market, reputation) against it, so it is
// reachable from a cmd/ entry point and does not trip the whole-program
// dead-code gate for code nothing yet calls.
type fakeBeliefSubstrate struct {
	mu      sync.Mutex
	beliefs map[NodeRef]NodeBelief
}

func newFakeBeliefSubstrate() *fakeBeliefSubstrate {
	return &fakeBeliefSubstrate{beliefs: make(map[NodeRef]NodeBelief)}
}

func (s *fakeBeliefSubstrate) Belief(_ context.Context, ref NodeRef) (NodeBelief, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	nb, ok := s.beliefs[ref]
	return nb, ok, nil
}

func (s *fakeBeliefSubstrate) SetBelief(_ context.Context, ref NodeRef, nb NodeBelief) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.beliefs[ref] = nb
	return nil
}

var _ BeliefSubstrate = (*fakeBeliefSubstrate)(nil)

// TestBeliefSubstrate_UnknownRefIsNotFound proves a node nobody has scored yet
// reports "not found" rather than a zero-value belief that could be mistaken
// for a real (if uninformative) score.
func TestBeliefSubstrate_UnknownRefIsNotFound(t *testing.T) {
	s := newFakeBeliefSubstrate()

	got, ok, err := s.Belief(context.Background(), NodeRef{Kind: NodeKindClaim, ID: "claim-1"})
	if err != nil {
		t.Fatalf("Belief: %v", err)
	}
	if ok {
		t.Fatalf("Belief reported ok=true for an unscored node: %+v", got)
	}
	if !reflect.DeepEqual(got, NodeBelief{}) {
		t.Fatalf("Belief returned a non-zero value for an unscored node: %+v", got)
	}
}

// TestBeliefSubstrate_RoundTrip proves SetBelief/Belief round-trip exactly for
// a claim-node and for a technique×environment node — the two faces
// ADR-0029 §3 names (the market and reputation) as views over this substrate.
// The substrate itself stays generic: it does not know what a "claim" or a
// "technique×environment" node is beyond the NodeKind tag.
func TestBeliefSubstrate_RoundTrip(t *testing.T) {
	tests := []struct {
		name string
		ref  NodeRef
		nb   NodeBelief
	}{
		{
			name: "a claim-node (the market view, ADR-0029 §3)",
			ref:  NodeRef{Kind: NodeKindClaim, ID: "claim-42"},
			nb: NodeBelief{
				Belief:         Belief{Juicy: 0.9, Exploitable: 0.8, Reachable: 1, Model: "prm-v1"},
				EvidenceDigest: "digest-a",
			},
		},
		{
			name: "a technique×environment node (the reputation view, ADR-0029 §3)",
			ref:  NodeRef{Kind: NodeKindTechniqueEnvironment, ID: "t-ssh-brute:env-prod"},
			nb: NodeBelief{
				Belief:         Belief{Juicy: 0.3, Exploitable: 0.3, Reachable: 1, Model: "prm-v1"},
				EvidenceDigest: "digest-b",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newFakeBeliefSubstrate()
			ctx := context.Background()

			if err := s.SetBelief(ctx, tc.ref, tc.nb); err != nil {
				t.Fatalf("SetBelief: %v", err)
			}
			got, ok, err := s.Belief(ctx, tc.ref)
			if err != nil {
				t.Fatalf("Belief: %v", err)
			}
			if !ok {
				t.Fatalf("Belief reported ok=false right after SetBelief")
			}
			if !reflect.DeepEqual(got, tc.nb) {
				t.Fatalf("Belief = %+v, want %+v", got, tc.nb)
			}
		})
	}
}

// TestBeliefSubstrate_KindsAreIndependent proves a substrate keys on
// (Kind, ID) together: a claim and a host sharing the literal id string "1"
// must not collide, because the ontology (ADR-0029 §2) is what tells two
// otherwise-identical ids apart.
func TestBeliefSubstrate_KindsAreIndependent(t *testing.T) {
	s := newFakeBeliefSubstrate()
	ctx := context.Background()

	claim := NodeRef{Kind: NodeKindClaim, ID: "1"}
	host := NodeRef{Kind: NodeKindHost, ID: "1"}

	claimBelief := NodeBelief{Belief: Belief{Juicy: 0.9}, EvidenceDigest: "claim-digest"}
	if err := s.SetBelief(ctx, claim, claimBelief); err != nil {
		t.Fatalf("SetBelief(claim): %v", err)
	}

	if _, ok, err := s.Belief(ctx, host); err != nil {
		t.Fatalf("Belief(host): %v", err)
	} else if ok {
		t.Fatalf("host with the same literal id as a claim reported a belief; kinds are not independent")
	}

	got, ok, err := s.Belief(ctx, claim)
	if err != nil || !ok {
		t.Fatalf("Belief(claim): got=%+v ok=%v err=%v", got, ok, err)
	}
	if !reflect.DeepEqual(got, claimBelief) {
		t.Fatalf("Belief(claim) = %+v, want %+v", got, claimBelief)
	}
}

// TestBeliefSubstrate_OverwriteReplacesExactly proves a later SetBelief for
// the same ref fully replaces the earlier one — belief stays exact and
// deterministic (ADR-0005 §2, still true under ADR-0029), never accumulated or
// averaged.
func TestBeliefSubstrate_OverwriteReplacesExactly(t *testing.T) {
	s := newFakeBeliefSubstrate()
	ctx := context.Background()
	ref := NodeRef{Kind: NodeKindClaim, ID: "claim-1"}

	first := NodeBelief{Belief: Belief{Juicy: 0.2}, EvidenceDigest: "d1"}
	second := NodeBelief{Belief: Belief{Juicy: 0.8}, EvidenceDigest: "d2"}

	if err := s.SetBelief(ctx, ref, first); err != nil {
		t.Fatalf("SetBelief(first): %v", err)
	}
	if err := s.SetBelief(ctx, ref, second); err != nil {
		t.Fatalf("SetBelief(second): %v", err)
	}

	got, ok, err := s.Belief(ctx, ref)
	if err != nil || !ok {
		t.Fatalf("Belief: got=%+v ok=%v err=%v", got, ok, err)
	}
	if !reflect.DeepEqual(got, second) {
		t.Fatalf("Belief = %+v, want the later write %+v (not a blend of both)", got, second)
	}
}
