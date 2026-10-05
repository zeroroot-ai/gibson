// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	worldpb "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/world/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// awaitOpenBets polls ListOpenBets until it returns want bets, then returns
// them — mirroring awaitHypotheses's pattern for the async Submit -> World
// pipeline (brain_ingest_observe_test.go). ctx leads the parameter list per
// the codebase's context-as-argument convention.
func awaitOpenBets(ctx context.Context, t *testing.T, srv *worldServer, want int) []*worldpb.OpenBet {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var got []*worldpb.OpenBet
	for time.Now().Before(deadline) {
		resp, err := srv.ListOpenBets(ctx, &worldpb.ListOpenBetsRequest{})
		if err != nil {
			t.Fatalf("ListOpenBets: %v", err)
		}
		got = resp.GetBets()
		if len(got) == want {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("want %d open bets, got %d: %+v", want, len(got), got)
	return nil
}

// TestListOpenBets_TenantScoped proves ListOpenBets reads only the caller's
// own tenant's hypotheses and refuses a request with no tenant in context —
// the same tenant-isolation contract every other WorldService RPC holds.
func TestListOpenBets_TenantScoped(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	srv := NewWorldServer(reg, nil)

	reg.For("acme").Submit(brain.HypothesisObserved{
		ScopeID: "s1", Claim: "port 6443 is unauthenticated", Proposer: "recon-agent",
		Confidence: 0.7, HypothesisID: "hyp-6443", RunID: "run-1",
	})
	reg.For("other-tenant").Submit(brain.HypothesisObserved{
		ScopeID: "s1", Claim: "a different tenant's claim", HypothesisID: "hyp-other",
	})

	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	got := awaitOpenBets(tctx, t, srv, 1)
	if got[0].GetHypothesisId() != "hyp-6443" {
		t.Fatalf("expected acme's own bet, got %+v", got[0])
	}

	if _, err := srv.ListOpenBets(context.Background(), &worldpb.ListOpenBetsRequest{}); err == nil {
		t.Fatal("expected an error when no tenant is in context")
	}
}

// TestListOpenBets_ReturnsClaimProposerConfidenceEvidenceRunID proves the
// full field mapping the dashboard#97 review queue needs (gibson#339
// acceptance criteria).
func TestListOpenBets_ReturnsClaimProposerConfidenceEvidenceRunID(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	srv := NewWorldServer(reg, nil)

	reg.For("acme").Submit(brain.HypothesisObserved{
		ScopeID: "s1", Claim: "the admin panel is reachable without auth",
		Proposer: "recon-agent", Confidence: 0.8, HypothesisID: "hyp-admin",
		RunID: "run-9",
		References: []brain.ReferencedEntityRef{
			{Label: "Host", IDProperties: map[string]string{"address": "10.0.0.5"}},
		},
	})

	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	got := awaitOpenBets(tctx, t, srv, 1)
	b := got[0]
	if b.GetHypothesisId() != "hyp-admin" {
		t.Fatalf("hypothesis_id: %+v", b)
	}
	if b.GetClaim() != "the admin panel is reachable without auth" {
		t.Fatalf("claim: %+v", b)
	}
	if b.GetProposer() != "recon-agent" {
		t.Fatalf("proposer: %+v", b)
	}
	if b.GetConfidence() != 0.8 {
		t.Fatalf("confidence: %+v", b)
	}
	if b.GetRunId() != "run-9" {
		t.Fatalf("run_id: %+v", b)
	}
	if len(b.GetEvidence()) != 1 || b.GetEvidence()[0].GetLabel() != "Host" ||
		b.GetEvidence()[0].GetIdProperties()["address"] != "10.0.0.5" {
		t.Fatalf("evidence: %+v", b.GetEvidence())
	}
}

// TestListOpenBets_ExcludesSettled proves a Hypothesis whose HypothesisID
// already has a BetSettlement never appears — "open" means unsettled.
func TestListOpenBets_ExcludesSettled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	srv := NewWorldServer(reg, nil)

	reg.For("acme").Submit(brain.HypothesisObserved{
		ScopeID: "s1", Claim: "settled claim", HypothesisID: "hyp-settled",
	})
	reg.For("acme").Submit(brain.BetSettledTrue{HypothesisID: "hyp-settled"})
	reg.For("acme").Submit(brain.HypothesisObserved{
		ScopeID: "s1", Claim: "still open claim", HypothesisID: "hyp-open",
	})

	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	got := awaitOpenBets(tctx, t, srv, 1)
	if got[0].GetHypothesisId() != "hyp-open" {
		t.Fatalf("expected only the unsettled bet, got %+v", got)
	}
}

// TestListOpenBets_ExcludesHypothesesWithNoHypothesisID proves a Hypothesis
// that was never given a bettable id (an observation with no
// HypothesisObservation.hypothesis_id set) is not listed as an open bet: it
// was never entered into the betting system, so it is not a bet at all, open
// or otherwise.
func TestListOpenBets_ExcludesHypothesesWithNoHypothesisID(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	srv := NewWorldServer(reg, nil)

	reg.For("acme").Submit(brain.HypothesisObserved{
		ScopeID: "s1", Claim: "a claim proposed with no bettable id",
	})
	reg.For("acme").Submit(brain.HypothesisObserved{
		ScopeID: "s1", Claim: "a bettable claim", HypothesisID: "hyp-1",
	})

	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	got := awaitOpenBets(tctx, t, srv, 1)
	if got[0].GetHypothesisId() != "hyp-1" {
		t.Fatalf("expected only the id-bearing hypothesis, got %+v", got)
	}
}

// TestSettleBetByHITL_TruePositive_Settles proves a true_positive verdict
// settles the named bet through Engine.SettleBetByHITL (gibson#280).
func TestSettleBetByHITL_TruePositive_Settles(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	srv := NewWorldServer(reg, nil)

	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	tctx = auth.ContextWithActingUser(tctx, "reviewer-1")
	resp, err := srv.SettleBetByHITL(tctx, &worldpb.SettleBetByHITLRequest{
		HypothesisId: "hyp-1", Verdict: "true_positive",
	})
	if err != nil {
		t.Fatalf("SettleBetByHITL: %v", err)
	}
	if !resp.GetSettled() {
		t.Fatalf("expected settled=true, got %+v", resp)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s := reg.For("acme").BetSettlements(); len(s) == 1 && s[0].HypothesisID == "hyp-1" {
			if s[0].Verdict != brain.SettlementVerdictTrue {
				t.Fatalf("verdict = %v, want TRUE", s[0].Verdict)
			}
			if s[0].UserID != "reviewer-1" {
				t.Fatalf("user id = %q, want the server-resolved reviewer, not empty or client-supplied", s[0].UserID)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("bet was never settled")
}

// TestSettleBetByHITL_MissingActingUser_Errors proves a settlement attempt
// with no acting user resolvable from context is refused with
// codes.Unauthenticated (fail closed) and the bet stays unsettled — the
// reviewer is the accountability record for a HITL verdict (ADR-0106
// provenance, ADR-0132's class of consequential action), so an
// unattributable verdict must never flow through as a zero-value identity.
func TestSettleBetByHITL_MissingActingUser_Errors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	srv := NewWorldServer(reg, nil)

	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	_, err := srv.SettleBetByHITL(tctx, &worldpb.SettleBetByHITLRequest{
		HypothesisId: "hyp-1", Verdict: "true_positive",
	})
	if err == nil {
		t.Fatal("expected an error when no acting user is in context")
	}
	if got := status.Code(err); got != codes.Unauthenticated {
		t.Fatalf("code = %v, want Unauthenticated", got)
	}
	if settled := reg.For("acme").BetSettlements(); len(settled) != 0 {
		t.Fatalf("an unattributed verdict must never settle a bet, got %+v", settled)
	}
}

// TestSettleBetByHITL_Dismiss_LabelOnlyNoSettle proves dismiss applies the
// ordinary label (SubmitLabel's own channel) but never settles the bet —
// matching Engine.SettleBetByHITL's own refusal semantics for dismiss
// (bet_settlement.go: "a bet's binary settlement has no 'not actionable'
// outcome the way a surfaced surprise does").
func TestSettleBetByHITL_Dismiss_LabelOnlyNoSettle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	srv := NewWorldServer(reg, nil)

	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	tctx = auth.ContextWithActingUser(tctx, "reviewer-1")
	resp, err := srv.SettleBetByHITL(tctx, &worldpb.SettleBetByHITLRequest{
		HypothesisId: "hyp-1", Verdict: "dismiss",
	})
	if err != nil {
		t.Fatalf("SettleBetByHITL: %v", err)
	}
	if resp.GetSettled() {
		t.Fatalf("dismiss must never settle, got %+v", resp)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		labels := reg.For("acme").Labels()
		if len(labels) == 1 {
			if labels[0].TargetID != "bet-hyp-1" {
				t.Fatalf("label target id = %q, want the betLabelTargetID convention", labels[0].TargetID)
			}
			if labels[0].Verdict != brain.VerdictDismiss {
				t.Fatalf("label verdict = %v, want dismiss", labels[0].Verdict)
			}
			if labels[0].UserID != "reviewer-1" {
				t.Fatalf("label user id = %q, want the server-resolved reviewer", labels[0].UserID)
			}
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(reg.For("acme").Labels()) != 1 {
		t.Fatal("dismiss must apply exactly one label")
	}
	if settled := reg.For("acme").BetSettlements(); len(settled) != 0 {
		t.Fatalf("dismiss must never create a BetSettlement, got %+v", settled)
	}
}

// TestSettleBetByHITL_InvalidVerdict_Errors proves an unknown verdict is
// refused rather than silently accepted.
func TestSettleBetByHITL_InvalidVerdict_Errors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	srv := NewWorldServer(reg, nil)

	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	if _, err := srv.SettleBetByHITL(tctx, &worldpb.SettleBetByHITLRequest{
		HypothesisId: "hyp-1", Verdict: "maybe",
	}); err == nil {
		t.Fatal("expected an error for an unknown verdict")
	}
}

// TestSettleBetByHITL_MissingHypothesisID_Errors proves an empty
// hypothesis_id is refused rather than reaching the engine.
func TestSettleBetByHITL_MissingHypothesisID_Errors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	srv := NewWorldServer(reg, nil)

	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	if _, err := srv.SettleBetByHITL(tctx, &worldpb.SettleBetByHITLRequest{
		Verdict: "true_positive",
	}); err == nil {
		t.Fatal("expected an error for a missing hypothesis_id")
	}
}

// TestSettleBetByHITL_TenantScoped proves the RPC refuses a request with no
// tenant in context — the same isolation contract every other WorldService
// write holds.
func TestSettleBetByHITL_TenantScoped(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	srv := NewWorldServer(reg, nil)

	if _, err := srv.SettleBetByHITL(context.Background(), &worldpb.SettleBetByHITLRequest{
		HypothesisId: "hyp-1", Verdict: "true_positive",
	}); err == nil {
		t.Fatal("expected an error when no tenant is in context")
	}
}
