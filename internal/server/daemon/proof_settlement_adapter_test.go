// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/finding"
	"github.com/zeroroot-ai/gibson/internal/engine/settlement"
	"github.com/zeroroot-ai/sdk/auth"
)

// awaitAdapterDestructivePending polls e's DestructiveActionSnapshot until
// hypothesisID's request has folded (the async Submit->tick fold, ADR-0001),
// or fails the test.
func awaitAdapterDestructivePending(t *testing.T, e *brain.Engine, hypothesisID string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, a := range e.DestructiveActionSnapshot() {
			if a.HypothesisID == hypothesisID {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("destructive action %q was not recorded within the deadline", hypothesisID)
}

// destructiveMarkerRegistry returns a settlement.Registry with one
// deterministic predicate: true iff any evidence's Content equals the
// configured marker string. Mirrors brain's own test helper of the same
// shape (bet_settlement_test.go), reimplemented here since it is unexported
// across packages.
func destructiveMarkerRegistry(t *testing.T) *settlement.Registry {
	t.Helper()
	r := settlement.NewRegistry()
	err := r.Register("T1490", "marker_present", func(params json.RawMessage, evidence []finding.EnhancedEvidence) (bool, error) {
		var p struct {
			Marker string `json:"marker"`
		}
		if uerr := json.Unmarshal(params, &p); uerr != nil {
			return false, fmt.Errorf("unmarshal params: %w", uerr)
		}
		for _, e := range evidence {
			if s, ok := e.Content.(string); ok && s == p.Marker {
				return true, nil
			}
		}
		return false, nil
	})
	if err != nil {
		t.Fatalf("register predicate: %v", err)
	}
	return r
}

// TestTenantRoutedProofSettlement_RequestDestructiveAuthorization_NoTenant_PermissionDenied
// proves the adapter fails closed (never a silent default tenant) when ctx
// carries none, the same guard DomainPackPredicate/SettleBetTrue's own
// forTenant already enforces.
func TestTenantRoutedProofSettlement_RequestDestructiveAuthorization_NoTenant_PermissionDenied(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	registry := brain.NewRegistry(ctx)
	s := newTenantRoutedProofSettlement(registry)

	_, err := s.RequestDestructiveAuthorization(context.Background(), brain.DestructiveAuthorizationRequest{HypothesisID: "hyp-1"})
	if err == nil {
		t.Fatal("want an error when ctx carries no tenant")
	}
}

// TestTenantRoutedProofSettlement_RequestDestructiveAuthorization_EnqueuesOnTenantEngine
// proves the adapter resolves ctx's tenant and enqueues onto THAT tenant's
// own DestructiveAuthorizationQueue (ADR-0032 decision 1) — the same
// per-tenant routing DomainPackPredicate/SettleBetTrue already prove
// (belief_substrate_adapter_test.go's sibling pattern).
func TestTenantRoutedProofSettlement_RequestDestructiveAuthorization_EnqueuesOnTenantEngine(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	registry := brain.NewRegistry(ctx)
	s := newTenantRoutedProofSettlement(registry)

	acmeCtx := auth.ContextWithTenantString(context.Background(), "acme")
	id, err := s.RequestDestructiveAuthorization(acmeCtx, brain.DestructiveAuthorizationRequest{
		HypothesisID: "hyp-1", Technique: "T1490", PredicateType: "T1490",
	})
	if err != nil {
		t.Fatalf("RequestDestructiveAuthorization: %v", err)
	}
	if id != "hyp-1" {
		t.Fatalf("want authorization_request_id %q, got %q", "hyp-1", id)
	}

	acmeEngine := registry.For("acme")
	awaitAdapterDestructivePending(t, acmeEngine, "hyp-1")

	globexEngine := registry.For("globex")
	if got := globexEngine.DestructiveActionSnapshot(); len(got) != 0 {
		t.Fatalf("a different tenant must never see acme's destructive request, got %+v", got)
	}
}

// TestTenantRoutedProofSettlement_SettleBetTrue_WiresRealVerifierForDestructive
// proves the ADR-0032 decision 3/4 wiring this adapter exists for: when the
// caller (the SubmitProof handler) leaves authorize nil on a destructive
// request, SettleBetTrue's authorizer becomes that tenant's own
// DestructiveAuthorizationQueue.Verify — refusing settlement with no
// recorded approval, and settling once one is approved.
func TestTenantRoutedProofSettlement_SettleBetTrue_WiresRealVerifierForDestructive(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	registry := brain.NewRegistry(ctx)
	s := newTenantRoutedProofSettlement(registry)
	acmeCtx := auth.ContextWithTenantString(context.Background(), "acme")
	reg := destructiveMarkerRegistry(t)

	req := brain.BetSettlementRequest{
		HypothesisID:    "hyp-1",
		Technique:       "T1490",
		PredicateType:   "marker_present",
		PredicateParams: map[string]any{"marker": "tok"},
		Evidence:        []finding.EnhancedEvidence{finding.NewEnhancedEvidence(finding.EvidenceLog, "capture", "tok")},
		Destructive:     true,
	}

	// No authorization was ever requested: SettleBetTrue must refuse via the
	// adapter's own wired-in Verify, never settle.
	_, err := s.SettleBetTrue(acmeCtx, reg, nil, req)
	if err == nil {
		t.Fatal("want an error: no destructive authorization was ever requested")
	}
	if !errors.Is(err, brain.ErrDestructiveActionPending) {
		t.Fatalf("want ErrDestructiveActionPending, got %v", err)
	}

	// Request and approve, then confirm the SAME adapter settles it.
	if _, rErr := s.RequestDestructiveAuthorization(acmeCtx, brain.DestructiveAuthorizationRequest{HypothesisID: "hyp-1"}); rErr != nil {
		t.Fatalf("RequestDestructiveAuthorization: %v", rErr)
	}
	acmeEngine := registry.For("acme")
	awaitAdapterDestructivePending(t, acmeEngine, "hyp-1")
	if dErr := acmeEngine.DestructiveAuthorizationQueue().Decide("hyp-1", "reviewer-1", true); dErr != nil {
		t.Fatalf("Decide: %v", dErr)
	}

	deadline := time.Now().Add(2 * time.Second)
	var settled bool
	for time.Now().Before(deadline) {
		settled, err = s.SettleBetTrue(acmeCtx, reg, nil, req)
		if err == nil {
			break
		}
		if !errors.Is(err, brain.ErrDestructiveActionPending) {
			t.Fatalf("SettleBetTrue: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("SettleBetTrue never saw the approval land: %v", err)
	}
	if !settled {
		t.Fatal("want settled=true once the recorded decision is approved")
	}
}
