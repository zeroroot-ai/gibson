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
	destructiveauthzv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/destructiveauthz/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// awaitPending polls ListPendingDestructiveActions until it returns want
// entries, or fails the test — the request is folded onto the engine's
// Timeline asynchronously (ADR-0001), so a call made immediately after
// Authorize starts can race the fold.
func awaitPending(t *testing.T, ctx context.Context, srv destructiveauthzv1.DestructiveAuthorizationServiceServer, want int) *destructiveauthzv1.ListPendingDestructiveActionsResponse {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var resp *destructiveauthzv1.ListPendingDestructiveActionsResponse
	for time.Now().Before(deadline) {
		var err error
		resp, err = srv.ListPendingDestructiveActions(ctx, &destructiveauthzv1.ListPendingDestructiveActionsRequest{})
		if err != nil {
			t.Fatalf("ListPendingDestructiveActions: %v", err)
		}
		if len(resp.GetActions()) == want {
			return resp
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("want %d pending actions, got %d: %+v", want, len(resp.GetActions()), resp.GetActions())
	return nil
}

func TestListPendingDestructiveActions_TenantScoped(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	srv := NewDestructiveAuthorizationServer(reg, nil)

	e := reg.For("acme")
	q := e.DestructiveAuthorizationQueue()
	go func() {
		_, _ = q.Authorize(context.Background(), "acme", brain.BetSettlementRequest{HypothesisID: "hyp-1"})
	}()

	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	resp := awaitPending(t, tctx, srv, 1)
	if resp.Actions[0].ActionId != "hyp-1" || resp.Actions[0].HypothesisId != "hyp-1" {
		t.Fatalf("unexpected pending action: %+v", resp.Actions[0])
	}

	// No tenant in context -> PermissionDenied.
	if _, err := srv.ListPendingDestructiveActions(context.Background(), &destructiveauthzv1.ListPendingDestructiveActionsRequest{}); err == nil {
		t.Fatal("expected an error when no tenant is in context")
	}

	// Cleanup so the goroutine does not leak past the test.
	_ = q.Decide("hyp-1", "reviewer-1", false)
}

func TestListPendingDestructiveActions_OtherTenantIsInvisible(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	srv := NewDestructiveAuthorizationServer(reg, nil)

	e := reg.For("acme")
	q := e.DestructiveAuthorizationQueue()
	go func() {
		_, _ = q.Authorize(context.Background(), "acme", brain.BetSettlementRequest{HypothesisID: "hyp-1"})
	}()
	acmeCtx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	awaitPending(t, acmeCtx, srv, 1)

	otherCtx := auth.WithTenant(context.Background(), auth.MustNewTenantID("umbrella"))
	resp, err := srv.ListPendingDestructiveActions(otherCtx, &destructiveauthzv1.ListPendingDestructiveActionsRequest{})
	if err != nil {
		t.Fatalf("ListPendingDestructiveActions: %v", err)
	}
	if len(resp.GetActions()) != 0 {
		t.Fatalf("a different tenant must never see acme's pending actions, got %+v", resp.GetActions())
	}

	_ = q.Decide("hyp-1", "reviewer-1", false)
}

func TestApproveDestructiveAction_UnblocksTheWaitingSettlement(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	srv := NewDestructiveAuthorizationServer(reg, nil)

	e := reg.For("acme")
	q := e.DestructiveAuthorizationQueue()
	resultCh := make(chan bool, 1)
	go func() {
		approved, _ := q.Authorize(context.Background(), "acme", brain.BetSettlementRequest{HypothesisID: "hyp-1"})
		resultCh <- approved
	}()

	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	tctx = auth.ContextWithActingUser(tctx, "reviewer-1")
	awaitPending(t, tctx, srv, 1)

	if _, err := srv.ApproveDestructiveAction(tctx, &destructiveauthzv1.ApproveDestructiveActionRequest{ActionId: "hyp-1"}); err != nil {
		t.Fatalf("ApproveDestructiveAction: %v", err)
	}

	select {
	case approved := <-resultCh:
		if !approved {
			t.Fatal("want the waiting Authorize call to see approved=true")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Authorize did not unblock after ApproveDestructiveAction")
	}

	awaitPending(t, tctx, srv, 0)
}

func TestApproveDestructiveAction_RequiresActionID(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	srv := NewDestructiveAuthorizationServer(reg, nil)

	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	if _, err := srv.ApproveDestructiveAction(tctx, &destructiveauthzv1.ApproveDestructiveActionRequest{}); err == nil {
		t.Fatal("want an error when action_id is empty")
	}
}

func TestApproveDestructiveAction_UnknownActionErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	srv := NewDestructiveAuthorizationServer(reg, nil)

	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	tctx = auth.ContextWithActingUser(tctx, "reviewer-1")
	_, err := srv.ApproveDestructiveAction(tctx, &destructiveauthzv1.ApproveDestructiveActionRequest{ActionId: "hyp-nonexistent"})
	if err == nil {
		t.Fatal("want an error approving an unknown action")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("want codes.FailedPrecondition for an unknown action, got %v", status.Code(err))
	}
}

func TestDenyDestructiveAction_UnblocksTheWaitingSettlementAsDenied(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	srv := NewDestructiveAuthorizationServer(reg, nil)

	e := reg.For("acme")
	q := e.DestructiveAuthorizationQueue()
	resultCh := make(chan bool, 1)
	go func() {
		approved, _ := q.Authorize(context.Background(), "acme", brain.BetSettlementRequest{HypothesisID: "hyp-1"})
		resultCh <- approved
	}()

	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	tctx = auth.ContextWithActingUser(tctx, "reviewer-1")
	awaitPending(t, tctx, srv, 1)

	if _, err := srv.DenyDestructiveAction(tctx, &destructiveauthzv1.DenyDestructiveActionRequest{ActionId: "hyp-1"}); err != nil {
		t.Fatalf("DenyDestructiveAction: %v", err)
	}

	select {
	case approved := <-resultCh:
		if approved {
			t.Fatal("want the waiting Authorize call to see approved=false")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Authorize did not unblock after DenyDestructiveAction")
	}
}

func TestDenyDestructiveAction_RequiresActionID(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	srv := NewDestructiveAuthorizationServer(reg, nil)

	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	if _, err := srv.DenyDestructiveAction(tctx, &destructiveauthzv1.DenyDestructiveActionRequest{}); err == nil {
		t.Fatal("want an error when action_id is empty")
	}
}

func TestDenyDestructiveAction_UnknownActionErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	srv := NewDestructiveAuthorizationServer(reg, nil)

	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	tctx = auth.ContextWithActingUser(tctx, "reviewer-1")
	_, err := srv.DenyDestructiveAction(tctx, &destructiveauthzv1.DenyDestructiveActionRequest{ActionId: "hyp-nonexistent"})
	if err == nil {
		t.Fatal("want an error denying an unknown action")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("want codes.FailedPrecondition for an unknown action, got %v", status.Code(err))
	}
}

// -----------------------------------------------------------------------
// Privileged-fallback fix (CodeQL analyze / privileged-fallback): a failed
// acting-user resolution must reject the call, never silently proceed with
// an empty/unknown identity attributed to a destructive-action decision.
// -----------------------------------------------------------------------

func TestApproveDestructiveAction_RequiresActingUser(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	srv := NewDestructiveAuthorizationServer(reg, nil)

	e := reg.For("acme")
	q := e.DestructiveAuthorizationQueue()
	go func() {
		_, _ = q.Authorize(context.Background(), "acme", brain.BetSettlementRequest{HypothesisID: "hyp-1"})
	}()

	// Tenant present, but NO acting-user set — the exact failure mode
	// ActingUserFromContext's "ok=false" return represents.
	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	awaitPending(t, tctx, srv, 1)

	_, err := srv.ApproveDestructiveAction(tctx, &destructiveauthzv1.ApproveDestructiveActionRequest{ActionId: "hyp-1"})
	if err == nil {
		t.Fatal("want an error when no acting user is in context")
	}
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("want codes.Unauthenticated, got %v", status.Code(err))
	}

	// The action must still be pending -- the missing identity must not
	// have let the approval through with a blank/unknown attribution.
	resp := awaitPending(t, tctx, srv, 1)
	if resp.Actions[0].ActionId != "hyp-1" {
		t.Fatalf("want hyp-1 still pending after the rejected call, got %+v", resp.Actions)
	}

	// Cleanup so the goroutine does not leak past the test.
	_ = q.Decide("hyp-1", "reviewer-1", false)
}

func TestDenyDestructiveAction_RequiresActingUser(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	srv := NewDestructiveAuthorizationServer(reg, nil)

	e := reg.For("acme")
	q := e.DestructiveAuthorizationQueue()
	go func() {
		_, _ = q.Authorize(context.Background(), "acme", brain.BetSettlementRequest{HypothesisID: "hyp-1"})
	}()

	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	awaitPending(t, tctx, srv, 1)

	_, err := srv.DenyDestructiveAction(tctx, &destructiveauthzv1.DenyDestructiveActionRequest{ActionId: "hyp-1"})
	if err == nil {
		t.Fatal("want an error when no acting user is in context")
	}
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("want codes.Unauthenticated, got %v", status.Code(err))
	}

	resp := awaitPending(t, tctx, srv, 1)
	if resp.Actions[0].ActionId != "hyp-1" {
		t.Fatalf("want hyp-1 still pending after the rejected call, got %+v", resp.Actions)
	}

	_ = q.Decide("hyp-1", "reviewer-1", false)
}
