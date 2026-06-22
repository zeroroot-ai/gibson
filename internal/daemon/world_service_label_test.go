package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/brain"
	worldpb "github.com/zeroroot-ai/gibson/internal/daemon/api/gibson/world/v1"
	"github.com/zeroroot-ai/sdk/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// SubmitLabel appends a tenant-scoped label, stamping the caller's user id from
// context; ListLabels reads it back. The label is visible only in the caller's
// tenant (ADR-0006: pooled within tenant, never cross-tenant).
func TestWorldService_SubmitAndListLabels_TenantScoped(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	srv := NewWorldServer(reg, nil)

	acme := auth.ContextWithActingUser(
		auth.WithTenant(context.Background(), auth.MustNewTenantID("acme")), "alice")

	if _, err := srv.SubmitLabel(acme, &worldpb.SubmitLabelRequest{
		TargetId: "finding-1", Verdict: "true_positive", Severity: "high", Category: "rce",
	}); err != nil {
		t.Fatalf("SubmitLabel: %v", err)
	}

	// The label is readable in acme's tenant with the caller's user id stamped.
	resp := waitLabels(t, srv, acme, 1)
	if resp.Labels[0].TargetId != "finding-1" || resp.Labels[0].Verdict != "true_positive" {
		t.Errorf("label wrong: %+v", resp.Labels[0])
	}
	if resp.Labels[0].UserId != "alice" {
		t.Errorf("expected user id stamped from context, got %q", resp.Labels[0].UserId)
	}

	// A DIFFERENT tenant must NOT see acme's label.
	other := auth.WithTenant(context.Background(), auth.MustNewTenantID("other"))
	or, err := srv.ListLabels(other, &worldpb.ListLabelsRequest{})
	if err != nil {
		t.Fatalf("ListLabels(other): %v", err)
	}
	if len(or.GetLabels()) != 0 {
		t.Fatalf("cross-tenant leak: other tenant saw %d labels", len(or.GetLabels()))
	}
}

// SubmitLabel rejects an unknown verdict (fail-closed) and a missing target.
func TestWorldService_SubmitLabel_Validation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := NewWorldServer(brain.NewRegistry(ctx), nil)
	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))

	if _, err := srv.SubmitLabel(tctx, &worldpb.SubmitLabelRequest{TargetId: "f", Verdict: "bogus"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("unknown verdict should be InvalidArgument, got %v", err)
	}
	if _, err := srv.SubmitLabel(tctx, &worldpb.SubmitLabelRequest{Verdict: "true_positive"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("missing target_id should be InvalidArgument, got %v", err)
	}
	// No tenant in context -> PermissionDenied.
	if _, err := srv.SubmitLabel(context.Background(), &worldpb.SubmitLabelRequest{TargetId: "f", Verdict: "dismiss"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("no tenant should be PermissionDenied, got %v", err)
	}
}

// The review queue surfaces a Finding and carries any applied label.
func TestWorldService_ListReviewQueue(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx, brain.SurpriseFindingSystem)
	srv := NewWorldServer(reg, nil)

	eng := reg.For("acme")
	eng.Submit(brain.HostObserved{ScopeID: "s1", Address: "10.0.0.5", SSHHostKey: "AAAA"})
	eng.Submit(brain.HostObserved{ScopeID: "s1", Address: "10.0.0.5", SSHHostKey: "BBBB"})

	acme := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	// Wait for the finding to surface in the queue.
	var item *worldpb.ReviewItem
	for i := 0; i < 200 && item == nil; i++ {
		q, err := srv.ListReviewQueue(acme, &worldpb.ListReviewQueueRequest{})
		if err != nil {
			t.Fatalf("ListReviewQueue: %v", err)
		}
		for _, it := range q.GetItems() {
			if it.Kind == "finding" {
				item = it
			}
		}
		if item == nil {
			time.Sleep(5 * time.Millisecond)
		}
	}
	if item == nil {
		t.Fatal("expected a finding in the review queue")
	}
}

func waitLabels(t *testing.T, srv *worldServer, ctx context.Context, want int) *worldpb.ListLabelsResponse {
	t.Helper()
	for i := 0; i < 200; i++ {
		resp, err := srv.ListLabels(ctx, &worldpb.ListLabelsRequest{})
		if err != nil {
			t.Fatalf("ListLabels: %v", err)
		}
		if len(resp.GetLabels()) >= want {
			return resp
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d labels", want)
	return nil
}
