// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"fmt"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/brain/braintest"
	worldpb "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/world/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// submitProofReview records one proof with typed evidence for hypothesisID.
func submitProofReview(ctx context.Context, t *testing.T, e *brain.Engine, hypothesisID string) {
	t.Helper()
	err := e.SubmitProofForReview(ctx, brain.ProofReviewRequest{
		HypothesisID: hypothesisID,
		MissionID:    "mission-1",
		ScopeID:      "scope-1",
		Technique:    "T1190",
		Evidence: []brain.ProofReviewEvidence{
			{Type: "http_response", Title: "the admin page", Content: "200 OK"},
		},
		SubmittedAtUnixNano: 1_700_000_000_000_000_000,
	})
	if err != nil {
		t.Fatalf("SubmitProofForReview(%s): %v", hypothesisID, err)
	}
}

// awaitProofReviews polls ListProofReviews until it returns want proofs on
// the first page, because Submit folds into the World asynchronously.
func awaitProofReviews(ctx context.Context, t *testing.T, srv *worldServer, want int) []*worldpb.ProofReview {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var got []*worldpb.ProofReview
	for time.Now().Before(deadline) {
		resp, err := srv.ListProofReviews(ctx, &worldpb.ListProofReviewsRequest{})
		if err != nil {
			t.Fatalf("ListProofReviews: %v", err)
		}
		got = resp.GetReviews()
		if len(got) == want {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("want %d proof reviews, got %d: %+v", want, len(got), got)
	return nil
}

func TestListProofReviews_ReturnsTheEvidenceOfTheCallersTenant(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())
	srv := NewWorldServer(reg, nil)

	submitProofReview(ctx, t, reg.For("acme"), "hyp-acme")
	submitProofReview(ctx, t, reg.For("other-tenant"), "hyp-other")

	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	got := awaitProofReviews(tctx, t, srv, 1)
	r := got[0]
	if r.GetHypothesisId() != "hyp-acme" || r.GetMissionId() != "mission-1" ||
		r.GetScopeId() != "scope-1" || r.GetTechnique() != "T1190" ||
		r.GetSubmittedAtUnixNano() != 1_700_000_000_000_000_000 {
		t.Fatalf("unexpected proof review: %+v", r)
	}
	if len(r.GetEvidence()) != 1 || r.GetEvidence()[0].GetTitle() != "the admin page" ||
		r.GetEvidence()[0].GetType() != "http_response" || r.GetEvidence()[0].GetContent() != "200 OK" {
		t.Fatalf("unexpected evidence: %+v", r.GetEvidence())
	}

	if _, err := srv.ListProofReviews(context.Background(), &worldpb.ListProofReviewsRequest{}); err == nil {
		t.Fatal("expected an error when no tenant is in context")
	}
}

func TestListProofReviews_PagesGiveEachProofOnce(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())
	srv := NewWorldServer(reg, nil)
	for i := range 5 {
		submitProofReview(ctx, t, reg.For("acme"), fmt.Sprintf("hyp-%d", i))
	}
	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	awaitProofReviews(tctx, t, srv, 5)

	seen := map[string]int{}
	token := ""
	pages := 0
	for {
		resp, err := srv.ListProofReviews(tctx, &worldpb.ListProofReviewsRequest{PageSize: 2, PageToken: token})
		if err != nil {
			t.Fatalf("ListProofReviews page %d: %v", pages, err)
		}
		pages++
		for _, r := range resp.GetReviews() {
			seen[r.GetHypothesisId()]++
		}
		token = resp.GetNextPageToken()
		if token == "" {
			break
		}
		if pages > 5 {
			t.Fatal("paging did not end")
		}
	}
	if pages != 3 || len(seen) != 5 {
		t.Fatalf("want 3 pages over 5 proofs, got %d pages and %v", pages, seen)
	}
	for id, n := range seen {
		if n != 1 {
			t.Fatalf("proof %s returned %d times", id, n)
		}
	}
}

func TestListProofReviews_RefusesATokenItDidNotWrite(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())
	srv := NewWorldServer(reg, nil)
	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	reg.For("acme")

	_, err := srv.ListProofReviews(tctx, &worldpb.ListProofReviewsRequest{PageToken: "not-a-token"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument, got %v", err)
	}
}
