// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"testing"
	"time"

	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func claimService(t *testing.T) (*HarnessCallbackService, *RedisForkLedger) {
	t.Helper()
	l, _ := newForkLedger(t)
	return &HarnessCallbackService{forkLedger: l, sandboxIdentity: testIdentity(), logger: discardLogger()}, l
}

// TestClaimFork_ServesTheDispatchOnce serves a recorded fork its dispatch
// one time. The fork is the sandbox that its identity token names.
func TestClaimFork_ServesTheDispatchOnce(t *testing.T) {
	s, l := claimService(t)
	err := l.RecordForks(context.Background(), "jti-1", "ns/src-1/u0", []ForkDispatch{
		{SandboxID: "ns/fork-1/u1", Grant: "g-fork-1", NodeID: "n2", MissionID: "m1"},
		{SandboxID: "ns/fork-2/u2", Grant: "g-fork-2", NodeID: "n3", MissionID: "m1"},
	}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := s.ClaimFork(forkCtx("jti-1", "tok-fork-1", "fork-1"), &harnesspb.ClaimForkRequest{SandboxId: "fork-1"})
	if err != nil {
		t.Fatalf("ClaimFork: %v", err)
	}
	if resp.GetGrant() != "g-fork-1" || resp.GetNodeId() != "n2" || resp.GetMissionId() != "m1" {
		t.Fatalf("response = %v", resp)
	}
	_, err = s.ClaimFork(forkCtx("jti-1", "tok-fork-1", ""), &harnesspb.ClaimForkRequest{SandboxId: "fork-1"})
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("second claim: code = %v, want AlreadyExists", status.Code(err))
	}
	// The other fork claims its own dispatch with an empty sandbox_id: the
	// token is the proof.
	resp, err = s.ClaimFork(forkCtx("jti-1", "tok-fork-2", ""), &harnesspb.ClaimForkRequest{})
	if err != nil || resp.GetGrant() != "g-fork-2" {
		t.Fatalf("second fork: %v, %v", resp, err)
	}
}

// TestClaimFork_TheTokenNamesTheFork refuses a claim for another sandbox
// than the one that the identity token names (setec#235). A fork cannot
// claim the dispatch of another fork, and the source cannot claim a fork.
func TestClaimFork_TheTokenNamesTheFork(t *testing.T) {
	s, l := claimService(t)
	err := l.RecordForks(context.Background(), "jti-1", "ns/src-1/u0", []ForkDispatch{
		{SandboxID: "ns/fork-1/u1", Grant: "g-fork-1"},
		{SandboxID: "ns/fork-2/u2", Grant: "g-fork-2"},
	}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		ctx   context.Context
		claim string
		code  codes.Code
	}{
		{"fork 2 names fork 1", forkCtx("jti-1", "tok-fork-2", ""), "fork-1", codes.PermissionDenied},
		{"fork 2 sends the header of fork 1", forkCtx("jti-1", "tok-fork-2", "fork-1"), "fork-2", codes.PermissionDenied},
		{"header only, no token", forkCtx("jti-1", "", "fork-1"), "fork-1", codes.Unauthenticated},
		{"token that does not verify", forkCtx("jti-1", "tok-forged", ""), "fork-1", codes.Unauthenticated},
		{"the source claims", forkCtx("jti-1", "tok-src", ""), "", codes.PermissionDenied},
	}
	for _, c := range cases {
		if _, err := s.ClaimFork(c.ctx, &harnesspb.ClaimForkRequest{SandboxId: c.claim}); status.Code(err) != c.code {
			t.Errorf("%s: code = %v, want %v", c.name, status.Code(err), c.code)
		}
	}
	// No refused claim used up a fork.
	for _, tok := range []string{"tok-fork-1", "tok-fork-2"} {
		if _, err := s.ClaimFork(forkCtx("jti-1", tok, ""), &harnesspb.ClaimForkRequest{}); err != nil {
			t.Errorf("claim with %s after the refusals: %v", tok, err)
		}
	}
}

// TestClaimFork_Refusals checks the code of each refused claim.
func TestClaimFork_Refusals(t *testing.T) {
	s, l := claimService(t)
	ctx := context.Background()
	if err := l.BeginFork(ctx, "jti-p", "ns/src-1/u0", time.Hour); err != nil {
		t.Fatal(err)
	}
	req := &harnesspb.ClaimForkRequest{SandboxId: "fork-1"}

	if _, err := s.ClaimFork(ctx, req); status.Code(err) != codes.Unauthenticated {
		t.Errorf("no grant: code = %v", status.Code(err))
	}
	if _, err := s.ClaimFork(forkCtx("jti-p", "tok-fork-1", ""), req); status.Code(err) != codes.Unavailable {
		t.Errorf("pending: code = %v", status.Code(err))
	}
	if _, err := s.ClaimFork(forkCtx("jti-none", "tok-fork-1", ""), req); status.Code(err) != codes.PermissionDenied {
		t.Errorf("not a fork: code = %v", status.Code(err))
	}
	none := &HarnessCallbackService{sandboxIdentity: testIdentity(), logger: discardLogger()}
	if _, err := none.ClaimFork(forkCtx("jti-p", "tok-fork-1", ""), req); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("no ledger: code = %v", status.Code(err))
	}
	noVerifier := &HarnessCallbackService{forkLedger: l, logger: discardLogger()}
	if _, err := noVerifier.ClaimFork(forkCtx("jti-p", "tok-fork-1", ""), req); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("no verifier: code = %v", status.Code(err))
	}
}

// TestForkTask decodes the task of a fork dispatch.
func TestForkTask(t *testing.T) {
	if task, err := forkTask(""); task != nil || err != nil {
		t.Errorf("empty task = %v, %v", task, err)
	}
	if _, err := forkTask("!!!"); err == nil {
		t.Error("bad base64 must fail")
	}
	if _, err := forkTask("bm90IGpzb24="); err == nil {
		t.Error("bad JSON must fail")
	}
	// {"goal":"scan"}
	task, err := forkTask("eyJnb2FsIjoic2NhbiJ9")
	if err != nil || task.GetGoal() != "scan" {
		t.Errorf("task = %v, %v", task, err)
	}
}
