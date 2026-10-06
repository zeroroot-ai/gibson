// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"testing"
	"time"

	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	sdkcg "github.com/zeroroot-ai/sdk/capabilitygrant"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func claimCtx(jti string) context.Context {
	return withTaskGrantClaims(context.Background(), sdkcg.Claims{JTI: jti})
}

func claimService(t *testing.T) (*HarnessCallbackService, *RedisForkLedger) {
	t.Helper()
	l, _ := newForkLedger(t)
	return &HarnessCallbackService{forkLedger: l, logger: discardLogger()}, l
}

// TestClaimFork_ServesTheDispatchOnce serves a recorded fork its dispatch.
func TestClaimFork_ServesTheDispatchOnce(t *testing.T) {
	s, l := claimService(t)
	err := l.RecordForks(context.Background(), "jti-1", "ns/src/u0",
		[]ForkDispatch{{SandboxID: "ns/fork-1/u1", Grant: "g-fork", NodeID: "n2", MissionID: "m1"}}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := s.ClaimFork(claimCtx("jti-1"), &harnesspb.ClaimForkRequest{SandboxId: "fork-1"})
	if err != nil {
		t.Fatalf("ClaimFork: %v", err)
	}
	if resp.GetGrant() != "g-fork" || resp.GetNodeId() != "n2" || resp.GetMissionId() != "m1" {
		t.Fatalf("response = %v", resp)
	}
	_, err = s.ClaimFork(claimCtx("jti-1"), &harnesspb.ClaimForkRequest{SandboxId: "fork-1"})
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("second claim: code = %v, want AlreadyExists", status.Code(err))
	}
}

// TestClaimFork_Refusals checks the code of each refused claim.
func TestClaimFork_Refusals(t *testing.T) {
	s, l := claimService(t)
	ctx := context.Background()
	if err := l.BeginFork(ctx, "jti-p", "ns/src/u0", time.Hour); err != nil {
		t.Fatal(err)
	}
	req := &harnesspb.ClaimForkRequest{SandboxId: "fork-9"}

	if _, err := s.ClaimFork(ctx, req); status.Code(err) != codes.Unauthenticated {
		t.Errorf("no grant: code = %v", status.Code(err))
	}
	if _, err := s.ClaimFork(claimCtx("jti-p"), req); status.Code(err) != codes.Unavailable {
		t.Errorf("pending: code = %v", status.Code(err))
	}
	if _, err := s.ClaimFork(claimCtx("jti-none"), req); status.Code(err) != codes.PermissionDenied {
		t.Errorf("not a fork: code = %v", status.Code(err))
	}
	none := &HarnessCallbackService{logger: discardLogger()}
	if _, err := none.ClaimFork(claimCtx("jti-p"), req); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("no ledger: code = %v", status.Code(err))
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
