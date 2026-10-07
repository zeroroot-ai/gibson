// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/platform/capabilitygrant"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"github.com/zeroroot-ai/sdk/fork"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// stubForkGrants mints a grant that names the claimed sandbox.
type stubForkGrants struct{ err error }

func (s stubForkGrants) MintForkGrant(_ context.Context, d ForkDispatch) (string, error) {
	if s.err != nil {
		return "", s.err
	}
	return "new-grant-for-" + d.SandboxID, nil
}

func claimService(t *testing.T) (*HarnessCallbackService, *memForkLedger) {
	t.Helper()
	shortTargetWait(t)
	l := newForkLedger(t)
	return &HarnessCallbackService{
		forkLedger: l, forkGrants: stubForkGrants{}, sandboxIdentity: testIdentity(), logger: discardLogger(),
	}, l
}

// identityCtx is a claim call that carries only the identity token of the
// sandbox, as D80 states: no grant.
func identityCtx(token string) context.Context {
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs(fork.MetadataSandboxIdentity, token))
}

func recordFork(t *testing.T, l *memForkLedger, sandboxID, node string) {
	t.Helper()
	d := ForkDispatch{SandboxID: sandboxID, Tenant: "acme", AgentName: "zerocool", MissionID: "m1", MissionRunID: "r1", NodeID: node}
	if err := l.RecordStart(context.Background(), d, time.Hour); err != nil {
		t.Fatal(err)
	}
}

// A fork claims its dispatch with its identity token only, one time, and
// gets a new grant for its task (D80).
func TestClaimFork_ServesTheDispatchOnce(t *testing.T) {
	s, l := claimService(t)
	recordFork(t, l, "ns/fork-1/u1", "n2")

	resp, err := s.ClaimFork(identityCtx("tok-fork-1"), &harnesspb.ClaimForkRequest{SandboxId: "fork-1"})
	if err != nil {
		t.Fatalf("ClaimFork: %v", err)
	}
	if resp.GetGrant() != "new-grant-for-ns/fork-1/u1" || resp.GetNodeId() != "n2" || resp.GetMissionId() != "m1" {
		t.Fatalf("response = %v", resp)
	}
	_, err = s.ClaimFork(identityCtx("tok-fork-1"), &harnesspb.ClaimForkRequest{SandboxId: "fork-1"})
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("second claim: code = %v, want AlreadyExists", status.Code(err))
	}
}

// A token that names another sandbox than the one the daemon started is
// refused, and the refusal does not use up the claim.
func TestClaimFork_TokenForAnotherSandboxIsRefused(t *testing.T) {
	s, l := claimService(t)
	recordFork(t, l, "ns/fork-1/u1", "n2")

	_, err := s.ClaimFork(identityCtx("tok-fork-2"), &harnesspb.ClaimForkRequest{SandboxId: "fork-1"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied", status.Code(err))
	}
	if _, err := s.ClaimFork(identityCtx("tok-fork-1"), &harnesspb.ClaimForkRequest{SandboxId: "fork-1"}); err != nil {
		t.Fatalf("the real fork must still claim: %v", err)
	}
}

// A claim that presents a grant, the expired grant of the source or any
// other, is refused (D80).
func TestClaimFork_AGrantIsRefused(t *testing.T) {
	s, l := claimService(t)
	recordFork(t, l, "ns/fork-1/u1", "n2")
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		fork.MetadataSandboxIdentity, "tok-fork-1", taskGrantHeader, "Bearer h.e.s"))

	_, err := s.ClaimFork(ctx, &harnesspb.ClaimForkRequest{SandboxId: "fork-1"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied", status.Code(err))
	}
}

// A claim days after the start works: the claim needs no grant, and the
// record lives as long as the snapshot (7 days).
func TestClaimFork_AClaimAfterSevenDaysWorks(t *testing.T) {
	l := newForkLedger(t)
	s := &HarnessCallbackService{forkLedger: l, forkGrants: stubForkGrants{}, sandboxIdentity: testIdentity(), logger: discardLogger()}
	d := ForkDispatch{SandboxID: "ns/fork-1/u1", Tenant: "acme", AgentName: "zerocool", MissionID: "m1", MissionRunID: "r1", NodeID: "n2"}
	if err := l.RecordStart(context.Background(), d, SnapshotLife); err != nil {
		t.Fatal(err)
	}
	l.FastForward(SnapshotLife - time.Minute)
	if _, err := s.ClaimFork(identityCtx("tok-fork-1"), &harnesspb.ClaimForkRequest{SandboxId: "fork-1"}); err != nil {
		t.Fatalf("ClaimFork after 7 days: %v", err)
	}
}

// Each other refusal of the claim.
func TestClaimFork_Refusals(t *testing.T) {
	s, l := claimService(t)
	recordFork(t, l, "ns/fork-1/u1", "n2")
	req := &harnesspb.ClaimForkRequest{SandboxId: "fork-1"}

	if _, err := s.ClaimFork(identityCtx("tok-fork-1"), &harnesspb.ClaimForkRequest{SandboxId: "fork-9"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("not started: code = %v", status.Code(err))
	}
	if _, err := s.ClaimFork(context.Background(), req); status.Code(err) != codes.Unauthenticated {
		t.Errorf("no token: code = %v", status.Code(err))
	}
	if _, err := s.ClaimFork(identityCtx("bad"), req); status.Code(err) != codes.Unauthenticated {
		t.Errorf("bad token: code = %v", status.Code(err))
	}
	none := &HarnessCallbackService{logger: discardLogger()}
	if _, err := none.ClaimFork(identityCtx("tok-fork-1"), req); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("no fork support: code = %v", status.Code(err))
	}
	s.forkGrants = stubForkGrants{err: errors.New("no key")}
	if _, err := s.ClaimFork(identityCtx("tok-fork-1"), req); status.Code(err) != codes.Unavailable {
		t.Errorf("mint failure: code = %v", status.Code(err))
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

// shortTargetWait bounds the wait for a start record in a test.
func shortTargetWait(t *testing.T) {
	t.Helper()
	old := forkTargetWait
	forkTargetWait = 300 * time.Millisecond
	t.Cleanup(func() { forkTargetWait = old })
}

// The minter of a claimed fork mints a grant for the task of the dispatch,
// and refuses before the daemon has a key or for a dispatch without scope.
func TestNewForkGrantMinter(t *testing.T) {
	d := ForkDispatch{SandboxID: "s", Tenant: "acme", AgentName: "zerocool", MissionID: "m1", MissionRunID: "r1"}
	m := testMinter(t)
	tok, err := NewForkGrantMinter(func() *capabilitygrant.Minter { return m }).MintForkGrant(context.Background(), d)
	if err != nil || tok == "" {
		t.Fatalf("MintForkGrant = %q, %v", tok, err)
	}
	if _, err := NewForkGrantMinter(func() *capabilitygrant.Minter { return nil }).MintForkGrant(context.Background(), d); err == nil {
		t.Error("no minter: want an error")
	}
	if _, err := NewForkGrantMinter(func() *capabilitygrant.Minter { return m }).MintForkGrant(context.Background(), ForkDispatch{}); err == nil {
		t.Error("no scope: want an error")
	}
}
