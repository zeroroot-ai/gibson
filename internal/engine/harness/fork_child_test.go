// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"github.com/zeroroot-ai/sdk/fork"
	"strings"
	"testing"
	"time"

	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"github.com/zeroroot-ai/sdk/auth"
	sdkcg "github.com/zeroroot-ai/sdk/capabilitygrant"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/harness/sandboxed"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// ClaimFork waits in the call until the dispatch of the fork is recorded.
func TestClaimFork_WaitsForTheDispatch(t *testing.T) {
	s, l := claimService(t)
	ctx := context.Background()
	if err := l.ReserveForkSeat(ctx, ForkSeat{
		MissionID: "child-1", NodeID: "exploit", SandboxID: "ns/fork-1/u1", Tenant: "acme",
		SourceSandboxID: "ns/src-1/u0", SourceJTI: "jti-c",
	}, time.Hour); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = l.RecordForks(ctx, "jti-c", "ns/src-1/u0", []ForkDispatch{{SandboxID: "ns/fork-1/u1", Tenant: "acme", NodeID: "exploit"}}, time.Hour)
	}()
	resp, err := s.ClaimFork(identityCtx("tok-fork-1"), &harnesspb.ClaimForkRequest{SandboxId: "fork-1"})
	if err != nil || resp.GetGrant() == "" || resp.GetNodeId() != "exploit" {
		t.Fatalf("ClaimFork = %v, %v", resp, err)
	}
}

// The fork of the caller gets the network scope of the first node of the
// child, never the scope of the caller, and waits as the seat of that node.
func TestForkCaller_TakesTheScopeOfTheChildNode(t *testing.T) {
	launcher := &recordingLauncher{forkIDs: []string{"ns/fork-1/u1"}}
	h, ledger := forkHarness(t, launcher)
	childID := types.NewID()
	node := brain.WorkNode{ID: "exploit", Kind: "agent", Target: "zerocool",
		Network: &agent.NodeNetwork{Targets: []string{"10.0.0.5:443"}}}
	ctx := callerCtx(t, "user-1", "zerocool-lab")

	id, err := h.ForkCaller(ctx, CallerFork{
		CallerSandboxID: "ns/src-1/u0", CallerJTI: "jti-c", AgentName: "zerocool",
		ChildMissionID: childID, Node: node,
	})
	if err != nil || id != "ns/fork-1/u1" {
		t.Fatalf("ForkCaller = %q, %v", id, err)
	}
	if launcher.gotSource != "ns/src-1/u0" || launcher.gotFork.NetworkMode != sandboxed.NetworkModeAllowList ||
		len(launcher.gotFork.Egress) == 0 || !strings.HasPrefix(launcher.gotFork.Egress[0].Host, "10.0.0.5") {
		t.Fatalf("fork = %q %+v; want the scope of the child node", launcher.gotSource, launcher.gotFork)
	}
	seat, ok, err := ledger.TakeForkSeat(context.Background(), childID.String(), "exploit")
	if err != nil || !ok || seat.SandboxID != "ns/fork-1/u1" || seat.SourceJTI != "jti-c" || seat.Tenant != "zerocool-lab" {
		t.Fatalf("seat = %+v, %v, %v", seat, ok, err)
	}

	// A first node of another agent cannot continue the state of the caller.
	node.Target = "other-agent"
	if _, err := h.ForkCaller(ctx, CallerFork{
		CallerSandboxID: "ns/src-1/u0", CallerJTI: "jti-c", AgentName: "zerocool", ChildMissionID: childID, Node: node,
	}); err == nil {
		t.Fatal("a child node of another agent must be refused")
	}
	if launcher.forkCalls != 1 {
		t.Fatalf("fork calls = %d, want 1", launcher.forkCalls)
	}
}

// The first node of the child runs in the waiting fork: the harness records
// the dispatch of the node for the fork and follows it. It launches nothing.
func TestDelegateToAgent_RunsInTheWaitingFork(t *testing.T) {
	launcher := &recordingLauncher{outcome: sandboxed.AgentRunResult{
		SandboxID: "ns/fork-1/u1", Result: &sandboxed.AgentTerminalResult{Success: true, Output: "exploited"},
	}}
	h, ledger := forkHarness(t, launcher)
	seat := ForkSeat{
		MissionID: h.missionCtx.ID.String(), NodeID: "exploit", Tenant: "zerocool-lab", AgentName: "zerocool",
		SandboxID: "ns/fork-1/u1", SandboxClass: "agent", SourceSandboxID: "ns/src-1/u0", SourceJTI: "jti-c",
	}
	if err := ledger.ReserveForkSeat(context.Background(), seat, time.Hour); err != nil {
		t.Fatal(err)
	}
	task := agent.NewTask("exploit", "exploit the host", nil)
	task.NodeID = "exploit"

	res, err := h.DelegateToAgent(callerCtx(t, "user-1", "zerocool-lab"), "zerocool", task)
	if err != nil {
		t.Fatalf("DelegateToAgent: %v", err)
	}
	if launcher.calls != 0 || launcher.forkCalls != 0 || launcher.followCalls != 1 || launcher.gotFollow != "ns/fork-1/u1" {
		t.Fatalf("launch = %d, fork = %d, follow = %d %q", launcher.calls, launcher.forkCalls, launcher.followCalls, launcher.gotFollow)
	}
	meta, _ := res.Output["metadata"].(map[string]any)
	if meta["forked_from_sandbox"] != "ns/src-1/u0" {
		t.Fatalf("result metadata = %v", meta)
	}
	d, err := ledger.Claim(context.Background(), "ns/fork-1/u1")
	if err != nil || d.NodeID != "exploit" || d.Tenant == "" || d.AgentName != "zerocool" || d.TaskB64 == "" {
		t.Fatalf("claim = %+v, %v", d, err)
	}

	// The seat is gone: a second dispatch of the node launches fresh.
	if _, err := h.DelegateToAgent(callerCtx(t, "user-1", "zerocool-lab"), "zerocool", task); err != nil {
		t.Fatalf("second dispatch: %v", err)
	}
	if launcher.calls != 1 || launcher.followCalls != 1 {
		t.Fatalf("second dispatch: launch = %d, follow = %d", launcher.calls, launcher.followCalls)
	}
}

// A seat of another agent is refused.
func TestDelegateToAgent_WaitingForkOfAnotherAgent(t *testing.T) {
	launcher := &recordingLauncher{}
	h, ledger := forkHarness(t, launcher)
	if err := ledger.ReserveForkSeat(context.Background(), ForkSeat{
		MissionID: h.missionCtx.ID.String(), NodeID: "exploit", Tenant: "zerocool-lab", AgentName: "other",
		SandboxID: "ns/fork-1/u1", SourceSandboxID: "ns/src-1/u0", SourceJTI: "jti-c",
	}, time.Hour); err != nil {
		t.Fatal(err)
	}
	task := agent.NewTask("exploit", "x", nil)
	task.NodeID = "exploit"
	if _, err := h.DelegateToAgent(callerCtx(t, "user-1", "zerocool-lab"), "zerocool", task); err == nil {
		t.Fatal("a waiting fork of another agent must be refused")
	}
	if launcher.calls != 0 || launcher.followCalls != 0 {
		t.Fatal("a refused seat must start nothing")
	}
}

// forkingParent is a live parent harness that records the fork of the caller.
type forkingParent struct {
	originMockHarness
	got CallerFork
	err error
}

func (p *forkingParent) ForkCaller(_ context.Context, req CallerFork) (string, error) {
	p.got = req
	if p.err != nil {
		return "", p.err
	}
	return "ns/fork-1/u1", nil
}

// childNodeOperator is a mission operator that knows the first node of the
// child and records a cancel.
type childNodeOperator struct {
	recordingMissionOperator
	node      brain.WorkNode
	nodeErr   error
	cancelled []types.ID
}

func (m *childNodeOperator) ChildFirstNode(context.Context, types.ID) (brain.WorkNode, error) {
	return m.node, m.nodeErr
}

func (m *childNodeOperator) Cancel(_ context.Context, id types.ID) error {
	m.cancelled = append(m.cancelled, id)
	return nil
}

func forkOriginService(t *testing.T, mgr *childNodeOperator, parent *forkingParent) *HarnessCallbackService {
	t.Helper()
	svc := newOriginService(t, mgr, originParentMissionID, "zerocool")
	parentID, err := types.ParseID(originParentMissionID)
	if err != nil {
		t.Fatal(err)
	}
	parent.mission = MissionContext{ID: parentID, TenantID: originTenant, MissionRunID: "run-7"}
	svc.registry.Register(originParentMissionID, "zerocool", parent)
	l := newForkLedger(t)
	svc.forkLedger = l
	svc.sandboxIdentity = testIdentity()
	return svc
}

// forkOriginCtx is a call of the caller with its grant and identity token.
func forkOriginCtx(t *testing.T, token string) context.Context {
	t.Helper()
	tenant, err := auth.NewTenantID(originTenant)
	if err != nil {
		t.Fatal(err)
	}
	ctx := withTaskGrantClaims(originCtx(), sdkcg.Claims{JTI: "jti-c", Tenant: tenant, Subject: "component:agent:zerocool"})
	if token != "" {
		ctx = metadata.NewIncomingContext(ctx, metadata.Pairs(fork.MetadataSandboxIdentity, token))
	}
	return ctx
}

func forkOriginRequest() *harnesspb.CreateMissionRequest {
	req := originRequest()
	req.StartsFrom = harnesspb.OriginationStart_ORIGINATION_START_CALLER_STATE
	return req
}

// A child that starts from the state of the caller forks the verified
// sandbox of the caller for the first node of the child.
func TestCreateMission_StartsFromCallerStateForksTheCaller(t *testing.T) {
	mgr := &childNodeOperator{node: brain.WorkNode{ID: "exploit", Kind: "agent", Target: "zerocool"}}
	parent := &forkingParent{}
	svc := forkOriginService(t, mgr, parent)

	resp, err := svc.CreateMission(forkOriginCtx(t, "tok-src"), forkOriginRequest())
	if err != nil || resp.GetError() != nil || resp.GetMission() == nil {
		t.Fatalf("CreateMission = %v, %v", resp, err)
	}
	if parent.got.CallerSandboxID != "ns/src-1/u0" || parent.got.CallerJTI != "jti-c" ||
		parent.got.AgentName != "zerocool" || parent.got.Node.ID != "exploit" ||
		parent.got.ChildMissionID.String() != resp.GetMission().GetId() {
		t.Fatalf("fork = %+v", parent.got)
	}
	if len(mgr.cancelled) != 0 {
		t.Fatal("a forked child must not be cancelled")
	}
}

// Each refusal before the child exists creates no mission and no fork.
func TestCreateMission_StartsFromCallerStateRefusals(t *testing.T) {
	cases := []struct {
		name  string
		token string
		code  codes.Code
	}{
		{"no identity token", "", codes.Unauthenticated},
		{"a token that does not verify", "tok-forged", codes.Unauthenticated},
	}
	for _, c := range cases {
		mgr := &childNodeOperator{node: brain.WorkNode{ID: "exploit", Kind: "agent", Target: "zerocool"}}
		parent := &forkingParent{}
		svc := forkOriginService(t, mgr, parent)
		_, err := svc.CreateMission(forkOriginCtx(t, c.token), forkOriginRequest())
		if status.Code(err) != c.code {
			t.Errorf("%s: code = %v, want %v", c.name, status.Code(err), c.code)
		}
		if mgr.got != nil || parent.got.CallerSandboxID != "" {
			t.Errorf("%s: a refused fork created a mission or a fork", c.name)
		}
	}

	// A daemon with no fork ledger refuses before the child exists.
	mgr := &childNodeOperator{}
	parent := &forkingParent{}
	svc := forkOriginService(t, mgr, parent)
	svc.forkLedger = nil
	if _, err := svc.CreateMission(forkOriginCtx(t, "tok-src"), forkOriginRequest()); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("no fork support: code = %v", status.Code(err))
	}
	if mgr.got != nil {
		t.Error("no fork support: a mission was created")
	}
}

// The caller fork takes the agent from the verified grant. A request that
// names another agent gets the agent of the grant, and a grant that is not an
// agent grant cannot fork the caller.
func TestCreateMission_CallerForkAgentComesFromTheGrant(t *testing.T) {
	mgr := &childNodeOperator{node: brain.WorkNode{ID: "exploit", Kind: "agent", Target: "beta"}}
	parent := &forkingParent{}
	svc := forkOriginService(t, mgr, parent)
	req := forkOriginRequest()
	req.Context.AgentName = "beta" // alpha's grant, beta in the request
	_, err := svc.CreateMission(forkOriginCtx(t, "tok-src"), req)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition (first node targets beta, grant is zerocool)", status.Code(err))
	}
	if parent.got.AgentName != "zerocool" {
		t.Fatalf("fork agent = %q, want the agent of the grant", parent.got.AgentName)
	}

	tenant, _ := auth.NewTenantID(originTenant)
	ctx := withTaskGrantClaims(originCtx(), sdkcg.Claims{JTI: "jti-c", Tenant: tenant, Subject: "component:tool:nmap"})
	ctx = metadata.NewIncomingContext(ctx, metadata.Pairs(fork.MetadataSandboxIdentity, "tok-src"))
	mgr2 := &childNodeOperator{node: brain.WorkNode{ID: "exploit", Kind: "agent", Target: "zerocool"}}
	if _, err := forkOriginService(t, mgr2, &forkingParent{}).CreateMission(ctx, forkOriginRequest()); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-agent grant: code = %v, want PermissionDenied", status.Code(err))
	}
}

// A fork that fails after the child exists cancels the child.
func TestCreateMission_FailedForkCancelsTheChild(t *testing.T) {
	for name, mgr := range map[string]*childNodeOperator{
		"no single entry node": {nodeErr: errors.New("two entry nodes")},
		"fork failed":          {node: brain.WorkNode{ID: "exploit", Kind: "agent", Target: "zerocool"}},
	} {
		parent := &forkingParent{err: errors.New("setec down")}
		svc := forkOriginService(t, mgr, parent)
		_, err := svc.CreateMission(forkOriginCtx(t, "tok-src"), forkOriginRequest())
		if status.Code(err) != codes.FailedPrecondition {
			t.Errorf("%s: code = %v", name, status.Code(err))
		}
		if len(mgr.cancelled) != 1 {
			t.Errorf("%s: cancelled = %v, want the child", name, mgr.cancelled)
		}
	}
}
