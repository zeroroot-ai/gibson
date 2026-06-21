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

// TestWorldService_TenantScopedRead: the read path returns the caller's tenant's
// live World, and refuses a request with no tenant in context.
func TestWorldService_TenantScopedRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	srv := NewWorldServer(reg, nil)

	reg.For("acme").Submit(brain.HostObserved{ScopeID: "s", Address: "10.0.0.5", OpenPorts: []int{22}})

	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	var resp *worldpb.ListHostsResponse
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var err error
		if resp, err = srv.ListHosts(tctx, &worldpb.ListHostsRequest{}); err != nil {
			t.Fatalf("ListHosts: %v", err)
		}
		if len(resp.Hosts) == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(resp.GetHosts()) != 1 || resp.Hosts[0].Address != "10.0.0.5" {
		t.Fatalf("ListHosts = %+v, want one host 10.0.0.5", resp.GetHosts())
	}

	// No tenant in context -> PermissionDenied.
	if _, err := srv.ListHosts(context.Background(), &worldpb.ListHostsRequest{}); err == nil {
		t.Fatal("expected an error when no tenant is in context")
	}
}

// TestWorldService_ListLlmCalls: the World's LLM-call provenance (gibson#755) is
// readable, tenant-scoped, with token data surfaced; no tenant -> PermissionDenied.
func TestWorldService_ListLlmCalls(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	srv := NewWorldServer(reg, nil)

	reg.For("acme").Submit(brain.LlmCallObserved{
		CallID: "c1", Model: "claude-haiku-4-5", PromptTokens: 100, CompletionTokens: 40,
	})

	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	var resp *worldpb.ListLlmCallsResponse
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var err error
		if resp, err = srv.ListLlmCalls(tctx, &worldpb.ListLlmCallsRequest{}); err != nil {
			t.Fatalf("ListLlmCalls: %v", err)
		}
		if len(resp.LlmCalls) == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(resp.GetLlmCalls()) != 1 {
		t.Fatalf("ListLlmCalls = %+v, want one call", resp.GetLlmCalls())
	}
	c := resp.LlmCalls[0]
	if c.Model != "claude-haiku-4-5" || c.PromptTokens != 100 || c.CompletionTokens != 40 {
		t.Fatalf("unexpected call view: %+v", c)
	}

	if _, err := srv.ListLlmCalls(context.Background(), &worldpb.ListLlmCallsRequest{}); err == nil {
		t.Fatal("expected an error when no tenant is in context")
	}
}

// TestWorldService_GetLlmCall: a single call's transcript (prompt + completion)
// is retrievable for the conversation view (gibson#755); unknown id -> NotFound.
func TestWorldService_GetLlmCall(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	srv := NewWorldServer(reg, nil)

	reg.For("acme").Submit(brain.LlmCallObserved{
		CallID:     "c1",
		Model:      "claude-haiku-4-5",
		Messages:   []brain.LlmMessage{{Role: "user", Content: "scan the host"}},
		Completion: "running nmap",
	})

	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	var resp *worldpb.GetLlmCallResponse
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var err error
		resp, err = srv.GetLlmCall(tctx, &worldpb.GetLlmCallRequest{CallId: "c1"})
		if err == nil && resp.GetCall() != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if resp.GetCall() == nil {
		t.Fatal("GetLlmCall returned no call")
	}
	call := resp.Call
	if len(call.Messages) != 1 || call.Messages[0].Content != "scan the host" || call.Completion != "running nmap" {
		t.Fatalf("transcript not returned: %+v", call)
	}

	// Unknown call id -> NotFound.
	if _, err := srv.GetLlmCall(tctx, &worldpb.GetLlmCallRequest{CallId: "nope"}); status.Code(err) != codes.NotFound {
		t.Fatalf("want NotFound for unknown call, got %v", err)
	}
}

// TestWorldService_GetFrameAt: a replay frame is a server-side fold of the log to
// a point (ADR-0001). Scrubbing to an earlier seq reproduces the World as it was;
// seq == total reproduces the live World; isolation holds.
func TestWorldService_GetFrameAt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	srv := NewWorldServer(reg, nil)

	// Three observations: host, then a finding, then a second host.
	reg.For("acme").Submit(brain.HostObserved{ScopeID: "s", Address: "10.0.0.5", OpenPorts: []int{22}})
	reg.For("acme").Submit(brain.FindingRaised{ID: "f1", Title: "weak ssh", ScopeID: "s", Address: "10.0.0.5", Severity: "high"})
	reg.For("acme").Submit(brain.HostObserved{ScopeID: "s", Address: "10.0.0.6", OpenPorts: []int{443}})

	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))

	// Wait until all three events have folded into the live World.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(reg.For("acme").Events()) == 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Frame after the first event only: one host, no finding.
	f1, err := srv.GetFrameAt(tctx, &worldpb.GetFrameAtRequest{Seq: 1})
	if err != nil {
		t.Fatalf("GetFrameAt(1): %v", err)
	}
	if f1.Seq != 1 || f1.Total != 3 {
		t.Fatalf("frame meta = seq %d/total %d, want 1/3", f1.Seq, f1.Total)
	}
	if len(f1.Hosts) != 1 || len(f1.Findings) != 0 {
		t.Fatalf("frame@1 = %d hosts %d findings, want 1/0", len(f1.Hosts), len(f1.Findings))
	}

	// Frame after two events: one host + the finding (the second host not yet seen).
	f2, err := srv.GetFrameAt(tctx, &worldpb.GetFrameAtRequest{Seq: 2})
	if err != nil {
		t.Fatalf("GetFrameAt(2): %v", err)
	}
	if len(f2.Hosts) != 1 || len(f2.Findings) != 1 {
		t.Fatalf("frame@2 = %d hosts %d findings, want 1/1", len(f2.Hosts), len(f2.Findings))
	}

	// seq past the end clamps to total → the live World: two hosts + one finding.
	fEnd, err := srv.GetFrameAt(tctx, &worldpb.GetFrameAtRequest{Seq: 99})
	if err != nil {
		t.Fatalf("GetFrameAt(99): %v", err)
	}
	if fEnd.Seq != 3 || len(fEnd.Hosts) != 2 || len(fEnd.Findings) != 1 {
		t.Fatalf("frame@end = seq %d, %d hosts %d findings, want 3/2/1", fEnd.Seq, len(fEnd.Hosts), len(fEnd.Findings))
	}

	// Folding a frame must not mutate the live World (still two hosts).
	if live, _ := srv.ListHosts(tctx, &worldpb.ListHostsRequest{}); len(live.GetHosts()) != 2 {
		t.Fatalf("live World mutated by frame fold: %d hosts, want 2", len(live.GetHosts()))
	}

	// No tenant -> error.
	if _, err := srv.GetFrameAt(context.Background(), &worldpb.GetFrameAtRequest{Seq: 1}); err == nil {
		t.Fatal("expected an error when no tenant is in context")
	}
}
