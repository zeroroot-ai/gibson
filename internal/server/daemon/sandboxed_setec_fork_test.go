// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build setec_integration

package daemon

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/zeroroot-ai/gibson/internal/engine/harness/sandboxed"
	setecv1 "github.com/zeroroot-ai/setec/api/grpc/v1"
)

// forkingSetec records the Fork request that it gets. The
// embedded interface panics on any other call.
type forkingSetec struct {
	setecv1.SandboxServiceClient
	fork    *setecv1.ForkRequest
	forkErr error
}

func (f *forkingSetec) Fork(_ context.Context, in *setecv1.ForkRequest, _ ...grpc.CallOption) (*setecv1.ForkResponse, error) {
	f.fork = in
	if f.forkErr != nil {
		return nil, f.forkErr
	}
	return &setecv1.ForkResponse{Snapshot: "snap-1", SandboxIds: []string{"ns/f1/u1", "ns/f2/u2"}}, nil
}


// A fork names the tenant, the count, the snapshot lifetime and the network
// of the request (ADR-0169).
func TestSetecClient_ForkMapsTheRequest(t *testing.T) {
	rec := &forkingSetec{}
	c := &setecClient{inner: rec}
	resp, err := c.Fork(context.Background(), sandboxed.ForkRequest{
		Tenant: "acme", SandboxID: "ns/src/u0", Count: 2,
		NetworkMode: sandboxed.NetworkModeAllowList,
		Egress:      []sandboxed.EgressRule{{CIDR: "10.0.0.0/24", Ports: []sandboxed.PortRange{{Protocol: "UDP", Port: 53}}}},
		SnapshotTTL: 90 * time.Second,
	})
	if err != nil {
		t.Fatalf("Fork: %v", err)
	}
	if resp.Snapshot != "snap-1" || len(resp.SandboxIDs) != 2 {
		t.Fatalf("response = %+v", resp)
	}
	got := rec.fork
	if got.GetTenant() != "acme" || got.GetSandboxId() != "ns/src/u0" || got.GetCount() != 2 || got.GetSnapshotTtlSeconds() != 90 {
		t.Fatalf("request = %v", got)
	}
	allow := got.GetNetwork().GetAllow()
	if got.GetNetwork().GetMode() != sandboxed.NetworkModeAllowList || len(allow) != 1 || allow[0].GetCidr() != "10.0.0.0/24" ||
		allow[0].GetPorts()[0].GetProtocol() != "UDP" || allow[0].GetPorts()[0].GetPort() != 53 {
		t.Fatalf("network = %v", got.GetNetwork())
	}
}

// A fork with no tenant, a bad count or a setec error is refused.
func TestSetecClient_ForkRefusals(t *testing.T) {
	ctx := context.Background()
	c := &setecClient{inner: &forkingSetec{}}
	if _, err := c.Fork(ctx, sandboxed.ForkRequest{SandboxID: "s", Count: 1}); !errors.Is(err, errNoTenant) {
		t.Errorf("no tenant: err = %v", err)
	}
	for _, n := range []int{0, sandboxed.MaxForks + 1} {
		if _, err := c.Fork(ctx, sandboxed.ForkRequest{Tenant: "acme", SandboxID: "s", Count: n}); err == nil {
			t.Errorf("count %d: want an error", n)
		}
	}
	c = &setecClient{inner: &forkingSetec{forkErr: errors.New("source is not running")}}
	if _, err := c.Fork(ctx, sandboxed.ForkRequest{Tenant: "acme", SandboxID: "s", Count: 1}); err == nil {
		t.Error("a setec error must return")
	}
}
