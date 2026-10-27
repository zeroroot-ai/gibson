// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build setec_integration

package daemon

import (
	"context"
	"testing"

	"google.golang.org/grpc"

	"github.com/zeroroot-ai/gibson/internal/engine/harness/sandboxed"
	setecv1 "github.com/zeroroot-ai/setec/api/grpc/v1"
)

// launchingSetec records the Launch request that it gets. The embedded
// interface panics on any other call.
type launchingSetec struct {
	setecv1.SandboxServiceClient
	launch *setecv1.LaunchRequest
}

func (l *launchingSetec) Launch(_ context.Context, in *setecv1.LaunchRequest, _ ...grpc.CallOption) (*setecv1.LaunchResponse, error) {
	l.launch = in
	return &setecv1.LaunchResponse{SandboxId: "sbx-1"}, nil
}

// The network of a launch reaches setec in full: the mode of the node, and
// each rule with its CIDR and its port ranges (gibson#865).
func TestSetecNetwork_MapsEachForm(t *testing.T) {
	if n := setecNetwork("", nil); n != nil {
		t.Errorf("no mode and no rules: network = %v, want nil", n)
	}
	if n := setecNetwork(sandboxed.NetworkModeNone, []sandboxed.EgressRule{{Host: "x", Port: 1}}); n.GetMode() != sandboxed.NetworkModeNone || len(n.GetAllow()) != 0 {
		t.Errorf("mode none: network = %v", n)
	}
	if n := setecNetwork(sandboxed.NetworkModeExternalOnly, nil); n.GetMode() != sandboxed.NetworkModeExternalOnly {
		t.Errorf("external only: network = %v", n)
	}
	n := setecNetwork("", []sandboxed.EgressRule{{Host: "api.example.com", Port: 443}})
	if n.GetMode() != sandboxed.NetworkModeAllowList || n.GetAllow()[0].GetHost() != "api.example.com" || n.GetAllow()[0].GetPort() != 443 {
		t.Errorf("rules with no mode: network = %v", n)
	}
	n = setecNetwork(sandboxed.NetworkModeAllowList, []sandboxed.EgressRule{{
		CIDR: "10.0.0.0/24", Ports: []sandboxed.PortRange{{Protocol: "UDP", Port: 1, EndPort: 65535}},
	}})
	a := n.GetAllow()[0]
	if a.GetHost() != "10.0.0.0" {
		t.Errorf("a rule for a CIDR target needs a host, setec refuses an empty one (gibson#1331): %v", n)
	}
	if a.GetCidr() != "10.0.0.0/24" || a.GetPorts()[0].GetProtocol() != "UDP" || a.GetPorts()[0].GetEndPort() != 65535 {
		t.Errorf("cidr rule: network = %v", n)
	}
}

// A CIDR target of one address gives that address as the host.
func TestEgressHost(t *testing.T) {
	for name, tc := range map[string]struct {
		rule sandboxed.EgressRule
		want string
	}{
		"a host stays":         {sandboxed.EgressRule{Host: "api.example.com", Port: 443}, "api.example.com"},
		"a host with a CIDR":   {sandboxed.EgressRule{Host: "svc", CIDR: "10.0.0.0/24"}, "svc"},
		"a one-address CIDR":   {sandboxed.EgressRule{CIDR: "10.244.0.152/32"}, "10.244.0.152"},
		"a block of addresses": {sandboxed.EgressRule{CIDR: "10.0.0.7/24"}, "10.0.0.0"},
		"an IPv6 block":        {sandboxed.EgressRule{CIDR: "fd00::/64"}, "fd00::"},
		"a bad CIDR":           {sandboxed.EgressRule{CIDR: "nope"}, ""},
		"nothing":              {sandboxed.EgressRule{}, ""},
	} {
		if got := egressHost(tc.rule); got != tc.want {
			t.Errorf("%s: host = %q, want %q", name, got, tc.want)
		}
	}
}

// A launch sends the network mode of the node. Before this change the mode
// and each CIDR and port range were dropped.
func TestSetecClient_LaunchSendsTheNetworkMode(t *testing.T) {
	rec := &launchingSetec{}
	c := &setecClient{inner: rec}
	if _, err := c.Launch(context.Background(), sandboxed.LaunchRequest{
		Tenant: "acme", SandboxClass: "standard", Image: "img", NetworkMode: sandboxed.NetworkModeNone,
	}); err != nil {
		t.Fatalf("Launch: %v", err)
	}
	if rec.launch.GetNetwork().GetMode() != sandboxed.NetworkModeNone {
		t.Errorf("launch network = %v, want mode none", rec.launch.GetNetwork())
	}
}
