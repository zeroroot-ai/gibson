// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package mintgrants

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/modelclient"
	"github.com/zeroroot-ai/gibson/internal/platform/capabilitygrant"
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/modelcall"
)

var testCaller = modelclient.Caller{Tenant: "acme", Mission: "m1", Task: "t1", Initiator: "user:u1", Purpose: "brain-decider"}

type fakeMinter struct {
	got  capabilitygrant.MintRequest
	call capabilitygrant.DaemonCallRequest
}

func (m *fakeMinter) MintDaemonCall(r capabilitygrant.DaemonCallRequest) (string, error) {
	m.call = r
	return "daemon-call", nil
}

func (m *fakeMinter) Mint(r capabilitygrant.MintRequest) (string, error) {
	m.got = r
	return "signed", nil
}

func TestMinterGrants(t *testing.T) {
	m := &fakeMinter{}
	g, err := New(m)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := g.Grant(context.Background(), testCaller)
	if err != nil || tok != "signed" {
		t.Fatalf("Grant = %q, %v", tok, err)
	}
	r := m.got
	if r.Tenant != "acme" || r.MissionID != "m1" || r.TaskID != "t1" || r.Initiator != "user:u1" {
		t.Errorf("mint request = %+v", r)
	}
	// A task grant lists the two call routes. The list route has its own
	// daemon call grant, so a task grant never lists it.
	want := map[string]bool{modelcall.RouteResponses: true, modelcall.RouteEmbeddings: true}
	if len(r.AllowedRPCs) != len(want) {
		t.Errorf("allowed = %v", r.AllowedRPCs)
	}
	for _, p := range r.AllowedRPCs {
		if !want[p] {
			t.Errorf("the grant lists %q", p)
		}
	}
	if r.TTL <= 0 || r.TTL > grantTTL {
		t.Errorf("ttl = %v", r.TTL)
	}
	// A call with no mission gets a daemon call grant of the purpose.
	tok, err = g.Grant(context.Background(), modelclient.Caller{
		Tenant: "acme", Purpose: modelcall.PurposeChat, Initiator: "user:u2",
	})
	if err != nil || tok != "daemon-call" {
		t.Fatalf("daemon call grant = %q, %v", tok, err)
	}
	if m.call.Tenant != "acme" || m.call.Purpose != "chat" || m.call.Initiator != "user:u2" {
		t.Errorf("daemon call request = %+v", m.call)
	}
	// A purpose outside the set, or half a mission scope, gets no grant.
	if _, err := g.Grant(context.Background(), modelclient.Caller{Tenant: "acme", Purpose: "brain-decider"}); !errors.Is(err, ErrNoGrantScope) {
		t.Errorf("a made-up purpose: %v", err)
	}
	if _, err := g.Grant(context.Background(), modelclient.Caller{Tenant: "acme", Mission: "m", Purpose: "x"}); !errors.Is(err, ErrNoGrantScope) {
		t.Errorf("a mission with no task: %v", err)
	}
}
