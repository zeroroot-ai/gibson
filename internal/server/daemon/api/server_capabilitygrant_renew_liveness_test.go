// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	gibsontypes "github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/capabilitygrant"
	daemonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"
	"github.com/zeroroot-ai/sdk/auth"
	sdkcg "github.com/zeroroot-ai/sdk/capabilitygrant"
)

// A task grant is scoped to one mission run. Renewing it past the end of that
// run turns a task-scoped credential into a standing one, so renewal is gated
// on the run still executing (gibson#1602). These tests pin that gate, including
// the case where the gate itself is unwired — which must refuse, not renew.

type fakeKeyProvider struct{}

func (fakeKeyProvider) GetEncryptionKey(context.Context) ([]byte, error) {
	return []byte("0123456789abcdef0123456789abcdef"), nil
}
func (fakeKeyProvider) Name() string { return "test" }
func (fakeKeyProvider) Health(context.Context) gibsontypes.HealthStatus {
	return gibsontypes.HealthStatus{}
}
func (fakeKeyProvider) Close() error { return nil }

// stubVerifier returns fixed claims, so a test drives the liveness gate without
// minting and re-verifying a real token first.
type stubVerifier struct {
	claims sdkcg.Claims
	err    error
}

func (v stubVerifier) Verify(context.Context, string) (sdkcg.Claims, error) {
	return v.claims, v.err
}

// liveLookup answers the run-liveness question from a fixed set.
type liveLookup struct{ live map[string]bool }

func (l liveLookup) IsMissionLive(missionID string) bool { return l.live[missionID] }

func renewTestClaims() sdkcg.Claims {
	return sdkcg.Claims{
		Subject:     "component:agent:zerocool",
		MissionID:   "m1",
		TaskID:      "run-1",
		AllowedRPCs: []string{"/gibson.harness.v1.HarnessCallbackService/Observe"},
		Tenant:      mustTenant("acme"),
	}
}

func mustTenant(s string) auth.TenantID {
	t, err := auth.NewTenantID(s)
	if err != nil {
		panic(err)
	}
	return t
}

func renewRequest() *daemonpb.RenewCapabilityGrantRequest {
	return &daemonpb.RenewCapabilityGrantRequest{
		AgentId:   "component:agent:zerocool",
		MissionId: "m1",
		TaskId:    "run-1",
	}
}

func renewCtx() context.Context {
	return metadata.NewIncomingContext(context.Background(),
		metadata.Pairs("x-capability-grant", "a-verified-token"))
}

func newRenewServer(t *testing.T, lookup LiveMissionLookup) *DaemonServer {
	t.Helper()
	m, err := capabilitygrant.NewMinter(context.Background(), capabilitygrant.Config{
		Issuer:      "gibson-test",
		Audience:    "gibson-harness",
		KeyID:       "k1",
		KeyProvider: fakeKeyProvider{},
	})
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}
	s := &DaemonServer{}
	s.WithCGRenewal(m, stubVerifier{claims: renewTestClaims()})
	if lookup != nil {
		s.WithLiveMissionLookup(lookup)
	}
	return s
}

func TestRenewCapabilityGrant_RenewsWhileTheRunIsLive(t *testing.T) {
	s := newRenewServer(t, liveLookup{live: map[string]bool{"m1": true}})

	resp, err := s.RenewCapabilityGrant(renewCtx(), renewRequest())
	if err != nil {
		t.Fatalf("a live run must renew: %v", err)
	}
	if resp.GetCapabilityGrant() == "" {
		t.Fatal("want a fresh grant, got an empty one")
	}
}

func TestRenewCapabilityGrant_RefusesOnceTheRunHasEnded(t *testing.T) {
	// This is the whole point of the gate: a worker that outlived its mission,
	// or a token lifted from one, must not be able to refresh itself forever.
	s := newRenewServer(t, liveLookup{live: map[string]bool{}})

	_, err := s.RenewCapabilityGrant(renewCtx(), renewRequest())
	if err == nil {
		t.Fatal("want a refusal after the run ended, got a fresh grant")
	}
	if got := status.Code(err); got != codes.FailedPrecondition {
		t.Fatalf("code = %s, want FailedPrecondition", got)
	}
	if !strings.Contains(err.Error(), "mission run has ended") {
		t.Fatalf("error should say why: %v", err)
	}
}

func TestRenewCapabilityGrant_RefusesWhenTheGateIsUnwired(t *testing.T) {
	// A gate that cannot fail is worse than no gate. With no liveness source
	// there is no way to tell a live run from an ended one, so renewal refuses
	// rather than issuing a grant nothing can end.
	s := newRenewServer(t, nil)

	_, err := s.RenewCapabilityGrant(renewCtx(), renewRequest())
	if err == nil {
		t.Fatal("want a refusal with no liveness source wired, got a fresh grant")
	}
	if got := status.Code(err); got != codes.FailedPrecondition {
		t.Fatalf("code = %s, want FailedPrecondition", got)
	}
	if !strings.Contains(err.Error(), "liveness") {
		t.Fatalf("error should name the missing wiring: %v", err)
	}
}

func TestRenewCapabilityGrant_TheGateRunsAfterTheClaimChecks(t *testing.T) {
	// A caller whose claims do not match its request is denied on the claims, not
	// on liveness: the liveness gate must not become the first line of defence
	// and mask a credential mismatch.
	s := newRenewServer(t, liveLookup{live: map[string]bool{}})

	req := renewRequest()
	req.AgentId = "component:agent:someone-else"

	_, err := s.RenewCapabilityGrant(renewCtx(), req)
	if got := status.Code(err); got != codes.PermissionDenied {
		t.Fatalf("code = %s, want PermissionDenied from the claim cross-check", got)
	}
}
