// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build setec_integration

package daemon

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"

	"github.com/zeroroot-ai/gibson/internal/engine/harness/sandboxed"
	setecv1 "github.com/zeroroot-ai/setec/api/grpc/v1"
)

// recordingSetec records the tenant of each request it gets. The embedded
// interface panics on a call this test does not expect.
type recordingSetec struct {
	setecv1.SandboxServiceClient
	tenants []string
}

func (r *recordingSetec) Launch(_ context.Context, in *setecv1.LaunchRequest, _ ...grpc.CallOption) (*setecv1.LaunchResponse, error) {
	r.tenants = append(r.tenants, in.GetTenant())
	return &setecv1.LaunchResponse{SandboxId: "sbx-1", SandboxClass: in.GetSandboxClass(), Runtime: "launcher"}, nil
}

func (r *recordingSetec) Wait(_ context.Context, in *setecv1.WaitRequest, _ ...grpc.CallOption) (*setecv1.WaitResponse, error) {
	r.tenants = append(r.tenants, in.GetTenant())
	return &setecv1.WaitResponse{}, nil
}

func (r *recordingSetec) Kill(_ context.Context, in *setecv1.KillRequest, _ ...grpc.CallOption) (*setecv1.KillResponse, error) {
	r.tenants = append(r.tenants, in.GetTenant())
	return &setecv1.KillResponse{}, nil
}

// Each setec request names the tenant of the caller (ADR-0142, gibson#756),
// and a call with no tenant is refused before it reaches setec.
func TestSetecClient_EachRequestNamesTheTenant(t *testing.T) {
	ctx := context.Background()
	rec := &recordingSetec{}
	c := &setecClient{inner: rec}

	if _, err := c.Launch(ctx, sandboxed.LaunchRequest{Tenant: "acme", SandboxClass: "standard", Image: "img"}); err != nil {
		t.Fatalf("Launch: %v", err)
	}
	if _, err := c.Wait(ctx, "acme", "sbx-1"); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if err := c.Kill(ctx, "acme", "sbx-1"); err != nil {
		t.Fatalf("Kill: %v", err)
	}
	if len(rec.tenants) != 3 {
		t.Fatalf("setec got %d requests, want 3", len(rec.tenants))
	}
	for i, got := range rec.tenants {
		if got != "acme" {
			t.Errorf("request %d: tenant = %q, want acme", i, got)
		}
	}

	if _, err := c.Launch(ctx, sandboxed.LaunchRequest{SandboxClass: "standard", Image: "img"}); !errors.Is(err, errNoTenant) {
		t.Errorf("Launch with no tenant: err = %v", err)
	}
	if _, err := c.Wait(ctx, "", "sbx-1"); !errors.Is(err, errNoTenant) {
		t.Errorf("Wait with no tenant: err = %v", err)
	}
	if err := c.Kill(ctx, "", "sbx-1"); !errors.Is(err, errNoTenant) {
		t.Errorf("Kill with no tenant: err = %v", err)
	}
	if _, err := c.StreamLogs(ctx, "", "sbx-1"); !errors.Is(err, errNoTenant) {
		t.Errorf("StreamLogs with no tenant: err = %v", err)
	}
	if _, err := c.Exec(ctx, "", "sbx-1", []string{"true"}); !errors.Is(err, errNoTenant) {
		t.Errorf("Exec with no tenant: err = %v", err)
	}
	if _, err := c.LaunchSession(ctx, sandboxed.SessionLaunchRequest{SandboxClass: "standard", Idle: 1}); !errors.Is(err, errNoTenant) {
		t.Errorf("LaunchSession with no tenant: err = %v", err)
	}
	if len(rec.tenants) != 3 {
		t.Errorf("a refused call reached setec: %d requests", len(rec.tenants))
	}
}

// TestSetecClient_LaunchCopiesTheReportedIsolation: the adapter hands the
// class and the runtime that setec reports to the isolation check, so a
// launch with no reported runtime is refused there.
func TestSetecClient_LaunchCopiesTheReportedIsolation(t *testing.T) {
	c := &setecClient{inner: &recordingSetec{}}
	resp, err := c.Launch(context.Background(), sandboxed.LaunchRequest{Tenant: "acme", SandboxClass: "standard", Image: "img"})
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	if resp.SandboxClass != "standard" || resp.Runtime != "launcher" {
		t.Fatalf("launch response = %+v, want the class and the runtime that setec reported", resp)
	}
	if err := sandboxed.VerifyIsolation("standard", resp); err != nil {
		t.Fatalf("VerifyIsolation of a reported launcher sandbox: %v", err)
	}
}
