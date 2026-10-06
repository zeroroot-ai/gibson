// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package sandboxed

import (
	"context"
	"errors"
	"sync"
	"testing"

	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// tenantClient records the tenant of each setec call (ADR-0142, gibson#756).
type tenantClient struct {
	mu    sync.Mutex
	calls []string // "launch:acme", "wait:acme", ...
}

func (c *tenantClient) note(call, tenant string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, call+":"+tenant)
}

func (c *tenantClient) Launch(_ context.Context, req LaunchRequest) (LaunchResponse, error) {
	c.note("launch", req.Tenant)
	return reportedIsolation(req, LaunchResponse{SandboxID: "sbx-" + req.Tenant}), nil
}

func (c *tenantClient) StreamLogs(_ context.Context, tenant, _ string) (LogStream, error) {
	c.note("logs", tenant)
	return &fixedLogs{chunks: [][]byte{markerLine("ok")}}, nil
}

func (c *tenantClient) Wait(_ context.Context, tenant, _ string) (WaitResponse, error) {
	c.note("wait", tenant)
	return WaitResponse{ExitCode: 0, Reason: "Completed"}, nil
}

func (c *tenantClient) Kill(_ context.Context, tenant, _ string) error {
	c.note("kill", tenant)
	return nil
}

func (c *tenantClient) seen() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.calls...)
}

func assertOnlyTenant(t *testing.T, calls []string, tenant string) {
	t.Helper()
	if len(calls) == 0 {
		t.Fatal("no setec call was made")
	}
	for _, call := range calls {
		if call[len(call)-len(tenant):] != tenant {
			t.Errorf("call %q does not name tenant %q", call, tenant)
		}
	}
}

// Two tenants send two different tenant values on every setec call of a
// tool run.
func TestExecute_EachCallNamesTheTenantOfTheCaller(t *testing.T) {
	for _, tenant := range []string{"acme", "globex"} {
		c := &tenantClient{}
		spec := helloSpec
		spec.Live = LiveScope{Tenant: tenant}
		var out wrapperspb.StringValue
		if err := newExecutor(t, c).ExecuteWithSpec(context.Background(), "hello", spec, wrapperspb.String("in"), &out); err != nil {
			t.Fatalf("%s: ExecuteWithSpec: %v", tenant, err)
		}
		assertOnlyTenant(t, c.seen(), tenant)
	}
}

// A tool call with no tenant does not launch.
func TestExecute_NoTenantDoesNotLaunch(t *testing.T) {
	c := &tenantClient{}
	spec := helloSpec
	spec.Live = LiveScope{}
	err := newExecutor(t, c).ExecuteWithSpec(context.Background(), "hello", spec, wrapperspb.String("in"), &wrapperspb.StringValue{})
	var gerr *types.GibsonError
	if !errors.As(err, &gerr) || gerr.Code != types.SANDBOX_POLICY_DENIED {
		t.Fatalf("err = %v; want SANDBOX_POLICY_DENIED", err)
	}
	if len(c.seen()) != 0 {
		t.Fatalf("setec calls = %v; want none", c.seen())
	}
}

// Two tenants send two different tenant values on every setec call of an
// agent run.
func TestLaunchAgent_EachCallNamesTheTenantOfTheDispatch(t *testing.T) {
	for _, tenant := range []string{"acme", "globex"} {
		c := &tenantClient{}
		if _, err := newAgentLauncher(t, c).LaunchAgent(context.Background(), agentSpec, AgentDispatch{Tenant: tenant}); err != nil {
			t.Fatalf("%s: LaunchAgent: %v", tenant, err)
		}
		assertOnlyTenant(t, c.seen(), tenant)
	}
}

// An agent dispatch with no tenant does not launch.
func TestLaunchAgent_NoTenantDoesNotLaunch(t *testing.T) {
	c := &tenantClient{}
	if _, err := newAgentLauncher(t, c).LaunchAgent(context.Background(), agentSpec, AgentDispatch{}); err == nil {
		t.Fatal("want an error for a dispatch with no tenant")
	}
	if len(c.seen()) != 0 {
		t.Fatalf("setec calls = %v; want none", c.seen())
	}
}

// A member dispatch with no tenant does not launch.
func TestLaunchMember_NoTenantDoesNotLaunch(t *testing.T) {
	c := &tenantClient{}
	if _, err := newAgentLauncher(t, c).LaunchMember(context.Background(), memberSpec(), AgentDispatch{}); err == nil {
		t.Fatal("want an error for a dispatch with no tenant")
	}
	if len(c.seen()) != 0 {
		t.Fatalf("setec calls = %v; want none", c.seen())
	}
}
