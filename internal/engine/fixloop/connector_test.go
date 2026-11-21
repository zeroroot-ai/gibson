// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package fixloop

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/catalog"
)

// fakeMCP is the tool list of the daemon. It has no way to call a tool, so a
// test that passes shows that each call took the governed path.
type fakeMCP struct {
	tools   []catalog.ToolEntry
	tenants []string
}

func (f *fakeMCP) ListConnectorTools(_ context.Context, tenant string) ([]catalog.ToolEntry, error) {
	f.tenants = append(f.tenants, tenant)
	return f.tools, nil
}

// Each read of the fix loop takes the governed path, with the mission of the
// fix (ADR-0065, review M8).
func TestConnectorReader_MergeRequest(t *testing.T) {
	f := &fakeMCP{tools: []catalog.ToolEntry{{Connector: "gitlab", Tool: ToolMergeRequestState}}}
	w := &fakeTenantCaller{result: map[string]any{
		"state": "open", "pipeline_green": true, "at": "2026-11-20T08:00:00Z",
		"created_at": "2026-11-20T07:00:00Z", "source_branch": "job/j-1",
	}}
	got, err := NewConnectorReader(f, w).MergeRequest(context.Background(), "t1", "run-9", "mr-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.State != MROpen || !got.PipelineGreen || !got.At.Equal(t0) ||
		!got.CreatedAt.Equal(t0.Add(-time.Hour)) || got.SourceBranch != "job/j-1" {
		t.Fatalf("fact = %+v", got)
	}
	if len(w.calls) != 1 || w.calls[0] != "t1/run-9/gitlab/merge_request_state/mr-1" {
		t.Fatalf("governed calls = %v", w.calls)
	}
	for _, tn := range f.tenants {
		if tn != "t1" {
			t.Fatalf("tenant = %q, want t1", tn)
		}
	}
}

func TestConnectorReader_UnknownStateIsAnError(t *testing.T) {
	f := &fakeMCP{tools: []catalog.ToolEntry{{Connector: "gitlab", Tool: ToolMergeRequestState}}}
	w := &fakeTenantCaller{result: map[string]any{"state": "approved"}}
	if _, err := NewConnectorReader(f, w).MergeRequest(context.Background(), "t1", "", "mr-1"); err == nil {
		t.Fatal("want an error for an unknown state")
	}
}

func TestConnectorReader_NoConnector(t *testing.T) {
	_, err := NewConnectorReader(&fakeMCP{}, &fakeTenantCaller{}).Health(context.Background(), "t1", "", "app", t0, time.Minute)
	if !errors.Is(err, ErrNoConnector) {
		t.Fatalf("err = %v, want ErrNoConnector", err)
	}
}

func TestConnectorReader_DeployAndHealth(t *testing.T) {
	f := &fakeMCP{
		tools: []catalog.ToolEntry{
			{Connector: "argo", Tool: ToolDeploymentState}, {Connector: "prom", Tool: ToolHealthSignal},
		},
	}
	w := &fakeTenantCaller{
		result: map[string]any{
			"deployed": true, "deployment": "d1", "application": "a1", "at": "2026-11-20T09:00:00Z",
			"known": true, "done": true, "held": true,
			"restart": map[string]any{"needed": true, "started": "2026-11-20T09:00:00Z"},
		},
	}
	r := NewConnectorReader(f, w)
	d, err := r.Deploy(context.Background(), "t1", "run-9", "mr-1")
	if err != nil || !d.Deployed || d.ApplicationKey != "a1" || !d.Restart.Needed || !d.Restart.Ended.IsZero() {
		t.Fatalf("deploy = %+v, %v", d, err)
	}
	h, err := r.Health(context.Background(), "t1", "run-9", "a1", t0, time.Minute)
	if err != nil || !h.Known || !h.Done || !h.Held {
		t.Fatalf("health = %+v, %v", h, err)
	}
	if len(w.calls) != 2 || w.calls[0] != "t1/run-9/argo/deployment_state/mr-1" || w.calls[1] != "t1/run-9/prom/health_signal/" {
		t.Fatalf("governed calls = %v", w.calls)
	}
}

// With no governed caller, no connector call runs.
func TestConnectorReader_NoGovernedCallerNoCall(t *testing.T) {
	f := &fakeMCP{tools: []catalog.ToolEntry{{Connector: "gitlab", Tool: ToolMergeRequestState}}}
	if _, err := NewConnectorReader(f, nil).MergeRequest(context.Background(), "t1", "", "mr-1"); err == nil {
		t.Fatal("want an error with no governed caller")
	}
}

type fakeTenantCaller struct {
	calls  []string
	result any
}

func (f *fakeTenantCaller) CallConnectorForTenant(
	_ context.Context, tenant, missionID, connector, tool string, args map[string]any,
) (any, error) {
	mr, _ := args["merge_request"].(string)
	f.calls = append(f.calls, tenant+"/"+missionID+"/"+connector+"/"+tool+"/"+mr)
	return f.result, nil
}

// The revert goes through the governed caller, never the plain MCP client,
// with the mission of the fix (gibson#1465). The result says if the revert
// merged.
func TestConnectorReader_RevertTakesTheGovernedPath(t *testing.T) {
	mcp := &fakeMCP{tools: []catalog.ToolEntry{{Connector: "gitlab-fixloop", Tool: ToolRevertMergeRequest}}}
	w := &fakeTenantCaller{result: map[string]any{"merged": false, "revert_merge_request": "g/p!13"}}
	fact, err := NewConnectorReader(mcp, w).Revert(context.Background(), "t1", "g/p!12", "run-9")
	if err != nil {
		t.Fatal(err)
	}
	if fact.Merged || fact.RevertMergeRequest != "g/p!13" {
		t.Fatalf("fact = %+v", fact)
	}
	if len(w.calls) != 1 || w.calls[0] != "t1/run-9/gitlab-fixloop/revert_merge_request/g/p!12" {
		t.Fatalf("governed calls = %v", w.calls)
	}
	if _, err := NewConnectorReader(mcp, nil).Revert(context.Background(), "t1", "g/p!12", ""); err == nil {
		t.Fatal("want an error with no governed caller")
	}
}
