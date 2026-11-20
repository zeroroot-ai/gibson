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

type fakeMCP struct {
	tools   []catalog.ToolEntry
	result  any
	called  []string
	tenants []string
}

func (f *fakeMCP) ListConnectorTools(_ context.Context, tenant string) ([]catalog.ToolEntry, error) {
	f.tenants = append(f.tenants, tenant)
	return f.tools, nil
}

func (f *fakeMCP) CallConnectorTool(_ context.Context, tenant, connector, tool string, _ map[string]any) (any, error) {
	f.tenants = append(f.tenants, tenant)
	f.called = append(f.called, connector+"/"+tool)
	return f.result, nil
}

func TestConnectorReader_MergeRequest(t *testing.T) {
	f := &fakeMCP{
		tools:  []catalog.ToolEntry{{Connector: "gitlab", Tool: ToolMergeRequestState}},
		result: map[string]any{"state": "open", "pipeline_green": true, "at": "2026-11-20T08:00:00Z"},
	}
	got, err := NewConnectorReader(f).MergeRequest(context.Background(), "t1", "mr-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.State != MROpen || !got.PipelineGreen || !got.At.Equal(t0) {
		t.Fatalf("fact = %+v", got)
	}
	if len(f.called) != 1 || f.called[0] != "gitlab/merge_request_state" {
		t.Fatalf("called = %v", f.called)
	}
	for _, tn := range f.tenants {
		if tn != "t1" {
			t.Fatalf("tenant = %q, want t1", tn)
		}
	}
}

func TestConnectorReader_UnknownStateIsAnError(t *testing.T) {
	f := &fakeMCP{
		tools:  []catalog.ToolEntry{{Connector: "gitlab", Tool: ToolMergeRequestState}},
		result: map[string]any{"state": "approved"},
	}
	if _, err := NewConnectorReader(f).MergeRequest(context.Background(), "t1", "mr-1"); err == nil {
		t.Fatal("want an error for an unknown state")
	}
}

func TestConnectorReader_NoConnector(t *testing.T) {
	_, err := NewConnectorReader(&fakeMCP{}).Health(context.Background(), "t1", "app", t0, time.Minute)
	if !errors.Is(err, ErrNoConnector) {
		t.Fatalf("err = %v, want ErrNoConnector", err)
	}
}

func TestConnectorReader_DeployAndHealth(t *testing.T) {
	f := &fakeMCP{
		tools: []catalog.ToolEntry{
			{Connector: "argo", Tool: ToolDeploymentState}, {Connector: "prom", Tool: ToolHealthSignal},
		},
		result: map[string]any{
			"deployed": true, "deployment": "d1", "application": "a1", "at": "2026-11-20T09:00:00Z",
			"known": true, "done": true, "held": true,
			"restart": map[string]any{"needed": true, "started": "2026-11-20T09:00:00Z"},
		},
	}
	r := NewConnectorReader(f)
	d, err := r.Deploy(context.Background(), "t1", "mr-1")
	if err != nil || !d.Deployed || d.ApplicationKey != "a1" || !d.Restart.Needed || !d.Restart.Ended.IsZero() {
		t.Fatalf("deploy = %+v, %v", d, err)
	}
	h, err := r.Health(context.Background(), "t1", "a1", t0, time.Minute)
	if err != nil || !h.Known || !h.Done || !h.Held {
		t.Fatalf("health = %+v, %v", h, err)
	}
}
