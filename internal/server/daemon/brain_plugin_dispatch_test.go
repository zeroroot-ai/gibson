// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	gibsonharness "github.com/zeroroot-ai/gibson/internal/engine/harness"
)

// pluginHarness is an AgentHarness that only answers QueryPlugin. Like
// toolHarness, every other call panics on the nil embedded interface, so an
// unexpected harness call fails the test instead of passing silently.
type pluginHarness struct {
	gibsonharness.AgentHarness

	gotName   string
	gotMethod string
	gotParams map[string]any

	result any
	err    error

	forTargetID string
}

func (h *pluginHarness) ForTarget(targetID string) gibsonharness.AgentHarness {
	h.forTargetID = targetID
	return h
}

func (h *pluginHarness) QueryPlugin(_ context.Context, name, method string, params map[string]any) (any, error) {
	h.gotName = name
	h.gotMethod = method
	h.gotParams = params
	return h.result, h.err
}

// The dispatched payload carries the node's method and its declared params,
// typed the way the projection typed them (gibson#556).
func TestDispatchPlugin_CarriesMethodAndParams(t *testing.T) {
	h := &pluginHarness{result: map[string]any{"issues": 3}}
	b := newBrainExecutor(nil, slog.Default())
	bind := &missionBinding{ctx: context.Background(), harness: h}

	input, err := pluginInputJSON("Scan", map[string]string{"depth": "2", "scope": `{"hosts":["a"]}`})
	if err != nil {
		t.Fatalf("pluginInputJSON: %v", err)
	}
	out, err := b.dispatchPlugin(bind, brain.DispatchRequest{
		WorkID: "w1",
		Kind:   "plugin",
		Target: "burp",
		Input:  input,
	})
	if err != nil {
		t.Fatalf("dispatchPlugin: %v", err)
	}
	if h.gotName != "burp" {
		t.Errorf("plugin name = %q, want burp", h.gotName)
	}
	if h.gotMethod != "Scan" {
		t.Errorf("method = %q, want Scan", h.gotMethod)
	}
	if got, ok := h.gotParams["depth"].(string); !ok || got != "2" {
		t.Errorf("params.depth = %#v, want the string \"2\"", h.gotParams["depth"])
	}
	scope, ok := h.gotParams["scope"].(map[string]any)
	if !ok {
		t.Fatalf("params.scope = %#v, want the decoded object", h.gotParams["scope"])
	}
	if hosts, _ := scope["hosts"].([]any); len(hosts) != 1 || hosts[0] != "a" {
		t.Errorf("params.scope.hosts = %#v, want [a]", scope["hosts"])
	}
	if out != `{"issues":3}` {
		t.Errorf("result = %q, want the plugin's result as JSON", out)
	}
	if h.forTargetID != "" {
		t.Errorf("a non-instance work id re-scoped the harness to %q", h.forTargetID)
	}
}

// A plugin node with no params dispatches with the method alone.
func TestDispatchPlugin_NoParams(t *testing.T) {
	h := &pluginHarness{result: "ok"}
	b := newBrainExecutor(nil, slog.Default())
	bind := &missionBinding{ctx: context.Background(), harness: h}

	out, err := b.dispatchPlugin(bind, brain.DispatchRequest{
		WorkID: "w1", Kind: "plugin", Target: "burp", Input: `{"method":"Scan"}`,
	})
	if err != nil {
		t.Fatalf("dispatchPlugin: %v", err)
	}
	if h.gotMethod != "Scan" || len(h.gotParams) != 0 {
		t.Errorf("dispatched method=%q params=%v, want Scan with no params", h.gotMethod, h.gotParams)
	}
	if out != `"ok"` {
		t.Errorf("result = %q, want \"ok\"", out)
	}
}

// A for_each instance dispatches against its own target, as a tool node does.
func TestDispatchPlugin_InstanceRescopesHarness(t *testing.T) {
	h := &pluginHarness{}
	b := newBrainExecutor(nil, slog.Default())
	bind := &missionBinding{ctx: context.Background(), harness: h}

	const target = "0f3f1a2e-6a1b-4c1d-9e2f-0123456789ab"
	if _, err := b.dispatchPlugin(bind, brain.DispatchRequest{
		WorkID: "scan#" + target, Kind: "plugin", Target: "burp", Input: `{"method":"Scan"}`,
	}); err != nil {
		t.Fatalf("dispatchPlugin: %v", err)
	}
	if h.forTargetID != target {
		t.Errorf("harness re-scoped to %q, want %q", h.forTargetID, target)
	}
}

func TestDispatchPlugin_Refusals(t *testing.T) {
	b := newBrainExecutor(nil, slog.Default())
	cases := map[string]struct {
		req  brain.DispatchRequest
		h    *pluginHarness
		want string
	}{
		"no plugin name": {
			req:  brain.DispatchRequest{WorkID: "w", Kind: "plugin", Input: `{"method":"Scan"}`},
			h:    &pluginHarness{},
			want: "no plugin name",
		},
		"input is not json": {
			req:  brain.DispatchRequest{WorkID: "w", Kind: "plugin", Target: "burp", Input: "Scan"},
			h:    &pluginHarness{},
			want: "decode node input",
		},
		"no method": {
			req:  brain.DispatchRequest{WorkID: "w", Kind: "plugin", Target: "burp", Input: `{"params":{}}`},
			h:    &pluginHarness{},
			want: "names no method",
		},
		"plugin error": {
			req:  brain.DispatchRequest{WorkID: "w", Kind: "plugin", Target: "burp", Input: `{"method":"Scan"}`},
			h:    &pluginHarness{err: errors.New("boom")},
			want: `plugin "burp".Scan: boom`,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			bind := &missionBinding{ctx: context.Background(), harness: tc.h}
			_, err := b.dispatchPlugin(bind, tc.req)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

// Dispatch routes a plugin kind through the harness and completes the work
// with the plugin's result. Before gibson#556 the kind fell into the "not
// supported" refusal and the node failed by name.
func TestDispatch_PluginNodeCompletesThroughTheHarness(t *testing.T) {
	h := &pluginHarness{result: map[string]any{"ok": true}}
	wc := dispatchOutcome(t, h, brain.DispatchRequest{
		WorkID: "w1", Kind: "plugin", Target: "burp",
		Input: `{"method":"Scan","params":{"depth":2}}`,
	})
	if wc.Err != "" {
		t.Fatalf("plugin work failed: %s", wc.Err)
	}
	if wc.Result != `{"ok":true}` {
		t.Errorf("result = %q, want the plugin's result as JSON", wc.Result)
	}
	if h.gotName != "burp" || h.gotMethod != "Scan" {
		t.Errorf("harness saw plugin=%q method=%q, want burp/Scan", h.gotName, h.gotMethod)
	}
	if got, _ := h.gotParams["depth"].(float64); got != 2 {
		t.Errorf("params.depth = %#v, want 2", h.gotParams["depth"])
	}
}
