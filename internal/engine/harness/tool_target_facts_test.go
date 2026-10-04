// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/harness/sandboxed"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// gibson#485: the tool path did not know its target at all. `grep TargetID`
// over internal/engine/tool and internal/engine/harness/sandboxed was empty, so
// a tool could act only on what the mission author typed into its input.

// stubTargetFacts answers one target by id and records what was asked for.
type stubTargetFacts struct {
	byID map[string]*types.Target
	err  error
	// asked is the id the dispatch path actually looked up. The fan-out test
	// turns on this: it must be the INSTANCE's id, not the primary's.
	asked string
}

func (s *stubTargetFacts) Get(_ context.Context, id types.ID) (*types.Target, error) {
	s.asked = id.String()
	if s.err != nil {
		return nil, s.err
	}
	return s.byID[id.String()], nil
}

func harnessWithFacts(target TargetInfo, facts TargetFactsLookup) *DefaultAgentHarness {
	return &DefaultAgentHarness{
		targetInfo:  target,
		targetFacts: facts,
		logger:      slog.New(slog.DiscardHandler),
	}
}

// The happy path: a tool is told what it is acting against, from the store.
func TestAddTargetFacts_TellsTheToolItsTarget(t *testing.T) {
	id := types.NewID()
	stub := &stubTargetFacts{byID: map[string]*types.Target{
		id.String(): {ID: id, Name: "goat", Type: "kubernetes", URL: "https://10.0.0.1:6443"},
	}}
	h := harnessWithFacts(TargetInfo{ID: id}, stub)

	spec := sandboxed.ToolSpec{Env: map[string]string{"GIBSON_TOOL_NAME": "kube-bench"}}
	h.addTargetFacts(context.Background(), &spec)

	for k, want := range map[string]string{
		"GIBSON_TOOL_NAME":     "kube-bench", // not clobbered
		"GIBSON_TARGET_ID":     id.String(),
		"GIBSON_TARGET_NAME":   "goat",
		"GIBSON_TARGET_TYPE":   "kubernetes",
		"GIBSON_TARGET_HOST":   "10.0.0.1:6443",
		"GIBSON_TARGET_DOMAIN": "10.0.0.1",
	} {
		if got := spec.Env[k]; got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
}

// THE REGRESSION THIS EXISTS FOR. A fan-out instance's harness answers Target()
// with the instance's id and the PRIMARY's name and URL, because ForTarget
// swaps only the id — deliberately, since nothing reading it for scope needs
// the rest. Deriving the tool's facts from that view would pair the instance's
// id with another target's host, and the tool would scan the wrong machine and
// report a clean result for it. The facts must come from the STORE, by id.
func TestAddTargetFacts_ResolvesTheInstanceTargetNotThePrimary(t *testing.T) {
	primary := types.NewID()
	instance := types.NewID()
	stub := &stubTargetFacts{byID: map[string]*types.Target{
		primary.String():  {ID: primary, Name: "primary", URL: "https://10.0.0.1:6443"},
		instance.String(): {ID: instance, Name: "second", URL: "https://10.0.0.2:6443"},
	}}

	// Exactly the shape ForTarget produces: the instance id beside the
	// primary's name and URL.
	h := harnessWithFacts(TargetInfo{
		ID:   instance,
		Name: "primary",
		URL:  "https://10.0.0.1:6443",
	}, stub)

	spec := sandboxed.ToolSpec{}
	h.addTargetFacts(context.Background(), &spec)

	if stub.asked != instance.String() {
		t.Errorf("looked up %q, want the instance %q", stub.asked, instance)
	}
	if got := spec.Env["GIBSON_TARGET_HOST"]; got != "10.0.0.2:6443" {
		t.Errorf("GIBSON_TARGET_HOST = %q, want the instance's host 10.0.0.2:6443 — "+
			"the tool was handed the primary's host beside the instance's id", got)
	}
	if got := spec.Env["GIBSON_TARGET_NAME"]; got != "second" {
		t.Errorf("GIBSON_TARGET_NAME = %q, want the instance's name", got)
	}
}

// Every failure is silent and TOTAL. A partial or empty set is worse than none:
// a tool cannot tell "this target has no host" from "the platform did not tell
// me", and the two call for opposite behaviour.
func TestAddTargetFacts_FailsClosedAndTotally(t *testing.T) {
	id := types.NewID()

	cases := map[string]*DefaultAgentHarness{
		"no lookup wired": harnessWithFacts(TargetInfo{ID: id}, nil),
		"no target id":    harnessWithFacts(TargetInfo{}, &stubTargetFacts{}),
		"store errors": harnessWithFacts(TargetInfo{ID: id},
			&stubTargetFacts{err: errors.New("redis is down")}),
		"target is gone": harnessWithFacts(TargetInfo{ID: id},
			&stubTargetFacts{byID: map[string]*types.Target{}}),
	}

	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			spec := sandboxed.ToolSpec{Env: map[string]string{"GIBSON_TOOL_NAME": "kube-bench"}}
			h.addTargetFacts(context.Background(), &spec)

			for k := range spec.Env {
				if k != "GIBSON_TOOL_NAME" {
					t.Errorf("env carries %q; a failed lookup must add nothing at all", k)
				}
			}
		})
	}
}

// A nil Env map must not panic — a manifest tool with no env reaches here.
func TestAddTargetFacts_AllocatesANilEnv(t *testing.T) {
	id := types.NewID()
	stub := &stubTargetFacts{byID: map[string]*types.Target{
		id.String(): {ID: id, Name: "goat"},
	}}
	h := harnessWithFacts(TargetInfo{ID: id}, stub)

	spec := sandboxed.ToolSpec{} // Env is nil
	h.addTargetFacts(context.Background(), &spec)

	if spec.Env["GIBSON_TARGET_NAME"] != "goat" {
		t.Errorf("a nil Env was not allocated; got %v", spec.Env)
	}
}

// resolveTargetFacts tolerates an unset provider, like resolveGraphRAG: a
// daemon that wires no target store must build a harness, not fail.
func TestResolveTargetFacts(t *testing.T) {
	if got := resolveTargetFacts(nil); got != nil {
		t.Errorf("a nil provider returned %T, want nil", got)
	}

	stub := &stubTargetFacts{}
	if got := resolveTargetFacts(func() TargetFactsLookup { return stub }); got != stub {
		t.Error("the provider's value was not used")
	}

	// A provider that itself returns nil is the daemon's no-Redis case and must
	// stay nil, or the harness nil check passes and dispatch panics.
	if got := resolveTargetFacts(func() TargetFactsLookup { return nil }); got != nil {
		t.Errorf("a provider returning nil produced %T, want nil", got)
	}
}

// A target that resolves but answers nothing adds nothing. Reachable with a
// malformed stored record: looked up by a real id, returned with a zero ID and
// no name, type or URL. Exporting GIBSON_TARGET_* keys with empty values would
// tell a tool its target has no host, which is not the same as not knowing.
func TestAddTargetFacts_ATargetWithNoFactsAddsNothing(t *testing.T) {
	id := types.NewID()
	stub := &stubTargetFacts{byID: map[string]*types.Target{
		id.String(): {}, // zero ID, no name, no type, no URL
	}}
	h := harnessWithFacts(TargetInfo{ID: id}, stub)

	spec := sandboxed.ToolSpec{Env: map[string]string{"GIBSON_TOOL_NAME": "kube-bench"}}
	h.addTargetFacts(context.Background(), &spec)

	if len(spec.Env) != 1 {
		t.Errorf("env = %v, want only GIBSON_TOOL_NAME", spec.Env)
	}
}
