// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package metatool

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/catalog"
	"github.com/zeroroot-ai/gibson/internal/platform/agentskillstore"
)

// fakeSkills serves one Agent Skill. It records each call.
type fakeSkills struct {
	digest   string
	resolved []string
	loads    int
	reads    []string
	allowed  []string
}

func (f *fakeSkills) Resolve(_ context.Context, tenant, mission, name string) (string, error) {
	f.resolved = append(f.resolved, tenant+"|"+mission+"|"+name)
	return f.digest, nil
}

func (f *fakeSkills) Load(_ context.Context, _, name, digest string) (*agentskillstore.Loaded, error) {
	f.loads++
	return &agentskillstore.Loaded{
		Entry: agentskillstore.Entry{Name: name, Digest: digest, Description: "map a target", AllowedTools: f.allowed},
		Body:  "# Steps\nRun httpx.",
		Files: []agentskillstore.FileInfo{{Path: "references/a.md", Size: 5}},
	}, nil
}

func (f *fakeSkills) ReadFile(_ context.Context, _, _, digest, path string) ([]byte, error) {
	f.reads = append(f.reads, digest+"|"+path)
	if path != "references/a.md" {
		return nil, fmt.Errorf("%w: %s", agentskillstore.ErrNotFound, path)
	}
	return []byte("guide"), nil
}

func noRecord(context.Context, SkillLoad) error { return nil }

var skillCaller = catalog.Caller{
	Subject: "user:alice", Tenant: "acme", Agent: "agent_principal:a1", Mission: "m1",
}

func skillCall(obs *seqObserver, args map[string]any, policy MissionPolicy) Call {
	return Call{
		Caller: skillCaller, ID: "skill:web-recon", Args: args, Policy: policy, RunID: "r1",
		Observer: obs, Recorder: obs.record,
	}
}

func TestCall_SkillReturnsTheBodyByDigest(t *testing.T) {
	obs := &seqObserver{}
	store := &fakeSkills{digest: "sha256:aa", allowed: []string{"native:nmap"}}
	var loads []SkillLoad
	h := NewHandler(nil, allowAll("skill:web-recon"), nil).
		WithSkills(store, func(_ context.Context, l SkillLoad) error { loads = append(loads, l); return nil })

	got, err := h.Call(context.Background(), skillCall(obs, nil, MissionPolicy{}))
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	res, ok := got.(SkillResult)
	if !ok || res.Digest != "sha256:aa" || res.Body != "# Steps\nRun httpx." || len(res.Files) != 1 {
		t.Fatalf("result = %#v", got)
	}
	// The digest comes from the pin of the mission.
	if len(store.resolved) != 1 || store.resolved[0] != "acme|m1|web-recon" {
		t.Errorf("resolved = %v", store.resolved)
	}
	if len(loads) != 1 || loads[0].Digest != "sha256:aa" || loads[0].MissionID != "m1" || loads[0].Agent != "agent_principal:a1" {
		t.Errorf("loads = %+v", loads)
	}
	// There is no connector audit record, and the flight recorder has one.
	for _, e := range obs.events {
		if e == "intent" {
			t.Error("a load of an Agent Skill must write no connector intent record")
		}
	}
	if len(obs.recorded) != 1 || obs.recorded[0] != "skill:web-recon|" {
		t.Errorf("recorded = %v", obs.recorded)
	}
}

// allowed-tools is data in the result. It gives the agent no tool: the result
// has no field that the harness reads as a tool, and a tool call still passes
// its own FGA check.
func TestCall_SkillAllowedToolsAddNoTool(t *testing.T) {
	obs := &seqObserver{}
	store := &fakeSkills{digest: "sha256:aa", allowed: []string{"mcp:gitlab:delete_project"}}
	h := NewHandler(nil, allowAll("skill:web-recon"), nil).WithSkills(store, noRecord)
	if _, err := h.Call(context.Background(), skillCall(obs, nil, MissionPolicy{})); err != nil {
		t.Fatalf("Call: %v", err)
	}
	// The tool that the Agent Skill names is not authorized for the agent.
	_, err := h.Authorize(context.Background(), skillCaller, "mcp:gitlab:delete_project")
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Authorize of a tool in allowed-tools = %v, want ErrUnauthorized", err)
	}
}

func TestCall_SkillRefusedWithNoGrant(t *testing.T) {
	obs := &seqObserver{}
	store := &fakeSkills{digest: "sha256:aa"}
	var loads int
	h := NewHandler(nil, allowAll(), nil).WithSkills(store, func(context.Context, SkillLoad) error { loads++; return nil })
	_, err := h.Call(context.Background(), skillCall(obs, nil, MissionPolicy{}))
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
	if len(store.resolved) != 0 || store.loads != 0 || loads != 0 {
		t.Errorf("the store was read for a caller with no grant: resolved %v, loads %d", store.resolved, store.loads)
	}
	if len(obs.recorded) != 1 {
		t.Errorf("a refused load must still be recorded, got %v", obs.recorded)
	}
}

func TestCall_SkillRefusedWhenTheMissionBlocksIt(t *testing.T) {
	obs := &seqObserver{}
	store := &fakeSkills{digest: "sha256:aa"}
	h := NewHandler(nil, allowAll("skill:web-recon"), nil).WithSkills(store, noRecord)
	_, err := h.Call(context.Background(), skillCall(obs, nil, MissionPolicy{Blocked: []string{"skill:web-recon"}}))
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("err = %v, want ErrBlocked", err)
	}
	if store.loads != 0 || len(store.resolved) != 0 {
		t.Error("the store was read for a blocked Agent Skill")
	}
}

func TestCall_SkillFileArgument(t *testing.T) {
	obs := &seqObserver{}
	store := &fakeSkills{digest: "sha256:aa"}
	h := NewHandler(nil, allowAll("skill:web-recon"), nil).WithSkills(store, noRecord)

	got, err := h.Call(context.Background(), skillCall(obs, map[string]any{"file": "references/a.md"}, MissionPolicy{}))
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if res, ok := got.(SkillFileResult); !ok || res.Content != "guide" || res.Digest != "sha256:aa" {
		t.Fatalf("result = %#v", got)
	}
	if store.loads != 0 {
		t.Error("a file load must not load the body")
	}

	// A path outside the folder is refused before the store is read.
	for _, path := range []string{"../secret", "/etc/passwd", "a/../../b", "a//b", `a\b`} {
		before := len(store.reads)
		_, err := h.Call(context.Background(), skillCall(obs, map[string]any{"file": path}, MissionPolicy{}))
		if !errors.Is(err, ErrSkillPath) {
			t.Errorf("file %q: err = %v, want ErrSkillPath", path, err)
		}
		if len(store.reads) != before {
			t.Errorf("file %q reached the store", path)
		}
	}
	// A path that is clean and not in the folder is refused by the store.
	_, err = h.Call(context.Background(), skillCall(obs, map[string]any{"file": "other.md"}, MissionPolicy{}))
	if !errors.Is(err, agentskillstore.ErrNotFound) {
		t.Errorf("a missing file: err = %v, want ErrNotFound", err)
	}
	_, err = h.Call(context.Background(), skillCall(obs, map[string]any{"file": 7}, MissionPolicy{}))
	if err == nil {
		t.Error("a file argument that is not a string must fail")
	}
}

// A script is run with the skill-script tool. Its text is never served, and the
// store is not read for the request.
func TestCall_SkillScriptIsNotServedAsText(t *testing.T) {
	obs := &seqObserver{}
	store := &fakeSkills{digest: "sha256:aa"}
	h := NewHandler(nil, allowAll("skill:web-recon"), nil).WithSkills(store, noRecord)
	for _, path := range []string{"scripts/probe.sh", "scripts/a/b.py"} {
		before := len(store.reads)
		_, err := h.Call(context.Background(), skillCall(obs, map[string]any{"file": path}, MissionPolicy{}))
		if !errors.Is(err, ErrSkillScript) {
			t.Errorf("file %q: err = %v, want ErrSkillScript", path, err)
		}
		if len(store.reads) != before {
			t.Errorf("file %q reached the store", path)
		}
	}
	// A reference file still loads, and so does a file whose name only starts
	// like the folder.
	for _, path := range []string{"references/a.md", "scripts-notes.md"} {
		if _, err := h.Call(context.Background(), skillCall(obs, map[string]any{"file": path}, MissionPolicy{})); errors.Is(err, ErrSkillScript) {
			t.Errorf("file %q was taken for a script", path)
		}
	}
}

func TestCall_SkillNeedsAMissionAndAStore(t *testing.T) {
	obs := &seqObserver{}
	store := &fakeSkills{digest: "sha256:aa"}
	h := NewHandler(nil, allowAll("skill:web-recon"), nil).WithSkills(store, noRecord)
	c := skillCall(obs, nil, MissionPolicy{})
	c.Caller.Mission = ""
	if _, err := h.Call(context.Background(), c); !errors.Is(err, ErrSkillNeedsMission) {
		t.Errorf("no mission: err = %v, want ErrSkillNeedsMission", err)
	}
	bare := NewHandler(nil, allowAll("skill:web-recon"), nil)
	if _, err := bare.Call(context.Background(), skillCall(obs, nil, MissionPolicy{})); err == nil {
		t.Error("a handler with no store must refuse a skill: id")
	}
}

// No load goes without its record. When the record fails, or no recorder is set,
// the agent gets no content.
func TestCall_SkillRefusedWhenTheLoadCannotBeRecorded(t *testing.T) {
	obs := &seqObserver{}
	store := &fakeSkills{digest: "sha256:aa"}
	boom := errors.New("timeline down")
	h := NewHandler(nil, allowAll("skill:web-recon"), nil).
		WithSkills(store, func(context.Context, SkillLoad) error { return boom })
	got, err := h.Call(context.Background(), skillCall(obs, nil, MissionPolicy{}))
	if !errors.Is(err, boom) || got != nil {
		t.Fatalf("Call = %#v, %v, want no content and the recorder error", got, err)
	}
	none := NewHandler(nil, allowAll("skill:web-recon"), nil).WithSkills(store, nil)
	if _, err := none.Call(context.Background(), skillCall(obs, nil, MissionPolicy{})); err == nil {
		t.Error("a handler with no recorder must refuse a skill: id")
	}
}
