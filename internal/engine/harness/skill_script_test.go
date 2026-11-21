// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"strings"
	"testing"

	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"

	"github.com/zeroroot-ai/gibson/internal/engine/harness/sandboxed"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/agentskillstore"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

// fakeSkillFiles serves one Agent Skill version and records what is read.
type fakeSkillFiles struct {
	files    map[string]string
	resolved []string
	reads    []string
	err      error
}

func (f *fakeSkillFiles) Resolve(_ context.Context, tenant, mission, name string) (string, error) {
	f.resolved = append(f.resolved, tenant+"/"+mission+"/"+name)
	return "sha256:pinned", f.err
}

func (f *fakeSkillFiles) Load(_ context.Context, _, name, digest string) (*agentskillstore.Loaded, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := &agentskillstore.Loaded{Entry: agentskillstore.Entry{Name: name, Digest: digest}}
	for p, c := range f.files {
		out.Files = append(out.Files, agentskillstore.FileInfo{Path: p, Size: len(c)})
	}
	return out, nil
}

func (f *fakeSkillFiles) ReadFile(_ context.Context, _, _, _, path string) ([]byte, error) {
	f.reads = append(f.reads, path)
	return []byte(f.files[path]), nil
}

// skillGrantAuthz allows can_load on one Agent Skill for one subject. It
// records each question, so a test can see that the question has the shape of
// the check of a load.
type skillGrantAuthz struct {
	authz.Authorizer
	subject, object string
	asked           []string
}

func (a *skillGrantAuthz) Check(_ context.Context, user, relation, object string) (bool, error) {
	a.asked = append(a.asked, user+" "+relation+" "+object)
	return user == a.subject && relation == "can_load" && object == a.object, nil
}

func scriptRequest(target string) *componentpb.CallToolRequest {
	return &componentpb.CallToolRequest{ToolName: SkillScriptTool, InputJson: `{"target":"` + target + `"}`}
}

const skillTenant = "acme"

func skillHarness(t *testing.T, store *fakeSkillFiles, blocked []string, grantSubject string) (*DefaultAgentHarness, *skillGrantAuthz, string) {
	t.Helper()
	missionID := types.NewID()
	object, err := authz.AgentSkillObject(skillTenant, "web-recon")
	if err != nil {
		t.Fatal(err)
	}
	a := &skillGrantAuthz{subject: grantSubject, object: object}
	if grantSubject == "mission" {
		a.subject = "mission:" + missionID.String()
	}
	h := &DefaultAgentHarness{
		missionCtx:          MissionContext{ID: missionID},
		componentAuthorizer: a,
		skillStore:          func() SkillFileStore { return store },
		missionDenyList:     func(context.Context, string, string) ([]string, error) { return blocked, nil },
	}
	return h, a, missionID.String()
}

func skillCtx(t *testing.T) context.Context {
	t.Helper()
	return callerCtx(t, "user-42", skillTenant)
}

func webRecon() map[string]string {
	return map[string]string{
		"scripts/probe.sh":  "#!/bin/sh\nnmap -Pn x\n",
		"references/api.md": "reference",
	}
}

// A mission that holds the grant gets each file of the pinned version below
// the name of the Agent Skill. A script gets an execute bit, a reference does
// not, and no file is writable.
func TestAddSkillFiles_PlacesTheFilesOfThePinnedVersion(t *testing.T) {
	store := &fakeSkillFiles{files: webRecon()}
	h, a, missionID := skillHarness(t, store, nil, "mission")
	var spec sandboxed.ToolSpec
	if err := h.addSkillFiles(skillCtx(t), SkillScriptTool, scriptRequest("web-recon/scripts/probe.sh"), &spec); err != nil {
		t.Fatalf("addSkillFiles: %v", err)
	}
	if len(store.resolved) != 1 || store.resolved[0] != skillTenant+"/"+missionID+"/web-recon" {
		t.Fatalf("the digest was not pinned for the mission: %v", store.resolved)
	}
	modes := map[string]uint32{}
	for _, f := range spec.Files {
		modes[f.Path] = f.Mode
		if f.Mode&0o222 != 0 || f.Mode&0o7000 != 0 {
			t.Errorf("%s: mode %o is writable or special", f.Path, f.Mode)
		}
	}
	if len(modes) != 2 || modes["web-recon/scripts/probe.sh"] != 0o555 || modes["web-recon/references/api.md"] != 0o444 {
		t.Fatalf("files = %v", modes)
	}
	if len(a.asked) == 0 || !strings.Contains(a.asked[len(a.asked)-1], "can_load") {
		t.Errorf("the check was %v, want a can_load check", a.asked)
	}
}

func TestAddSkillFiles_Refusals(t *testing.T) {
	cases := []struct {
		name    string
		store   *fakeSkillFiles
		blocked []string
		subject string
		target  string
		tool    string
		want    string
	}{
		{"no grant", &fakeSkillFiles{files: webRecon()}, nil, "mission:other", "web-recon/scripts/probe.sh", SkillScriptTool, "may not load"},
		{"the mission blocks the Agent Skill", &fakeSkillFiles{files: webRecon()}, []string{"skill:web-recon"}, "mission", "web-recon/scripts/probe.sh", SkillScriptTool, "blocked by mission policy"},
		{"a script that the Agent Skill lacks", &fakeSkillFiles{files: webRecon()}, nil, "mission", "web-recon/scripts/other.sh", SkillScriptTool, "has no file"},
		{"a target with no path", &fakeSkillFiles{files: webRecon()}, nil, "mission", "web-recon", SkillScriptTool, "must be <skill>"},
		{"a bad name", &fakeSkillFiles{files: webRecon()}, nil, "mission", "../etc/scripts/x", SkillScriptTool, "must be <skill>"},
		{"the store fails", &fakeSkillFiles{files: webRecon(), err: errors.New("db down")}, nil, "mission", "web-recon/scripts/probe.sh", SkillScriptTool, "db down"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, _, _ := skillHarness(t, tc.store, tc.blocked, tc.subject)
			var spec sandboxed.ToolSpec
			err := h.addSkillFiles(skillCtx(t), tc.tool, scriptRequest(tc.target), &spec)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want one with %q", err, tc.want)
			}
			if len(spec.Files) != 0 {
				t.Errorf("a refused call placed %d files", len(spec.Files))
			}
			if tc.name == "no grant" || tc.name == "the mission blocks the Agent Skill" {
				if len(tc.store.resolved) != 0 || len(tc.store.reads) != 0 {
					t.Error("the store was read for a refused call")
				}
			}
		})
	}
}

// The agent principal of the caller can hold the grant, as for a load.
func TestAddSkillFiles_AnAgentGrantPasses(t *testing.T) {
	store := &fakeSkillFiles{files: webRecon()}
	h, _, _ := skillHarness(t, store, nil, "agent_principal:scan-agent")
	ctx := callerCtx(t, "agent_principal:scan-agent", skillTenant)
	var spec sandboxed.ToolSpec
	if err := h.addSkillFiles(ctx, SkillScriptTool, scriptRequest("web-recon/scripts/probe.sh"), &spec); err != nil {
		t.Fatalf("addSkillFiles: %v", err)
	}
	if len(spec.Files) != 2 {
		t.Fatalf("files = %d, want 2", len(spec.Files))
	}
}

// Another tool is untouched, whatever its input holds.
func TestAddSkillFiles_IgnoresOtherTools(t *testing.T) {
	store := &fakeSkillFiles{files: webRecon()}
	h, _, _ := skillHarness(t, store, nil, "mission")
	var spec sandboxed.ToolSpec
	if err := h.addSkillFiles(skillCtx(t), "nmap", scriptRequest("web-recon/scripts/probe.sh"), &spec); err != nil {
		t.Fatalf("addSkillFiles for nmap: %v", err)
	}
	if len(spec.Files) != 0 || len(store.resolved) != 0 {
		t.Fatal("a tool other than skill-script got files")
	}
}

// A daemon with no Agent Skill store, a call with no mission, and a call with
// no tenant are each refused.
func TestAddSkillFiles_FailsClosedWithoutItsInputs(t *testing.T) {
	store := &fakeSkillFiles{files: webRecon()}
	req := scriptRequest("web-recon/scripts/probe.sh")

	h, _, _ := skillHarness(t, store, nil, "mission")
	h.skillStore = nil
	if err := h.addSkillFiles(skillCtx(t), SkillScriptTool, req, &sandboxed.ToolSpec{}); err == nil {
		t.Error("a harness with no store ran a script")
	}
	h, _, _ = skillHarness(t, store, nil, "mission")
	h.skillStore = func() SkillFileStore { return nil }
	if err := h.addSkillFiles(skillCtx(t), SkillScriptTool, req, &sandboxed.ToolSpec{}); err == nil {
		t.Error("a store provider that answers nil ran a script")
	}
	h, _, _ = skillHarness(t, store, nil, "mission")
	h.componentAuthorizer = nil
	if err := h.addSkillFiles(skillCtx(t), SkillScriptTool, req, &sandboxed.ToolSpec{}); err == nil {
		t.Error("a harness with no authorizer ran a script")
	}
	h, _, _ = skillHarness(t, store, nil, "mission")
	h.missionDenyList = nil
	if err := h.addSkillFiles(skillCtx(t), SkillScriptTool, req, &sandboxed.ToolSpec{}); err == nil {
		t.Error("a harness with no deny list source ran a script")
	}
	h, _, _ = skillHarness(t, store, nil, "mission")
	if err := h.addSkillFiles(context.Background(), SkillScriptTool, req, &sandboxed.ToolSpec{}); err == nil {
		t.Error("a call with no tenant ran a script")
	}
}
