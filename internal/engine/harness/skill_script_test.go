// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

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
	loadErr  error
	readErr  error
}

func (f *fakeSkillFiles) Resolve(_ context.Context, tenant, mission, name string) (string, error) {
	f.resolved = append(f.resolved, tenant+"/"+mission+"/"+name)
	return "sha256:pinned", f.err
}

func (f *fakeSkillFiles) Load(_ context.Context, _, name, digest string) (*agentskillstore.Loaded, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.loadErr != nil {
		return nil, f.loadErr
	}
	out := &agentskillstore.Loaded{Entry: agentskillstore.Entry{Name: name, Digest: digest}}
	for p, c := range f.files {
		out.Files = append(out.Files, agentskillstore.FileInfo{Path: p, Size: len(c)})
	}
	return out, nil
}

func (f *fakeSkillFiles) ReadFile(_ context.Context, _, _, _, path string) ([]byte, error) {
	f.reads = append(f.reads, path)
	if f.readErr != nil {
		return nil, f.readErr
	}
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

// More refusals: each input of the call that can be wrong, and each source that
// can fail, ends the call before any file is placed.
func TestAddSkillFiles_MoreRefusals(t *testing.T) {
	good := func() (*DefaultAgentHarness, *fakeSkillFiles) {
		store := &fakeSkillFiles{files: webRecon()}
		h, _, _ := skillHarness(t, store, nil, "mission")
		return h, store
	}
	cases := map[string]func() (*DefaultAgentHarness, proto.Message, string){
		"no input": func() (*DefaultAgentHarness, proto.Message, string) {
			h, _ := good()
			return h, &componentpb.CallToolRequest{ToolName: SkillScriptTool}, "no input"
		},
		"input that is not JSON": func() (*DefaultAgentHarness, proto.Message, string) {
			h, _ := good()
			return h, &componentpb.CallToolRequest{InputJson: "not json"}, "not JSON"
		},
		"no request": func() (*DefaultAgentHarness, proto.Message, string) {
			h, _ := good()
			return h, nil, "no input"
		},
		"a request with no input field": func() (*DefaultAgentHarness, proto.Message, string) {
			h, _ := good()
			return h, wrapperspb.String("x"), "no input"
		},
		"a call outside a mission": func() (*DefaultAgentHarness, proto.Message, string) {
			h, _ := good()
			h.missionCtx = MissionContext{}
			return h, scriptRequest("web-recon/scripts/probe.sh"), "only in a mission"
		},
		"a deny list that cannot be read": func() (*DefaultAgentHarness, proto.Message, string) {
			h, _ := good()
			h.missionDenyList = func(context.Context, string, string) ([]string, error) { return nil, errors.New("db") }
			return h, scriptRequest("web-recon/scripts/probe.sh"), "deny list"
		},
		"a check that fails": func() (*DefaultAgentHarness, proto.Message, string) {
			h, _ := good()
			h.componentAuthorizer = &recordingAuthorizer{err: errors.New("fga down")}
			return h, scriptRequest("web-recon/scripts/probe.sh"), "failed"
		},
		"a load that fails": func() (*DefaultAgentHarness, proto.Message, string) {
			h, store := good()
			store.loadErr = errors.New("no such version")
			return h, scriptRequest("web-recon/scripts/probe.sh"), "no such version"
		},
		"a file that cannot be read": func() (*DefaultAgentHarness, proto.Message, string) {
			h, store := good()
			store.readErr = errors.New("corrupt")
			return h, scriptRequest("web-recon/scripts/probe.sh"), "corrupt"
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			h, req, want := build()
			var spec sandboxed.ToolSpec
			err := h.addSkillFiles(skillCtx(t), SkillScriptTool, req, &spec)
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("err = %v, want one with %q", err, want)
			}
			if len(spec.Files) != 0 {
				t.Errorf("a refused call placed %d files", len(spec.Files))
			}
		})
	}
}

// A name that is not a valid Agent Skill name is refused by the check itself,
// whatever the caller did before it.
func TestAuthorizeSkillScript_RefusesABadName(t *testing.T) {
	h, _, missionID := skillHarness(t, &fakeSkillFiles{}, nil, "mission")
	if err := h.authorizeSkillScript(skillCtx(t), skillTenant, missionID, "Bad Name"); err == nil {
		t.Fatal("a bad name passed the check")
	}
}

// launchRecorder is a sandbox client that records the launch and then fails it,
// so the call ends right after the launch.
type launchRecorder struct {
	sandboxed.SandboxClient
	got sandboxed.LaunchRequest
}

func (l *launchRecorder) Launch(_ context.Context, r sandboxed.LaunchRequest) (sandboxed.LaunchResponse, error) {
	l.got = r
	return sandboxed.LaunchResponse{}, errors.New("stop after the launch")
}

// canExecuteAndLoad allows can_execute on the tool and can_load on the Agent
// Skill for the mission.
type canExecuteAndLoad struct {
	authz.Authorizer
	mission string
}

func (a canExecuteAndLoad) Check(_ context.Context, user, relation, _ string) (bool, error) {
	return relation == "can_execute" || (relation == "can_load" && user == "mission:"+a.mission), nil
}

// A skill-script call through CallToolProto reaches the sandbox launch with the
// files of the Agent Skill, and with the egress limit of the agent that makes
// the call. The files add no network path: the egress is the ceiling of the
// agent, and nothing else.
func TestCallToolProto_SkillScriptLaunchesWithTheFilesAndTheEgressOfTheAgent(t *testing.T) {
	rec := &launchRecorder{}
	exec, err := sandboxed.New(sandboxed.Config{Client: rec, SandboxClass: "tool"})
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeSkillFiles{files: webRecon()}
	h, _, missionID := skillHarness(t, store, nil, "mission")
	h.componentAuthorizer = canExecuteAndLoad{mission: missionID}
	h.sandboxedExecutor = exec
	h.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	h.tracer = noop.NewTracerProvider().Tracer("test")
	h.missionCtx.CurrentAgent = "cve-triage"

	req := scriptRequest("web-recon/scripts/probe.sh")
	var resp componentpb.CallToolResponse
	if err := h.CallToolProto(skillCtx(t), SkillScriptTool, req, &resp); err == nil {
		t.Fatal("the launch was set to fail")
	}
	if len(rec.got.Files) != 2 {
		t.Fatalf("launch files = %d, want 2", len(rec.got.Files))
	}
	want := agentEgressCeiling("cve-triage")
	if len(want) == 0 {
		t.Fatal("the test agent has no egress ceiling; pick another")
	}
	if len(rec.got.Egress) != len(want) {
		t.Fatalf("launch egress = %+v, want the ceiling of the agent %+v", rec.got.Egress, want)
	}
	if !reflect.DeepEqual(rec.got.Egress, want) {
		t.Errorf("egress = %+v, want %+v", rec.got.Egress, want)
	}

	// A call that the check refuses never reaches the launch.
	rec.got = sandboxed.LaunchRequest{}
	h.componentAuthorizer = canExecuteAndLoad{mission: "another-mission"}
	if err := h.CallToolProto(skillCtx(t), SkillScriptTool, req, &resp); err == nil {
		t.Fatal("a mission with no grant ran the script")
	}
	if rec.got.Image != "" {
		t.Error("a refused call reached the launch")
	}
}
