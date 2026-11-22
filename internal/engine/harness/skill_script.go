// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/zeroroot-ai/gibson/internal/engine/catalog"
	"github.com/zeroroot-ai/gibson/internal/engine/harness/sandboxed"
	"github.com/zeroroot-ai/gibson/internal/engine/metatool"
	"github.com/zeroroot-ai/gibson/internal/engine/toolid"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/agentskillstore"
	"github.com/zeroroot-ai/sdk/auth"
)

// SkillScriptTool is the name of the tool that runs a script of a loaded Agent
// Skill. It is a kind:tool manifest tool of the executor image. The daemon
// places the files of the Agent Skill in its sandbox for each call.
const SkillScriptTool = "skill-script"

// skillScriptDir is the directory of an Agent Skill folder that holds its
// scripts. A file there is placed with an execute bit.
const skillScriptDir = "scripts/"

// The modes of a placed file. The sandbox refuses a write, a setuid and a
// setgid bit, so no placed file is writable by the tool.
const (
	skillFileMode   uint32 = 0o444
	skillScriptMode uint32 = 0o555
)

// SkillFileStore is the part of the Agent Skill store that the files of a call
// use.
type SkillFileStore interface {
	Resolve(ctx context.Context, tenant, missionID, name string) (string, error)
	Load(ctx context.Context, tenant, name, digest string) (*agentskillstore.Loaded, error)
	ReadFile(ctx context.Context, tenant, name, digest, path string) ([]byte, error)
}

// MissionDenyList reads the deny list of a mission from its stored definition.
type MissionDenyList func(ctx context.Context, tenant, missionID string) ([]string, error)

// skillScriptInput is the input of a call of the skill-script tool that the
// harness reads. The target names the script as "<skill>/<path>".
type skillScriptInput struct {
	Target string `json:"target"`
}

// addSkillFiles places the files of an Agent Skill in the sandbox of a
// skill-script call. For any other tool it does nothing.
//
// The call names a script as "<skill>/<path>". The Agent Skill is read at the
// digest that the mission pinned (the first use of a name pins it, as a load
// does), so a new publish does not change a running mission. The caller needs
// the same grant that a load needs, and a mission that denies the Agent Skill
// cannot run its script. Every file of the version is placed below the name
// of the Agent Skill, and the tool then runs the script as a normal tool call:
// in the sandbox of the call, with the egress limit of the agent, and with a
// record of the call like any other tool.
func (h *DefaultAgentHarness) addSkillFiles(ctx context.Context, toolName string, request proto.Message, spec *sandboxed.ToolSpec) error {
	if toolName != SkillScriptTool {
		return nil
	}
	deny := func(format string, args ...any) error {
		return types.WrapError(types.SANDBOX_POLICY_DENIED,
			fmt.Sprintf("tool %q: "+format, append([]any{toolName}, args...)...), nil)
	}
	skill, script, err := skillScriptTarget(request)
	if err != nil {
		return deny("%v", err)
	}
	if h.skillStore == nil {
		return deny("this daemon serves no Agent Skill")
	}
	store := h.skillStore()
	if store == nil {
		return deny("this daemon serves no Agent Skill")
	}
	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" || tenant == auth.SystemTenantString {
		return deny("no tenant in context")
	}
	missionID := h.missionCtx.ID.String()
	if missionID == "" {
		return deny("an Agent Skill script runs only in a mission")
	}
	if err := h.authorizeSkillScript(ctx, tenant, missionID, skill); err != nil {
		return err
	}
	digest, err := store.Resolve(ctx, tenant, missionID, skill)
	if err != nil {
		return deny("resolve the Agent Skill %q: %v", skill, err)
	}
	loaded, err := store.Load(ctx, tenant, skill, digest)
	if err != nil {
		return deny("load the Agent Skill %q: %v", skill, err)
	}
	files, err := skillSandboxFiles(ctx, store, tenant, skill, digest, loaded)
	if err != nil {
		return deny("%v", err)
	}
	if !hasSkillFile(files, skill+"/"+script) {
		return deny("the Agent Skill %q has no file %q", skill, script)
	}
	spec.Files = files
	return nil
}

// authorizeSkillScript refuses the call unless the caller may load the Agent
// Skill, with the check that a load makes, and unless the deny list of the
// mission leaves the Agent Skill alone.
func (h *DefaultAgentHarness) authorizeSkillScript(ctx context.Context, tenant, missionID, skill string) error {
	id, err := toolid.ForSkill(skill)
	if err != nil {
		return types.WrapError(types.SANDBOX_POLICY_DENIED, fmt.Sprintf("tool %q: %v", SkillScriptTool, err), nil)
	}
	if h.missionDenyList == nil {
		return types.WrapError(types.SANDBOX_POLICY_DENIED,
			fmt.Sprintf("tool %q: the mission deny list source is not wired", SkillScriptTool), nil)
	}
	blocked, err := h.missionDenyList(ctx, tenant, missionID)
	if err != nil {
		return types.WrapError(types.SANDBOX_POLICY_DENIED,
			fmt.Sprintf("tool %q: read the deny list of mission %q", SkillScriptTool, missionID), err)
	}
	if _, denied := metatool.MatchBlocked(blocked, id.Canonical()); denied {
		return types.WrapError(types.SANDBOX_POLICY_DENIED,
			fmt.Sprintf("tool %q: the Agent Skill %q is blocked by mission policy", SkillScriptTool, skill), nil)
	}
	if h.componentAuthorizer == nil {
		return types.WrapError(types.SANDBOX_POLICY_DENIED,
			fmt.Sprintf("tool %q: authorization unavailable (no authorizer wired)", SkillScriptTool), nil)
	}
	caller := catalog.Caller{Tenant: tenant, Mission: missionID}
	if identity, idErr := auth.IdentityFromContext(ctx); idErr == nil {
		subject := callbackFGAUser(identity.Subject)
		caller.Subject = subject
		if strings.HasPrefix(subject, "agent_principal:") {
			caller.Agent = subject
		}
	}
	allowed, err := catalog.NewFGAAuthorizer(h.componentAuthorizer).CanExecute(ctx, caller, id)
	if err != nil {
		return types.WrapError(types.SANDBOX_POLICY_DENIED,
			fmt.Sprintf("tool %q: the check of the Agent Skill %q failed", SkillScriptTool, skill), err)
	}
	if !allowed {
		return types.WrapError(types.SANDBOX_POLICY_DENIED,
			fmt.Sprintf("tool %q: the caller may not load the Agent Skill %q", SkillScriptTool, skill), nil)
	}
	return nil
}

// skillScriptTarget reads the target of the call from the input of the
// request, and splits it into the Agent Skill and the path of the script.
func skillScriptTarget(request proto.Message) (skill, script string, err error) {
	raw := inputJSONOf(request)
	if raw == "" {
		return "", "", errors.New("the call has no input")
	}
	var in skillScriptInput
	if err := json.Unmarshal([]byte(raw), &in); err != nil {
		return "", "", fmt.Errorf("the input is not JSON: %w", err)
	}
	skill, script, ok := strings.Cut(in.Target, "/")
	if !ok || script == "" || !toolid.ValidSkillName(skill) {
		return "", "", fmt.Errorf("the target %q must be <skill>/<path of the script>", in.Target)
	}
	return skill, script, nil
}

// inputJSONOf returns the input_json field of a tool request, or "".
func inputJSONOf(request proto.Message) string {
	if request == nil {
		return ""
	}
	m := request.ProtoReflect()
	field := m.Descriptor().Fields().ByName("input_json")
	if field == nil || field.Kind() != protoreflect.StringKind {
		return ""
	}
	return m.Get(field).String()
}

// skillSandboxFiles reads each file of the Agent Skill version and returns it
// as a file of the sandbox below the name of the Agent Skill. A file under
// scripts/ gets an execute bit. No file is writable.
func skillSandboxFiles(
	ctx context.Context, store SkillFileStore, tenant, skill, digest string, loaded *agentskillstore.Loaded,
) ([]sandboxed.File, error) {
	files := make([]sandboxed.File, 0, len(loaded.Files))
	for _, f := range loaded.Files {
		content, err := store.ReadFile(ctx, tenant, skill, digest, f.Path)
		if err != nil {
			return nil, fmt.Errorf("read the file %q of the Agent Skill %q: %w", f.Path, skill, err)
		}
		mode := skillFileMode
		if strings.HasPrefix(f.Path, skillScriptDir) {
			mode = skillScriptMode
		}
		files = append(files, sandboxed.File{Path: skill + "/" + f.Path, Content: content, Mode: mode})
	}
	return files, nil
}

func hasSkillFile(files []sandboxed.File, path string) bool {
	for _, f := range files {
		if f.Path == path {
			return true
		}
	}
	return false
}
