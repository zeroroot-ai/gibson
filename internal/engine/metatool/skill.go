// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package metatool

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/zeroroot-ai/gibson/internal/engine/agentskill"
	"github.com/zeroroot-ai/gibson/internal/engine/toolid"
	"github.com/zeroroot-ai/gibson/internal/platform/agentskillstore"
)

// ErrSkillPath is returned when a request names a file that is not inside the
// folder of the Agent Skill.
var ErrSkillPath = errors.New("metatool: the file is not inside the folder of the Agent Skill")

// ErrSkillScript is returned for a request that reads a script of an Agent Skill
// as text. A script runs with the skill-script tool, in the sandbox of the
// agent, and its text never enters the context of the agent.
var ErrSkillScript = errors.New("metatool: a script of an Agent Skill is not loaded as text; run it with the skill-script tool")

// skillScriptDir is the folder of an Agent Skill that holds its scripts.
const skillScriptDir = "scripts/"

// ErrSkillNeedsMission is returned for a load with no mission. Only a mission
// agent loads an Agent Skill.
var ErrSkillNeedsMission = errors.New("metatool: an Agent Skill loads only in a mission")

// SkillStore is the part of the Agent Skill store that a load uses. A load
// reads the database of the tenant and never the registry.
type SkillStore interface {
	Resolve(ctx context.Context, tenant, missionID, name string) (string, error)
	Load(ctx context.Context, tenant, name, digest string) (*agentskillstore.Loaded, error)
	ReadFile(ctx context.Context, tenant, name, digest, path string) ([]byte, error)
}

// SkillLoad describes one successful load. The harness records it.
type SkillLoad struct {
	Tenant    string
	Agent     string
	MissionID string
	RunID     string
	Name      string
	Digest    string
	// File is the reference file of the load. It is empty for the body.
	File string
}

// WithSkills sets the store that serves a skill: id, and the function that
// records each load. It returns h. A Handler with no store or no recorder
// refuses a skill: id. When the recorder fails, the load fails and the agent
// gets no content, because no load goes without its record.
func (h *Handler) WithSkills(store SkillStore, onLoad func(ctx context.Context, load SkillLoad) error) *Handler {
	h.skills = store
	h.onSkillLoad = onLoad
	return h
}

// SkillFile names one reference file of a loaded Agent Skill.
type SkillFile struct {
	Path string `json:"path"`
	Size int    `json:"size"`
}

// SkillResult is the result of a load of the body. The agent gets it as the
// output of a tool and never as system instructions.
type SkillResult struct {
	Name        string `json:"name"`
	Digest      string `json:"digest"`
	Description string `json:"description"`
	Body        string `json:"body"`
	// Files lists the reference files. A second call names one of them in the
	// file argument.
	Files []SkillFile `json:"files"`
	// AllowedTools is the allowed-tools field of the Agent Skill. It is data
	// for the agent. It gives the agent no tool and no permission.
	AllowedTools []string `json:"allowed_tools"`
}

// SkillFileResult is the result of a load of one reference file.
type SkillFileResult struct {
	Name    string `json:"name"`
	Digest  string `json:"digest"`
	File    string `json:"file"`
	Content string `json:"content"`
}

// loadSkill serves a skill: id. It checks FGA again, because the agent can pass
// an id that it never got from the search. It pins the digest of the mission on
// the first load, so a new publish does not change what the mission loads. The
// args field "file" names one reference file inside the folder. A script is
// not a reference file: it runs with the skill-script tool.
func (h *Handler) loadSkill(ctx context.Context, c Call, tid toolid.ID) (any, error) {
	if h.skills == nil || h.onSkillLoad == nil {
		return nil, errors.New("metatool: Agent Skills are not configured")
	}
	if _, err := h.Authorize(ctx, c.Caller, tid.Canonical()); err != nil {
		return nil, err
	}
	missionID := c.MissionID
	if missionID == "" {
		missionID = c.Caller.Mission
	}
	if missionID == "" {
		return nil, ErrSkillNeedsMission
	}
	file, err := skillFileArg(c.Args)
	if err != nil {
		return nil, err
	}
	digest, err := h.skills.Resolve(ctx, c.Caller.Tenant, missionID, tid.Tool)
	if err != nil {
		return nil, fmt.Errorf("metatool: load %q: %w", tid.Canonical(), err)
	}
	load := SkillLoad{
		Tenant: c.Caller.Tenant, Agent: c.Caller.Agent, MissionID: missionID, RunID: c.RunID,
		Name: tid.Tool, Digest: digest, File: file,
	}
	var result any
	if file != "" {
		content, rerr := h.skills.ReadFile(ctx, c.Caller.Tenant, tid.Tool, digest, file)
		if rerr != nil {
			return nil, fmt.Errorf("metatool: load file %q of %q: %w", file, tid.Canonical(), rerr)
		}
		if !utf8.Valid(content) {
			return nil, fmt.Errorf("metatool: the file %q of %q is not text", file, tid.Canonical())
		}
		result = SkillFileResult{Name: tid.Tool, Digest: digest, File: file, Content: string(content)}
	} else {
		loaded, lerr := h.skills.Load(ctx, c.Caller.Tenant, tid.Tool, digest)
		if lerr != nil {
			return nil, fmt.Errorf("metatool: load %q: %w", tid.Canonical(), lerr)
		}
		res := SkillResult{
			Name: tid.Tool, Digest: digest, Description: loaded.Entry.Description, Body: loaded.Body,
			Files: make([]SkillFile, 0, len(loaded.Files)), AllowedTools: loaded.Entry.AllowedTools,
		}
		if res.AllowedTools == nil {
			res.AllowedTools = []string{}
		}
		for _, f := range loaded.Files {
			res.Files = append(res.Files, SkillFile{Path: f.Path, Size: f.Size})
		}
		result = res
	}
	if err := h.onSkillLoad(ctx, load); err != nil {
		return nil, fmt.Errorf("metatool: record the load of %q: %w", tid.Canonical(), err)
	}
	return result, nil
}

// skillFileArg reads the file argument. A path that leaves the folder is
// refused before the store is read.
func skillFileArg(args map[string]any) (string, error) {
	raw, ok := args["file"]
	if !ok || raw == nil {
		return "", nil
	}
	file, ok := raw.(string)
	if !ok {
		return "", errors.New("metatool: the file argument must be a string")
	}
	if file == "" {
		return "", nil
	}
	if err := agentskill.ValidPath(file); err != nil {
		return "", fmt.Errorf("%w: %q", ErrSkillPath, file)
	}
	if strings.HasPrefix(file, skillScriptDir) {
		return "", fmt.Errorf("%w: %q", ErrSkillScript, file)
	}
	return file, nil
}
