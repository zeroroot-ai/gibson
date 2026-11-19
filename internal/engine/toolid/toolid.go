// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package toolid is the codec for connector tool identifiers.
//
// A tool has a single canonical id used everywhere a tool is referenced by name
// — SearchTools results, the agent's invoke_tool call, mission blocked_tools,
// and PLUGIN-node addressing:
//
//	mcp:<connector>:<tool>     // a tool exposed by an MCP connector
//	native:<tool>              // a native primitive (nmap, httpx, …)
//	skill:<name>               // an Agent Skill (a method in the Agent Skills format)
//
// The canonical form carries structure a native LLM function name cannot
// (function names are constrained to ^[a-zA-Z0-9_-]{1,64}$). When — and only
// when — a tool is bound directly to the model as a native function, the
// flattened form is used instead:
//
//	mcp__<connector>__<tool>
//	native__<tool>
//	skill__<name>
//
// An MCP id names a connector and one of its tools. The daemon, the one MCP
// client, calls that connector. See ADR-0065.
package toolid

import (
	"fmt"
	"regexp"
	"strings"
)

// Source identifies which kind of component exposes a tool.
type Source string

const (
	// SourceMCP is a tool exposed by an MCP connector.
	SourceMCP Source = "mcp"
	// SourceNative is a native primitive tool (nmap, httpx, …).
	SourceNative Source = "native"
	// SourceSkill is an Agent Skill. The id holds the name of the Agent Skill.
	SourceSkill Source = "skill"
)

// MaxSkillNameLen is the longest name that the Agent Skills format allows.
const MaxSkillNameLen = 64

const (
	canonicalSep = ":"
	flattenSep   = "__"
)

// functionNameRE is the LLM-provider rule for a native function name.
var functionNameRE = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

// skillNameRE is the name rule of the Agent Skills format. The name has
// lowercase letters, digits and single hyphens. It has no hyphen at the start
// or at the end.
var skillNameRE = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// ID is a parsed, validated tool identifier.
//
// Connector is empty for SourceNative and for SourceSkill. For SourceSkill,
// Tool holds the name of the Agent Skill.
type ID struct {
	Source    Source
	Connector string
	Tool      string
}

// ForMCP constructs an MCP tool id from a connector instance name and a tool
// name. It rejects empty segments and segments containing the canonical
// separator.
func ForMCP(connector, tool string) (ID, error) {
	if connector == "" || tool == "" {
		return ID{}, fmt.Errorf("toolid: mcp id requires non-empty connector and tool")
	}
	if strings.Contains(connector, canonicalSep) || strings.Contains(tool, canonicalSep) {
		return ID{}, fmt.Errorf("toolid: %q segment must not contain %q", canonicalSep, canonicalSep)
	}
	return ID{Source: SourceMCP, Connector: connector, Tool: tool}, nil
}

// ForNative constructs a native primitive tool id from a tool name.
func ForNative(tool string) (ID, error) {
	if tool == "" {
		return ID{}, fmt.Errorf("toolid: native id requires non-empty tool")
	}
	if strings.Contains(tool, canonicalSep) {
		return ID{}, fmt.Errorf("toolid: native tool must not contain %q", canonicalSep)
	}
	return ID{Source: SourceNative, Tool: tool}, nil
}

// ValidSkillName reports whether name follows the name rule of the Agent Skills
// format. The name has 1 to 64 characters. It has lowercase letters, digits and
// hyphens. It has no hyphen at the start or at the end and no two hyphens
// together.
func ValidSkillName(name string) bool {
	return len(name) <= MaxSkillNameLen && skillNameRE.MatchString(name)
}

// ForSkill constructs an Agent Skill id from the name of the Agent Skill.
func ForSkill(name string) (ID, error) {
	if !ValidSkillName(name) {
		return ID{}, fmt.Errorf("toolid: %q is not a valid Agent Skill name", name)
	}
	return ID{Source: SourceSkill, Tool: name}, nil
}

// Parse decodes a canonical tool id.
func Parse(s string) (ID, error) {
	parts := strings.Split(s, canonicalSep)
	if len(parts) == 0 {
		return ID{}, fmt.Errorf("toolid: empty id")
	}
	switch Source(parts[0]) {
	case SourceMCP:
		if len(parts) != 3 || parts[1] == "" || parts[2] == "" {
			return ID{}, fmt.Errorf("toolid: mcp id must be mcp:<connector>:<tool>, got %q", s)
		}
		return ID{Source: SourceMCP, Connector: parts[1], Tool: parts[2]}, nil
	case SourceNative:
		if len(parts) != 2 || parts[1] == "" {
			return ID{}, fmt.Errorf("toolid: native id must be native:<tool>, got %q", s)
		}
		return ID{Source: SourceNative, Tool: parts[1]}, nil
	case SourceSkill:
		if len(parts) != 2 {
			return ID{}, fmt.Errorf("toolid: Agent Skill id must be skill:<name>, got %q", s)
		}
		return ForSkill(parts[1])
	default:
		return ID{}, fmt.Errorf("toolid: unknown source %q in %q", parts[0], s)
	}
}

// Canonical returns the canonical colon-form id.
func (id ID) Canonical() string {
	if id.Source == SourceNative || id.Source == SourceSkill {
		return string(id.Source) + canonicalSep + id.Tool
	}
	return string(id.Source) + canonicalSep + id.Connector + canonicalSep + id.Tool
}

// Flatten returns the native-function form, validated against the provider name
// rule. It errors if any segment contains the "__" separator (which would make
// Unflatten ambiguous) or if the result is not a legal function name (charset or
// the 64-char cap).
func (id ID) Flatten() (string, error) {
	segs := []string{string(id.Source), id.Tool}
	if id.Source == SourceMCP {
		segs = []string{string(id.Source), id.Connector, id.Tool}
	}
	for _, seg := range segs {
		if strings.Contains(seg, flattenSep) {
			return "", fmt.Errorf("toolid: segment %q contains the %q separator; cannot flatten unambiguously", seg, flattenSep)
		}
	}
	flat := strings.Join(segs, flattenSep)
	if !ValidFunctionName(flat) {
		return "", fmt.Errorf("toolid: flattened name %q is not a valid native function name (^[a-zA-Z0-9_-]{1,64}$)", flat)
	}
	return flat, nil
}

// Unflatten decodes a flattened native-function name back to an ID.
func Unflatten(flat string) (ID, error) {
	parts := strings.Split(flat, flattenSep)
	if len(parts) == 0 {
		return ID{}, fmt.Errorf("toolid: empty flattened name")
	}
	switch Source(parts[0]) {
	case SourceMCP:
		if len(parts) != 3 || parts[1] == "" || parts[2] == "" {
			return ID{}, fmt.Errorf("toolid: flattened mcp name must be mcp__<connector>__<tool>, got %q", flat)
		}
		return ID{Source: SourceMCP, Connector: parts[1], Tool: parts[2]}, nil
	case SourceNative:
		if len(parts) != 2 || parts[1] == "" {
			return ID{}, fmt.Errorf("toolid: flattened native name must be native__<tool>, got %q", flat)
		}
		return ID{Source: SourceNative, Tool: parts[1]}, nil
	case SourceSkill:
		if len(parts) != 2 {
			return ID{}, fmt.Errorf("toolid: flattened Agent Skill name must be skill__<name>, got %q", flat)
		}
		return ForSkill(parts[1])
	default:
		return ID{}, fmt.Errorf("toolid: unknown source in flattened name %q", flat)
	}
}

// ValidFunctionName reports whether s is a legal native LLM function name.
func ValidFunctionName(s string) bool {
	return functionNameRE.MatchString(s)
}
