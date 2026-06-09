// Package toolid is the codec for connector tool identifiers.
//
// A tool has a single canonical id used everywhere a tool is referenced by name
// — SearchTools results, the agent's invoke_tool call, mission blocked_tools,
// and PLUGIN-node addressing:
//
//	mcp:<connector>:<tool>     // a tool exposed by an MCP connector
//	native:<tool>              // a native primitive (nmap, httpx, …)
//
// The canonical form carries structure a native LLM function name cannot
// (function names are constrained to ^[a-zA-Z0-9_-]{1,64}$). When — and only
// when — a tool is bound directly to the model as a native function, the
// flattened form is used instead:
//
//	mcp__<connector>__<tool>
//	native__<tool>
//
// An MCP id decomposes to the existing (plugin_name, method) dispatch key via
// PluginRef, so connectors route through the daemon's existing PluginInvoke path
// with no new mechanism. See ADR-0047 facet 5.
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
)

const (
	canonicalSep = ":"
	flattenSep   = "__"
)

// functionNameRE is the LLM-provider rule for a native function name.
var functionNameRE = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

// ID is a parsed, validated tool identifier.
//
// Connector is empty for SourceNative.
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
	default:
		return ID{}, fmt.Errorf("toolid: unknown source %q in %q", parts[0], s)
	}
}

// Canonical returns the canonical colon-form id.
func (id ID) Canonical() string {
	if id.Source == SourceNative {
		return string(SourceNative) + canonicalSep + id.Tool
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
	default:
		return ID{}, fmt.Errorf("toolid: unknown source in flattened name %q", flat)
	}
}

// PluginRef decomposes an MCP id to the existing (plugin_name, method) dispatch
// key. ok is false for native tools, which are not PluginInvoke targets.
func (id ID) PluginRef() (pluginName, method string, ok bool) {
	if id.Source != SourceMCP {
		return "", "", false
	}
	return id.Connector, id.Tool, true
}

// ValidFunctionName reports whether s is a legal native LLM function name.
func ValidFunctionName(s string) bool {
	return functionNameRE.MatchString(s)
}
