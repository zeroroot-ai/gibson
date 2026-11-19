// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package toolid_test

import (
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/toolid"
)

// Canonical round-trips: Parse(Canonical(id)) == id, for both sources.
func TestParseCanonicalRoundTrip(t *testing.T) {
	cases := []struct {
		name      string
		canonical string
		want      toolid.ID
	}{
		{
			name:      "mcp tool",
			canonical: "mcp:gitlab-acme:create_merge_request",
			want:      toolid.ID{Source: toolid.SourceMCP, Connector: "gitlab-acme", Tool: "create_merge_request"},
		},
		{
			name:      "mcp shared connector",
			canonical: "mcp:gitlab:create_issue",
			want:      toolid.ID{Source: toolid.SourceMCP, Connector: "gitlab", Tool: "create_issue"},
		},
		{
			name:      "native primitive",
			canonical: "native:nmap",
			want:      toolid.ID{Source: toolid.SourceNative, Connector: "", Tool: "nmap"},
		},
		{
			name:      "agent skill",
			canonical: "skill:web-recon-2",
			want:      toolid.ID{Source: toolid.SourceSkill, Tool: "web-recon-2"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := toolid.Parse(tc.canonical)
			if err != nil {
				t.Fatalf("Parse(%q) error: %v", tc.canonical, err)
			}
			if got != tc.want {
				t.Fatalf("Parse(%q) = %+v, want %+v", tc.canonical, got, tc.want)
			}
			if rt := got.Canonical(); rt != tc.canonical {
				t.Fatalf("Canonical() = %q, want %q", rt, tc.canonical)
			}
		})
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	bad := []string{
		"",                   // empty
		"gitlab:create",      // unknown source
		"mcp:gitlab",         // mcp needs connector + tool
		"mcp::create",        // empty connector
		"mcp:gitlab:",        // empty tool
		"native:",            // empty native tool
		"native:nmap:extra",  // native takes no connector
		"mcp:git:lab:create", // too many segments for mcp
		"skill:",             // empty Agent Skill name
		"skill:a:b",          // the separator is not allowed in a name
		"skill:Recon",        // uppercase letter
		"skill:-recon",       // leading hyphen
		"skill:recon-",       // trailing hyphen
		"skill:re--con",      // two hyphens together
		"skill:re_con",       // underscore
		"skill:" + strings.Repeat("a", 65),
	}
	for _, s := range bad {
		if _, err := toolid.Parse(s); err == nil {
			t.Errorf("Parse(%q) = nil error, want error", s)
		}
	}
}

// Flatten -> Unflatten round-trips and stays within the native-function rule.
func TestFlattenUnflattenRoundTrip(t *testing.T) {
	ids := []toolid.ID{
		{Source: toolid.SourceMCP, Connector: "gitlab-acme", Tool: "create_merge_request"},
		{Source: toolid.SourceMCP, Connector: "github", Tool: "list_issues"},
		{Source: toolid.SourceNative, Tool: "nmap"},
	}
	for _, id := range ids {
		flat, err := id.Flatten()
		if err != nil {
			t.Fatalf("Flatten(%+v) error: %v", id, err)
		}
		if !toolid.ValidFunctionName(flat) {
			t.Fatalf("Flatten(%+v) = %q, not a valid native function name", id, flat)
		}
		back, err := toolid.Unflatten(flat)
		if err != nil {
			t.Fatalf("Unflatten(%q) error: %v", flat, err)
		}
		if back != id {
			t.Fatalf("round trip: Unflatten(Flatten(%+v)) = %+v", id, back)
		}
	}
}

func TestFlattenRejectsTooLong(t *testing.T) {
	// 64-char cap on the flattened native-function name.
	id := toolid.ID{
		Source:    toolid.SourceMCP,
		Connector: "a-very-long-connector-instance-name-that-eats-budget",
		Tool:      "an_equally_long_tool_name_that_overflows_the_limit",
	}
	if _, err := id.Flatten(); err == nil {
		t.Fatalf("Flatten(overlong) = nil error, want error")
	}
}

func TestFlattenRejectsAmbiguousSegment(t *testing.T) {
	// A segment containing the "__" separator would make Unflatten ambiguous.
	id := toolid.ID{Source: toolid.SourceMCP, Connector: "git__lab", Tool: "create"}
	if _, err := id.Flatten(); err == nil {
		t.Fatalf("Flatten(ambiguous segment) = nil error, want error")
	}
}

// PluginRef: an MCP id decomposes to the existing (plugin_name, method) dispatch
// key; a native id does not.
func TestForConnectorTool(t *testing.T) {
	id, err := toolid.ForMCP("gitlab", "create_issue")
	if err != nil {
		t.Fatalf("ForMCP error: %v", err)
	}
	if id.Canonical() != "mcp:gitlab:create_issue" {
		t.Fatalf("ForMCP canonical = %q", id.Canonical())
	}
	if _, err := toolid.ForMCP("gitlab:bad", "create"); err == nil {
		t.Fatalf("ForMCP with ':' in connector = nil error, want error")
	}
}

func TestSkillNameLimits(t *testing.T) {
	if !toolid.ValidSkillName(strings.Repeat("a", 64)) {
		t.Error("a name of 64 characters must be valid")
	}
	if toolid.ValidSkillName("") {
		t.Error("an empty name must be invalid")
	}
	if _, err := toolid.ForSkill("a:b"); err == nil {
		t.Error("ForSkill with the separator must fail")
	}
	id, err := toolid.ForSkill("web-recon")
	if err != nil {
		t.Fatalf("ForSkill: %v", err)
	}
	flat, err := id.Flatten()
	if err != nil {
		t.Fatalf("Flatten: %v", err)
	}
	back, err := toolid.Unflatten(flat)
	if err != nil || back != id {
		t.Fatalf("Unflatten(%q) = %+v, %v, want %+v", flat, back, err, id)
	}
}
