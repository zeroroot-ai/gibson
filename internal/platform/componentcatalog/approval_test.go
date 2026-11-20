// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package componentcatalog

import (
	"strings"
	"testing"
)

const responseConnector = `id: edr-x
kind: connector
spec:
  class: edr
  shape: Remote
  endpoint: https://x/mcp
  auth: oauth
`

func loadOne(t *testing.T, body string) (Manifest, error) {
	t.Helper()
	got, err := load(manifestFSWith(map[string]string{"c.yaml": body}))
	if err != nil {
		return Manifest{}, err
	}
	return got[0], nil
}

func TestApproval_ManifestMarksTools(t *testing.T) {
	m, err := loadOne(t, responseConnector+`  responseActions: true
  tools:
    isolate_host:
      approval: required
      undo: release_host
      blastRadius: one host
    release_host:
      approval: none
    revoke_session:
      approval: none
`)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	e := m.toConnectorEntry()

	if got := e.ApprovalFor("isolate_host"); !got.Required || got.UndoTool != "release_host" || got.BlastRadius != "one host" {
		t.Errorf("isolate_host = %+v", got)
	}
	// The owner decision: a session revoke runs with no approval.
	if got := e.ApprovalFor("revoke_session"); got.Required {
		t.Errorf("revoke_session must need only the grant: %+v", got)
	}
	// A tool that the manifest does not name is marked (fail closed).
	if got := e.ApprovalFor("brand_new_tool"); !got.Required {
		t.Errorf("an unnamed tool of a response connector must be marked: %+v", got)
	}
}

// The agent and the MCP server do not select the gate: a read-only connector
// that names one tool keeps the open path for the others.
func TestApproval_AReadOnlyConnectorNeedsOnlyTheGrant(t *testing.T) {
	m, err := loadOne(t, responseConnector+`  tools:
    export_everything:
      approval: required
`)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	e := m.toConnectorEntry()
	if !e.ApprovalFor("export_everything").Required {
		t.Error("a named tool must be marked")
	}
	if e.ApprovalFor("list_hosts").Required {
		t.Error("a tool of a connector that only reads needs only the grant")
	}
	plain, err := loadOne(t, responseConnector)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if plain.toConnectorEntry().ApprovalFor("anything").Required {
		t.Error("a connector with no marks needs only the grant")
	}
}

func TestApproval_TheLoaderRefusesABadMark(t *testing.T) {
	cases := map[string]struct{ spec, want string }{
		"no decision":                   {"  responseActions: true\n  tools:\n    a:\n      approval: required\n    b: {}\n", `needs approval "required" or "none"`},
		"unknown value":                 {"  tools:\n    a:\n      approval: maybe\n", `needs approval`},
		"none on a read-only connector": {"  tools:\n    a:\n      approval: none\n", "only has a meaning when responseActions is true"},
		"undo missing":                  {"  tools:\n    a:\n      approval: required\n      undo: b\n", "undo tool"},
		"undo itself":                   {"  tools:\n    a:\n      approval: required\n      undo: a\n", "undo tool"},
		"response with no tools":        {"  responseActions: true\n", "needs a tools list"},
		"response with no mark":         {"  responseActions: true\n  tools:\n    a:\n      approval: none\n", "marks no tool"},
		"bad name":                      {"  tools:\n    \"a b\":\n      approval: required\n", "not a valid tool name"},
		"unknown role":                  {"  tools:\n    a:\n      role: deploy\n", `needs role "merge"`},
		"role with no approval on a response connector": {
			"  responseActions: true\n  tools:\n    a:\n      approval: required\n    m:\n      role: merge\n",
			`needs approval "required" or "none"`,
		},
		"long radius": {"  tools:\n    a:\n      approval: required\n      blastRadius: " + strings.Repeat("x", 201) + "\n", "blastRadius"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := loadOne(t, responseConnector+c.spec)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want an error with %q, got %v", c.want, err)
			}
		})
	}
}

// A Git host names its merge tool with the role merge (gibson#1458). The
// entry needs no approval, and the other tools keep the open path.
func TestApproval_AManifestMarksTheMergeTool(t *testing.T) {
	m, err := loadOne(t, responseConnector+`  tools:
    merge_merge_request:
      role: merge
`)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	e := m.toConnectorEntry()
	if got := e.ApprovalFor("merge_merge_request"); !got.Merge || got.Required {
		t.Errorf("merge_merge_request = %+v, want the merge role and no approval", got)
	}
	if got := e.ApprovalFor("list_merge_requests"); got.Merge || got.Required {
		t.Errorf("an unnamed tool = %+v, want the grant only", got)
	}
}

func TestApproval_AnUnknownConnectorGetsTheStrictRule(t *testing.T) {
	if !LookupToolApproval("no-such-connector", "t").Required {
		t.Fatal("want the strict rule")
	}
}
