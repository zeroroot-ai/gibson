// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package componentcatalog

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// The approval mark of a connector tool (gibson#1474, ADR-0180).
//
// A response action is a tool call through a connector, for example "isolate a
// host" or "disable an account". A response action waits for a person only
// when it destroys data (owner decision of 2026-11-20, ADR-0180). Revoke a
// session, disable an account and isolate a host carry no approval mark: the
// grant is enough. The manifest of the connector marks each tool that destroys
// data. The daemon reads the mark at tool dispatch. The agent never selects
// it, and neither does the MCP server of the connector: the party that the
// gate controls must not choose the gate.
//
// The manifest holds one entry for each tool that it names:
//
//	responseActions: true
//	tools:
//	  delete_device:
//	    approval: required
//	    blastRadius: one device and its data
//	  isolate_host:
//	    approval: none
//	    undo: release_host
//	  release_host:
//	    approval: none
//	  revoke_session:
//	    approval: none
//	  disable_account:
//	    approval: none
//
// The rule for a tool that the manifest does not name depends on
// responseActions:
//
//   - responseActions is true: the tool needs approval. A new tool of the MCP
//     server waits for a person until a manifest names it (fail closed). This
//     is the deliberate default: the platform cannot know if a new tool
//     destroys data.
//   - responseActions is false or absent: the tool needs only the grant. These
//     are the connectors that read. They state no tool, and the platform has
//     no list of the tools of a vendor to check against.
//
// An entry can also state the role of a tool (gibson#1458). The one role is
// "merge": the tool merges a merge request on the Git host. The daemon runs a
// call of that tool only when the World holds the merge slot of the merge
// request (brain.World.MayMerge). The approval of an entry with a role can stay
// empty when responseActions is false, and the tool then needs only the grant
// and the slot:
//
//	tools:
//	  merge_merge_request:
//	    role: merge

// Values of ConnectorTool.Approval.
const (
	// ApprovalRequired means that a person must approve each call.
	ApprovalRequired = "required"
	// ApprovalNone means that the grant (can_execute) is enough.
	ApprovalNone = "none"
)

// ToolRoleMerge is the role of a tool that merges a merge request.
const ToolRoleMerge = "merge"

// ConnectorTool is the manifest entry of one tool of a connector.
type ConnectorTool struct {
	// Approval is "required" or "none". It is empty only on an entry that
	// states a role, on a connector with no response actions.
	Approval string `yaml:"approval"`
	// Role is empty or ToolRoleMerge.
	Role string `yaml:"role"`
	// Undo names the tool of the same connector that undoes this tool. The
	// approver sees the call as reversible only when the manifest names one.
	Undo string `yaml:"undo"`
	// BlastRadius states in plain words what a call of the tool reaches. The
	// approver reads it with the arguments of the call.
	BlastRadius string `yaml:"blastRadius"`
}

// ToolApproval is what the daemon needs to know about one call.
type ToolApproval struct {
	// Required is true when a person must approve the call.
	Required bool
	// UndoTool is the tool that undoes this tool. Empty means that the
	// manifest states none.
	UndoTool string
	// BlastRadius is the text of the manifest. It can be empty.
	BlastRadius string
	// Merge is true when the tool merges a merge request. The call then needs
	// the merge slot of the merge request.
	Merge bool
}

var toolNameRE = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

// ApprovalFor returns the approval rule of one tool of the connector.
func (e ConnectorEntry) ApprovalFor(tool string) ToolApproval {
	if t, ok := e.Tools[tool]; ok {
		return ToolApproval{
			Required:    t.Approval == ApprovalRequired,
			UndoTool:    t.Undo,
			BlastRadius: t.BlastRadius,
			Merge:       t.Role == ToolRoleMerge,
		}
	}
	return ToolApproval{Required: e.ResponseActions}
}

// LookupToolApproval returns the approval rule of one tool of one catalog
// connector. A connector that the catalog does not list returns a rule that
// requires approval, so an unknown name never gets the open path.
func LookupToolApproval(connector, tool string) ToolApproval {
	e, err := LookupConnector(connector)
	if err != nil {
		return ToolApproval{Required: true}
	}
	return e.ApprovalFor(tool)
}

// validateTools checks the tool marks of a connector.
func validateTools(id string, s ConnectorSpec) error {
	if len(s.Tools) == 0 {
		if s.ResponseActions {
			return fmt.Errorf("%s: responseActions needs a tools list that marks each response action", id)
		}
		return nil
	}
	names := make([]string, 0, len(s.Tools))
	for name := range s.Tools {
		names = append(names, name)
	}
	sort.Strings(names)
	required := 0
	for _, name := range names {
		t := s.Tools[name]
		if !toolNameRE.MatchString(name) {
			return fmt.Errorf("%s: tools name %q is not a valid tool name", id, name)
		}
		switch t.Role {
		case "", ToolRoleMerge:
		default:
			return fmt.Errorf("%s: tool %q needs role %q or no role, got %q", id, name, ToolRoleMerge, t.Role)
		}
		switch t.Approval {
		case "":
			if t.Role == "" || s.ResponseActions {
				return fmt.Errorf("%s: tool %q needs approval %q or %q, got %q", id, name, ApprovalRequired, ApprovalNone, t.Approval)
			}
		case ApprovalRequired:
			required++
		case ApprovalNone:
			if !s.ResponseActions {
				return fmt.Errorf("%s: tool %q states approval none, but approval none only has a meaning when responseActions is true", id, name)
			}
		default:
			return fmt.Errorf("%s: tool %q needs approval %q or %q, got %q", id, name, ApprovalRequired, ApprovalNone, t.Approval)
		}
		if t.Undo != "" {
			if _, ok := s.Tools[t.Undo]; !ok || t.Undo == name {
				return fmt.Errorf("%s: tool %q names the undo tool %q, which the tools list does not hold or which is the tool itself", id, name, t.Undo)
			}
		}
		if len(t.BlastRadius) > 200 || strings.ContainsAny(t.BlastRadius, "\r\n\x00") {
			return fmt.Errorf("%s: tool %q has a blastRadius that is too long or holds a control character", id, name)
		}
	}
	if s.ResponseActions && required == 0 {
		return fmt.Errorf("%s: responseActions is true, but the tools list marks no tool as approval required", id)
	}
	return nil
}
