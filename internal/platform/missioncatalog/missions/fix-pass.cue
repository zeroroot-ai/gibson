// The Fix pass mission: one pass of the fix agent over one Application.
//
// The mission has one agent node. The node runs `fix-agent`. The agent reads
// the open Findings of the Application, sends the highest priority one that it
// can fix to a coding job on a bank, and ends after the merge step. The child
// coding mission is `fix` (fix.cue). The agent originates it by name.
//
// # The node timeout
//
// A sandboxed agent node with no timeout gets 30 minutes from the launcher
// (defaultAgentRunTimeout). One pass can need more: the coding job (up to
// codingTimeout) and up to two merge waits (mergeWait each). The sandbox would
// stop the pass at 30 minutes and leave the merge request open.
//
// So this mission always sets the node timeout. It derives the value from the
// two durations the caller can set, so the node timeout can never fall below
// them:
//
//   timeout = codingTimeout + 2 x mergeWait + 15 minutes of margin
//
// With the defaults (45m and 30m) the node timeout is 2 hours.
//
// Parameters (ADR-0118):
//
//   application     the Application to fix (required)
//   bank            the bank of coding agents, by id or name (required)
//   forgeConnector  the connector of the Git host, by catalog id (required)
//   project         the project path on the Git host (required)
//   finding         one Finding to fix. Without it the agent takes the highest
//                   priority first.
//   target          the target id of the coding mission
//   baseBranch      the branch that the merge request targets
//   repository      the directory name of the worktree
//   codingTimeout   the wait for the coding job, a Go duration. Default 45m.
//   mergeWait       the wait for the merge slot, a Go duration. Default 30m.

import (
	"time"

	missionv1 "github.com/zeroroot-ai/sdk/api/proto/gibson/mission/v1"
)

_params: {
	application:    string
	bank:           string
	forgeConnector: string
	project:        string
	finding?:       string
	target?:        string
	baseBranch?:    string
	repository?:    string
	codingTimeout?: string
	mergeWait?:     string
}

// The durations. The defaults are the defaults of fix-agent 0.2.0.
_codingTimeout: *"45m" | string
if _params.codingTimeout != _|_ {
	_codingTimeout: _params.codingTimeout
}
_mergeWait: *"30m" | string
if _params.mergeWait != _|_ {
	_mergeWait: _params.mergeWait
}

// time.ParseDuration returns nanoseconds. A value that is not a duration, or
// that is not above zero, fails the render.
_codingNs: time.ParseDuration(_codingTimeout) & >0
_mergeNs:  time.ParseDuration(_mergeWait) & >0

// Two merge waits (the agent can wait for a resumed merge and for its own) and
// 15 minutes of margin for the start and the report.
_marginSeconds: 900
_nodeSeconds:   div(_codingNs+2*_mergeNs, 1000000000) + _marginSeconds

// _context is the task context that fix-agent reads. Each value is a
// TypedValue, so an agent that reads plain strings must read the string form.
_context: {
	"application": {stringValue: _params.application}
	"bank":        {stringValue: _params.bank}
	"connector":   {stringValue: "connector/\(_params.forgeConnector)"}
	"project":     {stringValue: _params.project}
	"timeout":     {stringValue: _codingTimeout}
	"merge_wait":  {stringValue: _mergeWait}
	if _params.finding != _|_ {
		"finding": {stringValue: _params.finding}
	}
	if _params.target != _|_ {
		"target": {stringValue: _params.target}
	}
	if _params.baseBranch != _|_ {
		"base_branch": {stringValue: _params.baseBranch}
	}
	if _params.repository != _|_ {
		"repository": {stringValue: _params.repository}
	}
}

mission: missionv1.#MissionDefinition & {
	name:        "fix-pass"
	description: "Run one pass of the fix agent over one Application: fix one Finding and open one merge request."
	version:     "1.0.0"
	targetRef:   ""

	nodes: {
		pass: {
			id:      "pass"
			type:    missionv1.#NODE_TYPE_AGENT
			timeout: "\(_nodeSeconds)s"
			agentConfig: {
				agentName: "fix-agent"
				task: {
					id:      "pass"
					goal:    "Fix one open Finding of \(_params.application) and open one merge request."
					context: _context
				}
			}
		}
	}

	entryPoints: ["pass"]
	exitPoints: ["pass"]
}
