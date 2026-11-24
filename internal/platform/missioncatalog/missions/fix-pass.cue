// The Fix pass mission: one pass of the fix agent over one Application.
//
// The mission has one agent node. The node runs `fix-agent`. The agent reads
// the open Findings of the Application, sends the highest priority one that it
// can fix to a coding job on a bank, and ends after the merge step. In 0.2.0 the
// agent builds its own job graph, named "fix <finding id>", and sends it as JSON.
// It does not start the catalog mission `fix` (fix.cue).
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
// the worst case of fix-agent 0.2.0:
//
//   one merge wait for an older open merge request,
//   one or three coding jobs, and
//   one merge wait for the new merge request.
//
// A coding job takes up to codingTimeout plus 30 seconds for the status read.
// With `finding` set the agent works one Finding with one attempt. Without it
// the agent can start three coding jobs (MaxAttempts in fix-agent). So:
//
//   finding set:     codingTimeout + 30s   + 2 x mergeWait + 15 minutes of margin
//   finding not set: 3 x (codingTimeout + 30s) + 2 x mergeWait + 15 minutes of margin
//
// With the defaults (45m and 30m) the node timeout is 2h0m30s with `finding`
// and 3h31m30s without it. The test guard in fix_pass_mission_test.go holds the
// same model of the pass, with a smaller margin of 10 minutes.
//
// Parameters (ADR-0118):
//
//   application     the Application to fix (required)
//   bank            the bank of coding agents, by id or name (required)
//   forgeConnector  the connector of the Git host, by catalog id (required)
//   project         the project path on the Git host (required)
//   finding         one Finding to fix. Without it the agent takes the highest
//                   priority first.
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
	baseBranch?:    string
	repository?:    string
	// The two durations are Go durations, because the mission derives its node
	// timeout from them. A bare string would not render.
	codingTimeout?: string @example("40m")
	mergeWait?:     string @example("40m")
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

// time.ParseDuration returns nanoseconds. A value that is not a duration, that
// is not above zero, or that is above 8 hours fails the render. The cap keeps a
// caller from holding a sandbox slot for days.
_maxDurationNs: 28800000000000
_codingNs:      time.ParseDuration(_codingTimeout) & >0 & <=_maxDurationNs
_mergeNs:       time.ParseDuration(_mergeWait) & >0 & <=_maxDurationNs

// The attempts of one pass: one with a named Finding, three (MaxAttempts of
// fix-agent) without it. Each coding job takes up to the coding timeout plus 30
// seconds for the status read.
_attempts: *3 | int
if _params.finding != _|_ {
	_attempts: 1
}
_jobNs: _codingNs + 30000000000

// Two merge waits (the agent can wait for a resumed merge and for its own) and
// 15 minutes of margin for the start and the report.
_marginSeconds: 900
_nodeSeconds:   div(_attempts*_jobNs+2*_mergeNs, 1000000000) + _marginSeconds

// _context is the task context that fix-agent reads. Each value is a
// TypedValue, so an agent that reads plain strings must read the string form.
_context: {
	"application": {stringValue: _params.application}
	"bank":        {stringValue: _params.bank}
	"connector":   {stringValue: "connector/\(_params.forgeConnector)"}
	"project":     {stringValue: _params.project}
	// The target of the coding mission is the target of this run. The daemon
	// binds the placeholder when the run starts, from the target that the
	// caller owns. No parameter can name a target (gibson#497).
	"target":      {stringValue: "{{target.id}}"}
	"timeout":     {stringValue: _codingTimeout}
	"merge_wait":  {stringValue: _mergeWait}
	if _params.finding != _|_ {
		"finding": {stringValue: _params.finding}
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
