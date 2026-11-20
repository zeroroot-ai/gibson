// The security test mission: attack one target and report what is proven.
//
// One red agent tests one target. It raises a finding for each proof that the
// daemon settles, and the report holds each finding with its proof, its
// technique and its replay. The mission does not fix anything. It has no job
// node, no repository and no connector, so it cannot change the target or the
// code of the target.
//
// Scope. The tenant sets the scope when it registers a target. The mission
// reads the target from `{{target.url}}`, bound from the mission target at
// submit, and never from a parameter. The mission sets no `research` flag, so
// the network scope of the agent node is the bound target and nothing else
// (owner decision S6). A target that the tenant did not register cannot bind,
// so the run is refused before it starts.
//
// The agent attacks with the attack predicates of the `main` pack. The list in
// `_techniques` is the same list. The daemon refuses a proof for a technique
// that is not in the list. A destructive predicate goes to the approval queue
// (ADR-0132), so the run waits for a person only on that one step.
//
// Parameters (ADR-0118). Every field is required:
//
//   application  the name of the thing under test, for the report
//
// The agent `red-agent` is not in the component catalog yet (gibson#1511). The
// catalog test does not check the name of an agent, so this mission renders,
// but a dispatch fails until the manifest exists.

import missionv1 "github.com/zeroroot-ai/sdk/api/proto/gibson/mission/v1"

_params: {
	application: string
}

// _techniques are the attack predicates of the main pack. A technique is the
// name of its predicate (ADR-0131).
_techniques: [
	"unauthenticated_endpoint_exposed",
	"credential_disclosure_detected",
	"privileged_container_detected",
	"node_token_readable",
	"rbac_write_access_proven",
]

_context: {
	"red.task":        {stringValue: "security-test"}
	"application":     {stringValue: _params.application}
	"scope.target":    {stringValue: "{{target.url}}"}
	"scope.name":      {stringValue: "{{target.name}}"}
	"report.contents": {stringValue: "finding, proof, technique, replay"}
	"fix":             {stringValue: "never"}
}

mission: missionv1.#MissionDefinition & {
	name:        "security-test"
	description: "Attack one target inside the scope that the tenant set, raise a finding for each proof, and report each finding with its proof, its technique and its replay."
	version:     "1.0.0"
	targetRef:   ""

	constraints: {
		allowedTechniques: _techniques
		requireEvidence:   true
	}

	nodes: {
		attack: {
			id:   "attack"
			type: missionv1.#NODE_TYPE_AGENT
			agentConfig: {
				agentName: "red-agent"
				task: {
					id:      "attack"
					goal:    "Test \(_params.application) at {{target.url}}. For each flaw that you can prove, call SubmitProof with the predicate of its technique and the recorded tool calls. Raise one finding for each proof that settles. Do not change the target and do not fix anything. Do not contact a host other than {{target.url}}. Before a destructive step, request authorization and wait for the decision."
					context: _context
				}
			}
		}

		// One completion for the run, so the report is written once and the
		// replay of each proof is complete before it is read.
		report: {
			id:   "report"
			type: missionv1.#NODE_TYPE_JOIN
			joinConfig: {
				waitFor: ["attack"]
				strategy: missionv1.#MERGE_STRATEGY_CONCAT
			}
			dependencies: ["attack"]
		}
	}

	edges: [
		{from: "attack", to: "report"},
	]

	entryPoints: ["attack"]
	exitPoints: ["report"]
}
