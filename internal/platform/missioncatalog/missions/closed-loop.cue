// The closed loop mission: attack, fix, attack again.
//
// One mission runs the whole loop on one graph (owner decision, 2026-11-19).
//
//   attack    a red agent proves each flaw of the target with the attack
//             predicates of the `main` pack, and raises a finding for each
//             proof that settles. The finding records its predicate as the
//             check that raised it (ADR-0178).
//   fix       a blue agent fixes each open finding through the fix loop. It
//             opens a merge request and merges it when the pipeline is green.
//             It reads the health signal of the service through a connector of
//             the class `observability`, and it reverts its merge when the
//             signal fails (ADR-0179).
//   reattack  the same red agent runs the same predicates again. A finding is
//             `verified` when its predicate settles false on evidence that is
//             newer than the deploy. A predicate that still settles true, on a
//             second path, leaves the finding `open`.
//   report    one completion for the run.
//
// Scope and destructive steps follow the `security-test` mission: the target
// comes from `{{target.url}}`, no node is `research`, and a destructive
// predicate goes to the approval queue (ADR-0132).
//
// Parameters (ADR-0118). Every field is required:
//
//   application             the name of the thing under test
//   bank                    the bank of always-on members that the fix job runs on
//   forgeConnector          the connector that holds the Git host credential
//   manifestsProject        the project path that holds the manifests of the target
//   observabilityConnector  the connector that holds the health signal
//
// Not built yet. The agent `red-agent` is not in the catalog (gibson#1511). The
// mission constraints have no hold time for the health signal and no wait for
// the deploy (ADR-0179 gap), so the fix goal states them in words. The status
// changes `fixing`, `fixed` and `verified` come from the epic "Fix loop".

import (
	missionv1 "github.com/zeroroot-ai/sdk/api/proto/gibson/mission/v1"
	jobv1 "github.com/zeroroot-ai/sdk/api/proto/gibson/job/v1"
)

_params: {
	application:            string
	bank:                   string
	forgeConnector:         string
	manifestsProject:       string
	observabilityConnector: string
}

_techniques: [
	"unauthenticated_endpoint_exposed",
	"credential_disclosure_detected",
	"privileged_container_detected",
	"node_token_readable",
	"rbac_write_access_proven",
]

_manifests: jobv1.#RepositorySpec & {
	name:         "manifests"
	connectorRef: "connector/\(_params.forgeConnector)"
	project:      _params.manifestsProject
	deliverable:  jobv1.#DELIVERABLE_KIND_MERGE_REQUEST
}

_context: {
	"application":  {stringValue: _params.application}
	"scope.target": {stringValue: "{{target.url}}"}
	"scope.name":   {stringValue: "{{target.name}}"}
}

mission: missionv1.#MissionDefinition & {
	name:        "closed-loop"
	description: "Attack one target, fix each proven flaw, and attack again. A finding is verified when the same attack predicate settles false on evidence that is newer than the deploy."
	version:     "1.0.0"
	targetRef:   ""

	constraints: {
		allowedTechniques: _techniques
		requireEvidence:   true
	}

	nodes: {
		// ---- attack -----------------------------------------------------
		attack: {
			id:   "attack"
			type: missionv1.#NODE_TYPE_AGENT
			agentConfig: {
				agentName: "red-agent"
				task: {
					id: "attack"
					goal: "Test \(_params.application) at {{target.url}}. For each flaw that you can prove, call SubmitProof with the predicate of its technique and the recorded tool calls. Raise one finding for each proof that settles. Do not change the target and do not fix anything. Do not contact a host other than {{target.url}}. Before a destructive step, request authorization and wait for the decision."
					context: _context & {"red.task": {stringValue: "attack"}}
				}
			}
		}

		// ---- fix --------------------------------------------------------
		fix: {
			id:   "fix"
			type: missionv1.#NODE_TYPE_JOB
			jobConfig: {
				bankRef: _params.bank
				spec: {
					goal: "For each finding that you are given, fix its cause in the manifests of this repository and open one merge request for the finding. Name the finding in the merge request. Merge it when the pipeline is green. After the deploy, read the health signal of the service through the connector \(_params.observabilityConnector). Hold the signal for the hold time of the service. When the signal fails, revert your merge and leave the finding open. Fix one service at a time. Do not attack."
					repositories: [_manifests]
					inputs: ["{{findings.open}}"]
				}
			}
			dependencies: ["attack"]
		}

		// ---- reattack ---------------------------------------------------
		// The same agent and the same predicates. A predicate that settles
		// false on evidence newer than the deploy verifies the finding. The
		// agent starts from a fresh sandbox, so it cannot reuse the old proof.
		reattack: {
			id:   "reattack"
			type: missionv1.#NODE_TYPE_AGENT
			agentConfig: {
				agentName: "red-agent"
				task: {
					id: "reattack"
					goal: "Run the attack of each finding again on \(_params.application) at {{target.url}}, with the same predicate. Collect new evidence. Call SubmitProof for each predicate. Look for a second path to the same flaw. Do not fix anything. Do not contact a host other than {{target.url}}. Before a destructive step, request authorization and wait for the decision."
					context: _context & {"red.task": {stringValue: "reattack"}}
				}
			}
			dependencies: ["fix"]
		}

		// ---- report -----------------------------------------------------
		report: {
			id:   "report"
			type: missionv1.#NODE_TYPE_JOIN
			joinConfig: {
				waitFor: ["reattack"]
				strategy: missionv1.#MERGE_STRATEGY_CONCAT
			}
			dependencies: ["reattack"]
		}
	}

	edges: [
		{from: "attack", to: "fix"},
		{from: "fix", to: "reattack"},
		{from: "reattack", to: "report"},
	]

	entryPoints: ["attack"]
	exitPoints: ["report"]
}
