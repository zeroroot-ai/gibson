// The incident response mission: one alert in, one contained incident, one
// fixed cause and one report out.
//
// A tool of the buyer raised the alert. An always-on agent or an A2A message
// starts this mission with the id of the Alert node (ADR-0177, ADR-0180).
//
//   triage    read the Alert node. Find or create the Incident node and join the
//             alert to it with PART_OF. An alert is never a finding.
//   reach     find in the graph what the incident reaches: the identities, hosts,
//             workloads and applications that the alert AFFECTS, and what they
//             touch.
//   contain   stop the spread with response actions inside the grant. The
//             daemon decides if the agent can make a call. The grant is the one
//             limit, and no person approves a call that the grant allows
//             (ADR-0108). A tool that a person cannot undo goes to the approval
//             queue at tool dispatch (ADR-0132, gibson#1474).
//   isolate   isolate a Kubernetes workload with a network policy. The change is
//             a merge request in the GitOps repo of the buyer, and the agent
//             merges it. The agent makes no direct change to a cluster.
//   cause     raise a finding for the cause. Link it with CAUSED_BY from the
//             Incident node.
//   fix       fix the cause through the fix loop (ADR-0178, ADR-0179).
//   release   release each containment after the finding of the cause is
//             `verified`. A containment stops its target on purpose, so the
//             health signal rule does not apply to it and a failed health
//             signal of an isolated target starts no revert (ADR-0180).
//   report    one completion for the incident.
//
// A response action outside the grant. The daemon refuses the call. The agent
// does not retry it and does not look for another tool with the same effect.
// The `contain` goal tells the agent to record the refusal on the Incident
// node, and the Timeline holds the refused call with its error. The incident
// report lists it as refused.
//
// Parameters (ADR-0118). Every field is required:
//
//   alertId                 the key of the Alert node that starts the mission
//   bank                    the bank of always-on members that the Git jobs run on
//   forgeConnector          the connector that holds the Git host credential
//   manifestsProject        the project path that holds the manifests of the workloads
//   observabilityConnector  the connector that holds the health signal
//
// Not built yet.
//
//   - The agent `incident-response` is not in the component catalog. No agent
//     repo for it exists, so a dispatch of the `triage`, `reach`, `contain`,
//     `cause` and `release` nodes fails until the manifest exists.
//   - The response actions are MCP servers in the `connectors` repo
//     (branch feat/first-servers). The catalog holds no manifest for them, so
//     the tool ids below name the connector by the id of its directory.
//   - The check at tool dispatch for a tool that a person cannot undo
//     (gibson#1474) is built by another lane. Until it lands, the grant is
//     the only limit.
//   - The mission constraints have no hold time for the health signal (ADR-0179
//     gap), so the fix goal states it in words.

import (
	missionv1 "github.com/zeroroot-ai/sdk/api/proto/gibson/mission/v1"
	jobv1 "github.com/zeroroot-ai/sdk/api/proto/gibson/job/v1"
)

_params: {
	alertId:                string
	bank:                   string
	forgeConnector:         string
	manifestsProject:       string
	observabilityConnector: string
}

// _responseTools is the set of response actions that the agent can ask for. A
// call outside the grant of the agent is refused by the daemon. The list is a
// hint for the agent. It is not an authorization.
_responseTools: {
	identity: "mcp:okta:revoke_user_sessions, mcp:okta:suspend_user, mcp:entra-id:revoke_sign_in_sessions, mcp:entra-id:disable_account"
	host:     "mcp:crowdstrike:contain_host, mcp:defender-endpoint:isolate_device, mcp:sentinelone:disconnect_from_network"
}

// _releaseTools undoes each response action that has an undo. A session has no
// undo. The user signs in again.
_releaseTools: {
	identity: "mcp:okta:unsuspend_user, mcp:entra-id:enable_account"
	host:     "mcp:crowdstrike:lift_containment, mcp:defender-endpoint:release_device, mcp:sentinelone:reconnect_to_network"
}

_manifests: jobv1.#RepositorySpec & {
	name:         "manifests"
	connectorRef: "connector/\(_params.forgeConnector)"
	project:      _params.manifestsProject
	deliverable:  jobv1.#DELIVERABLE_KIND_MERGE_REQUEST
}

_context: {
	"alert.id": {stringValue: _params.alertId}
}

mission: missionv1.#MissionDefinition & {
	name:        "incident-response"
	description: "Take one alert, find what the incident reaches, contain it inside the grant, fix its cause, release the containment after the fix is verified, and write the report."
	version:     "1.0.0"
	targetRef:   ""

	nodes: {
		// ---- triage -----------------------------------------------------
		triage: {
			id:   "triage"
			type: missionv1.#NODE_TYPE_AGENT
			agentConfig: {
				agentName: "incident-response"
				task: {
					id: "triage"
					goal: "Read the Alert node \(_params.alertId). Find the Incident node that the alert belongs to. When no Incident node exists, create one. Join the alert to the Incident node with PART_OF. Do not raise a finding for the alert. Do not contain anything in this step."
					context: _context & {"ir.task": {stringValue: "triage"}}
				}
			}
		}

		// ---- reach ------------------------------------------------------
		reach: {
			id:   "reach"
			type: missionv1.#NODE_TYPE_AGENT
			agentConfig: {
				agentName: "incident-response"
				task: {
					id: "reach"
					goal: "Read the graph. List each identity, host, workload and application that the alerts of the Incident node AFFECT. Follow the edges from each of them to what they reach. Record each place with an AFFECTS edge from the alert. Do not change any target in this step."
					context: _context & {"ir.task": {stringValue: "reach"}}
				}
			}
			dependencies: ["triage"]
		}

		// ---- contain ----------------------------------------------------
		contain: {
			id:   "contain"
			type: missionv1.#NODE_TYPE_AGENT
			agentConfig: {
				agentName: "incident-response"
				task: {
					id: "contain"
					goal: "Contain the identities and the hosts that the incident reaches. Use only the response actions in the context. Make each call once, with the id of one identity or one host. The daemon refuses a call that your grant does not allow. When the daemon refuses a call, or answers pending authorization, do not retry it and do not use another tool for the same effect. Record the tool id and the reason on the Incident node, as the property refused.<tool id>. Go on with the next action. Do not isolate a Kubernetes workload in this step."
					context: _context & {
						"ir.task":                {stringValue: "contain"}
						"response.tools.identity": {stringValue: _responseTools.identity}
						"response.tools.host":     {stringValue: _responseTools.host}
					}
				}
			}
			dependencies: ["reach"]
		}

		// ---- isolate ----------------------------------------------------
		isolate: {
			id:   "isolate"
			type: missionv1.#NODE_TYPE_JOB
			jobConfig: {
				bankRef: _params.bank
				spec: {
					goal: "For each Kubernetes workload that the incident reaches, add one network policy that isolates it. Put the policy in the manifests of this repository. Open one merge request for each workload, and merge it when the pipeline is green. Do not change the cluster in any other way. Do not read the health signal of an isolated workload. When the incident reaches no Kubernetes workload, do nothing."
					repositories: [_manifests]
					inputs: ["{{findings.open}}"]
				}
			}
			dependencies: ["reach"]
		}

		// ---- cause ------------------------------------------------------
		cause: {
			id:   "cause"
			type: missionv1.#NODE_TYPE_AGENT
			agentConfig: {
				agentName: "incident-response"
				task: {
					id: "cause"
					goal: "Find the cause of the incident. Raise one finding for the cause, with evidence. Link the Incident node to the finding with CAUSED_BY. A finding has a fix, and an alert has none, so raise a finding only for the cause. Do not fix anything in this step."
					context: _context & {"ir.task": {stringValue: "cause"}}
				}
			}
			dependencies: ["contain", "isolate"]
		}

		// ---- fix --------------------------------------------------------
		fix: {
			id:   "fix"
			type: missionv1.#NODE_TYPE_JOB
			jobConfig: {
				bankRef: _params.bank
				spec: {
					goal: "Fix the cause of the incident. Fix the finding that the Incident node names with CAUSED_BY, in the manifests of this repository. Open one merge request, name the finding in it, and merge it when the pipeline is green. After the deploy, read the health signal of the service through the connector \(_params.observabilityConnector). Hold the signal for the hold time of the service. When the signal fails, revert your merge and leave the finding open. Do not release any containment."
					repositories: [_manifests]
					inputs: ["{{findings.open}}"]
				}
			}
			dependencies: ["cause"]
		}

		// ---- release ----------------------------------------------------
		// The release runs after the fix. It acts only on a finding that is
		// `verified`. A finding that is not `verified` leaves each containment
		// in place, and the report says so.
		release: {
			id:   "release"
			type: missionv1.#NODE_TYPE_AGENT
			agentConfig: {
				agentName: "incident-response"
				task: {
					id: "release"
					goal: "Read the status of the finding that the Incident node names with CAUSED_BY. When the status is verified, release each containment that you made, with the matching release action in the context. When the status is not verified, release nothing and record that the containment stays. Do not read the health signal of a contained target. Do not release a containment that you did not make."
					context: _context & {
						"ir.task":                {stringValue: "release"}
						"release.tools.identity": {stringValue: _releaseTools.identity}
						"release.tools.host":     {stringValue: _releaseTools.host}
					}
				}
			}
			dependencies: ["fix"]
		}

		releaseWorkloads: {
			id:   "releaseWorkloads"
			type: missionv1.#NODE_TYPE_JOB
			jobConfig: {
				bankRef: _params.bank
				spec: {
					goal: "Read the status of the finding that the Incident node names with CAUSED_BY. When the status is verified, remove each network policy that the isolate step added. Make the change in a second commit, as one merge request, and merge it when the pipeline is green. When the status is not verified, change nothing. Do not read the health signal of an isolated workload."
					repositories: [_manifests]
					inputs: ["{{findings.open}}"]
				}
			}
			dependencies: ["fix"]
		}

		// ---- report -----------------------------------------------------
		report: {
			id:   "report"
			type: missionv1.#NODE_TYPE_JOIN
			joinConfig: {
				waitFor: ["release", "releaseWorkloads"]
				strategy: missionv1.#MERGE_STRATEGY_CONCAT
			}
			dependencies: ["release", "releaseWorkloads"]
		}
	}

	edges: [
		{from: "triage", to: "reach"},
		{from: "reach", to: "contain"},
		{from: "reach", to: "isolate"},
		{from: "contain", to: "cause"},
		{from: "isolate", to: "cause"},
		{from: "cause", to: "fix"},
		{from: "fix", to: "release"},
		{from: "fix", to: "releaseWorkloads"},
		{from: "release", to: "report"},
		{from: "releaseWorkloads", to: "report"},
	]

	entryPoints: ["triage"]
	exitPoints: ["report"]
}
