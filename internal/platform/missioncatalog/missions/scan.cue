// The Scan mission — the work-graph the always-on agent originates on every
// successful pipeline, and the one a person submits by hand to rehearse it.
//
// Three views of one Application converge on the same nodes in the tenant's
// knowledge graph:
//
//   image    trivy  → Image, Package, Vulnerability, Finding
//   source   zerocool (semgrep + triage) → Finding
//   runtime  naabu → httpx → nuclei → tlsx → Host, Port, Service, Finding
//
// The three branches are independent and are scheduled together; `report`
// joins them so the mission has one completion, which is what lets a rescan
// reconcile what it did not see this time.
//
// Parameters (ADR-0118). The caller supplies `_params`; every field is
// required, and CUE refuses the render if one is missing rather than
// substituting an empty string into a scan target:
//
//   application    the Application key every observation hangs off
//   repositoryUrl  the git remote the source branch clones
//   ref            the branch the pipeline built
//   commit         the exact commit the pipeline built
//   pipelineId     the pipeline that triggered this scan
//   pipelineUrl    that pipeline, for a human following the trail
//   imageRef       the image that pipeline published, by digest
//   forgeConnector OPTIONAL. The connector of the Git host, by catalog id:
//                  github-fixloop or gitlab-fixloop. With it the scan has the
//                  alerts node. Without it the scan has no alerts node, and the
//                  seven other parameters launch the scan as before.
//
// The runtime branch reads `{{target.domain}}`, bound from the mission's
// target at submit — never from a parameter, so a caller cannot point a
// scan at a host the tenant has not registered.

import (
	"list"

	missionv1 "github.com/zeroroot-ai/sdk/api/proto/gibson/mission/v1"
)

_params: {
	application:    string
	repositoryUrl:  string
	ref:            string
	commit:         string
	pipelineId:     string
	pipelineUrl:    string
	imageRef:       string
	// forgeConnector is optional. It is an enum, so a caller cannot name another
	// connector for the node that the daemon ingests.
	forgeConnector?: "github-fixloop" | "gitlab-fixloop"
}

// _withAlerts is true when the caller named the connector of the Git host.
_withAlerts: *false | bool
if _params.forgeConnector != _|_ {
	_withAlerts: true
}

// _alertsIDs is the id of the alerts node, or none.
_alertsIDs: [...string]
_alertsIDs: [if _withAlerts {"alerts"}]

// _context is attached to the agent node's task so the child inherits the
// provenance of the scan without re-deriving it. The keys match what the
// zerocool agent reads (GIBSON_AGENT_TASK_B64 → Task.context).
//
// Task.context is map[string]TypedValue, not map[string]string, so every
// value is wrapped. An agent that reads these as plain strings drops every
// key silently — the defect zerocool-plugins#90 fixed on the agent side.
_context: {
	"zerocool.task": {stringValue: "source-analysis"}
	"application": {stringValue: _params.application}
	"pipeline.id": {stringValue: _params.pipelineId}
	"pipeline.url": {stringValue: _params.pipelineUrl}
	"repository.url": {stringValue: _params.repositoryUrl}
	"repository.ref": {stringValue: _params.ref}
	"repository.commit": {stringValue: _params.commit}
	"image.ref": {stringValue: _params.imageRef}
}

mission: missionv1.#MissionDefinition & {
	name:        "scan"
	description: "Scan one Application from four sides: its image, its source, what it is actually running, and the dependency alerts of its Git host."
	version:     "1.0.0"
	targetRef:   ""

	nodes: {
		// ---- image ------------------------------------------------------
		image: {
			id:   "image"
			type: missionv1.#NODE_TYPE_TOOL
			toolConfig: {
				toolName: "trivy"
				input: {image: _params.imageRef}
			}
		}

		// ---- source -----------------------------------------------------
		source: {
			id:   "source"
			type: missionv1.#NODE_TYPE_AGENT
			agentConfig: {
				agentName: "zerocool"
				task: {
					id:      "source"
					goal:    "Scan the \(_params.application) repository at commit \(_params.commit) and submit a Finding for every real weakness you can support with evidence."
					context: _context
				}
			}
		}

		// ---- runtime ----------------------------------------------------
		// Ordered because each stage narrows the next: open ports before
		// live HTTP services, services before web templates and TLS.
		ports: {
			id:   "ports"
			type: missionv1.#NODE_TYPE_TOOL
			toolConfig: {
				toolName: "naabu"
				input: {target: "{{target.domain}}"}
			}
		}
		services: {
			id:   "services"
			type: missionv1.#NODE_TYPE_TOOL
			toolConfig: {
				toolName: "httpx"
				input: {target: "{{target.domain}}"}
			}
		}
		web: {
			id:   "web"
			type: missionv1.#NODE_TYPE_TOOL
			toolConfig: {
				toolName: "nuclei"
				input: {target: "{{target.domain}}"}
			}
		}
		tls: {
			id:   "tls"
			type: missionv1.#NODE_TYPE_TOOL
			toolConfig: {
				toolName: "tlsx"
				input: {host: "{{target.domain}}"}
			}
		}

		// ---- dependency alerts ------------------------------------------
		// The buyer's own alerts on the Git host, read through the connector of
		// the tenant (the grant, the kill switch and the audit record apply). Each
		// open alert is a Finding of this scan, so a rescan that reads no open
		// alert for it verifies the fix (gibson#1469).
		//
		// The daemon derives the project from repositoryUrl with the parsing of
		// the scan anchors, and it checks that the result names that project. The
		// node never carries a project of its own. If the node fails (no tool, a
		// refusal, a plan with no alerts), the daemon records the reason as the
		// result of the node and the join goes on.
		if _withAlerts {
			alerts: {
				id:   "alerts"
				type: missionv1.#NODE_TYPE_TOOL
				toolConfig: {
					toolName: "mcp:\(_params.forgeConnector):list_dependency_alerts"
					input: {repositoryUrl: _params.repositoryUrl, state: "all"}
				}
			}
		}

		// ---- join -------------------------------------------------------
		// One completion for the whole scan. A rescan can only decide that a
		// `fixed` Finding is `verified` — that it did not see it again — if
		// it knows every branch finished looking.
		report: {
			id:   "report"
			type: missionv1.#NODE_TYPE_JOIN
			joinConfig: {
				waitFor: list.Concat([["image", "source", "tls"], _alertsIDs])
				strategy: missionv1.#MERGE_STRATEGY_CONCAT
			}
			dependencies: list.Concat([["image", "source", "tls"], _alertsIDs])
		}
	}

	edges: [
		{from: "ports", to: "services"},
		{from: "services", to: "web"},
		{from: "web", to: "tls"},
		{from: "image", to: "report"},
		{from: "source", to: "report"},
		{from: "tls", to: "report"},
		for _, id in _alertsIDs {from: id, to: "report"},
	]

	entryPoints: list.Concat([["image", "source", "ports"], _alertsIDs])
	exitPoints: ["report"]
}
