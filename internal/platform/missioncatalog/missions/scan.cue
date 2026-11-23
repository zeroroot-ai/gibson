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
// Parameters (ADR-0118). Each branch runs only when its own parameters are
// present, and a scan with no branch parameter is refused at launch:
//
//   imageRef       the image that pipeline published, by digest. It starts the
//                  image branch.
//   commit         the exact commit the pipeline built. It starts the source
//                  branch, which also needs application, repositoryUrl and ref.
//   (runtime)      The runtime branch has no parameter. It runs whenever the
//                  image branch or the source branch runs, as it always did.
//                  A scan with only the alerts branch skips it. The branch reads
//                  `{{target.domain}}` and never a parameter.
//   forgeConnector the connector of the Git host, by catalog id: github-fixloop
//                  or gitlab-fixloop. It starts the alerts branch, which also
//                  needs repositoryUrl and application. Without the application
//                  the scan anchors have no Application, so the render fails.
//   application    the Application key every observation hangs off
//   repositoryUrl  the git remote of the source and the alerts branch
//   ref            the branch the pipeline built
//   pipelineId     the pipeline that triggered this scan, for the source branch
//   pipelineUrl    that pipeline, for a human following the trail
//
// A buyer with only a Git host connector launches the scan with repositoryUrl,
// application and forgeConnector, and the scan reads the dependency alerts.
//
// The runtime branch reads `{{target.domain}}`, bound from the mission's
// target at submit, never from a parameter, so a caller cannot point a scan at
// a host the tenant has not registered.

import (
	"list"

	missionv1 "github.com/zeroroot-ai/sdk/api/proto/gibson/mission/v1"
)

_params: {
	application?:    string
	repositoryUrl?: string
	ref?:           string
	commit?:        string
	pipelineId?:    string
	pipelineUrl?:   string
	imageRef?:      string
	// forgeConnector is an enum, so a caller cannot name another connector for
	// the node that the daemon ingests.
	forgeConnector?: "github-fixloop" | "gitlab-fixloop"
}

// Which branch runs. Each is true only when its own parameter is present.
_has: {
	image:   *false | bool
	source:  *false | bool
	runtime: *false | bool
	alerts:  *false | bool
}
if _params.imageRef != _|_ {
	_has: image: true
}
if _params.commit != _|_ {
	_has: source: true
}
// The runtime branch runs with the image branch or the source branch.
if _has.image || _has.source {
	_has: runtime: true
}
if _params.forgeConnector != _|_ {
	_has: alerts: true
}

// The exit node of each branch, or none.
_imageIDs: [...string]
_imageIDs: [if _has.image {"image"}]
_sourceIDs: [...string]
_sourceIDs: [if _has.source {"source"}]
_runtimeIDs: [...string]
_runtimeIDs: [if _has.runtime {"tls"}]
_alertsIDs: [...string]
_alertsIDs: [if _has.alerts {"alerts"}]
_exitIDs: list.Concat([_imageIDs, _sourceIDs, _runtimeIDs, _alertsIDs])

// A scan with no branch is refused. The targetRef of the mission is not concrete
// unless one branch runs, so the render fails. A scan needs one of imageRef,
// commit or forgeConnector.
_guard: string
if len(_exitIDs) > 0 {
	_guard: ""
}

// _context is attached to the agent node's task so the child inherits the
// provenance of the scan without re-deriving it. The keys match what the
// zerocool agent reads (GIBSON_AGENT_TASK_B64 → Task.context).
//
// Task.context is map[string]TypedValue, not map[string]string, so every
// value is wrapped. An agent that reads these as plain strings drops every
// key silently — the defect zerocool-plugins#90 fixed on the agent side.
_context: {
	"zerocool.task": {stringValue: "source-analysis"}
	// The source branch needs application, repositoryUrl, ref and commit. Each is
	// read without a guard, so the render fails when one is missing.
	"application": {stringValue: _params.application}
	if _params.pipelineId != _|_ {
		"pipeline.id": {stringValue: _params.pipelineId}
	}
	if _params.pipelineUrl != _|_ {
		"pipeline.url": {stringValue: _params.pipelineUrl}
	}
	"repository.url":    {stringValue: _params.repositoryUrl}
	"repository.ref":    {stringValue: _params.ref}
	"repository.commit": {stringValue: _params.commit}
	if _params.imageRef != _|_ {
		"image.ref": {stringValue: _params.imageRef}
	}
}

mission: missionv1.#MissionDefinition & {
	name:        "scan"
	description: "Scan one Application from up to four sides: its image, its source, what it is actually running, and the dependency alerts of its Git host."
	version:     "1.0.0"
	targetRef:   _guard

	nodes: {
		// ---- image ------------------------------------------------------
		if _has.image {
			image: {
				id:   "image"
				type: missionv1.#NODE_TYPE_TOOL
				toolConfig: {
					toolName: "trivy"
					input: {image: _params.imageRef}
				}
			}
		}

		// ---- source -----------------------------------------------------
		// Needs application, commit, repositoryUrl and ref. A missing one fails the
		// render, so the agent never scans HEAD by default.
		if _has.source {
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
		}

		// ---- runtime ----------------------------------------------------
		// Ordered because each stage narrows the next: open ports before
		// live HTTP services, services before web templates and TLS.
		if _has.runtime {
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
		if _has.alerts {
			alerts: {
				id:   "alerts"
				type: missionv1.#NODE_TYPE_TOOL
				toolConfig: {
					toolName: "mcp:\(_params.forgeConnector):list_dependency_alerts"
					input: {application: _params.application, repositoryUrl: _params.repositoryUrl, state: "all"}
				}
			}
		}

		// ---- join -------------------------------------------------------
		// One completion for the whole scan. A rescan can only decide that a
		// `fixed` Finding is `verified` if it knows every branch finished
		// looking.
		report: {
			id:   "report"
			type: missionv1.#NODE_TYPE_JOIN
			joinConfig: {
				waitFor:  _exitIDs
				strategy: missionv1.#MERGE_STRATEGY_CONCAT
			}
			dependencies: _exitIDs
		}
	}

	edges: [
		if _has.runtime {
			{from: "ports", to: "services"}
		},
		if _has.runtime {
			{from: "services", to: "web"}
		},
		if _has.runtime {
			{from: "web", to: "tls"}
		},
		for _, id in _exitIDs {from: id, to: "report"},
	]

	entryPoints: list.Concat([_imageIDs, _sourceIDs, [if _has.runtime {"ports"}], _alertsIDs])
	exitPoints: ["report"]
}
