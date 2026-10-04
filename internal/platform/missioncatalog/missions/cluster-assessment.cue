// The cluster assessment mission — benchmark, workloads, exploit, fix, report.
//
// It assesses one Kubernetes cluster and fixes what it finds. It is
// parameterized by its target, not written for one cluster: the mission names
// no host, no cluster and no credential value. The cluster it runs against is
// the Target a person submits it with, and the kubeconfig arrives as a name.
//
// The shape follows the `scan` mission: independent branches scheduled
// together, joined by `report`, so the run has ONE completion. That is what
// lets a rescan reconcile what it did not see — a `fixed` Finding can only
// become `verified` by a later run that looked and did not find it again.
//
// Four branches:
//
//   benchmark  kube-bench  CIS policies section, through the Kubernetes API
//   workloads  trivy-k8s   workload misconfiguration, through the same API
//   exploit    a job       which open findings are genuinely exploitable
//   fix        a job       a merge request per finding it fixes
//
// The two tool branches are independent: a cluster's controls and its workloads
// are different questions and neither narrows the other. The two job branches
// depend on the tools, because a job that opens before anything has been found
// has nothing to work on.
//
// Parameters (ADR-0018). Every field is required, and CUE refuses the render if
// one is missing rather than substituting an empty string:
//
//   kubeconfigSecret  the tenant secret holding the cluster's kubeconfig
//   bank              the bank of always-on members the two jobs run on
//   forgeConnector    the connector holding the forge credential
//   manifestsProject  the project path holding the cluster's manifests
//
// The kubeconfig is a NAME here, never a value (gibson#485). `secrets.tools`
// declares it, so every tool node in this run may be handed it; the daemon
// resolves it as itself at dispatch and the value reaches the tool in its
// environment. A tool's input JSON is captured with the tool call, so a value
// written into `input` would be stored and displayed — which is why each tool
// receives the secret's NAME in `kubeconfigSecret` and reads the value from
// GIBSON_SECRET_<NAME>.
//
// The two jobs declare the same secret through `credentialNames`, the job's own
// per-turn grant. A job member is not a tool dispatch and does not read the
// tool environment.

import (
	missionv1 "github.com/zeroroot-ai/sdk/api/proto/gibson/mission/v1"
	jobv1 "github.com/zeroroot-ai/sdk/api/proto/gibson/job/v1"
)

_params: {
	kubeconfigSecret: string
	bank:             string
	forgeConnector:   string
	manifestsProject: string
}

// _manifests is the one repository both jobs work in: the cluster's own
// manifests. The exploit job reads it to understand what it is attacking; the
// fix job changes it and opens a merge request.
_manifests: jobv1.#RepositorySpec & {
	name:         "manifests"
	connectorRef: "connector/\(_params.forgeConnector)"
	project:      _params.manifestsProject
	deliverable:  jobv1.#DELIVERABLE_KIND_MERGE_REQUEST
}

mission: missionv1.#MissionDefinition & {
	name:        "cluster-assessment"
	description: "Assess one Kubernetes cluster from its controls and its workloads, prove what is exploitable, and open a merge request per finding fixed."
	version:     "1.0.0"
	targetRef:   ""

	// Every tool node in this run may be handed the cluster's kubeconfig. Both
	// tool branches need it and neither can be told apart from the other by
	// kind, so the declaration is tool-wide rather than per-name.
	secrets: tools: [_params.kubeconfigSecret]

	nodes: {
		// ---- benchmark --------------------------------------------------
		benchmark: {
			id:   "benchmark"
			type: missionv1.#NODE_TYPE_TOOL
			toolConfig: {
				toolName: "kube-bench"
				input: {
					target:           "{{target.name}}"
					kubeconfigSecret: _params.kubeconfigSecret
				}
			}
		}

		// ---- workloads --------------------------------------------------
		workloads: {
			id:   "workloads"
			type: missionv1.#NODE_TYPE_TOOL
			toolConfig: {
				toolName: "trivy-k8s"
				input: {
					target:           "{{target.name}}"
					kubeconfigSecret: _params.kubeconfigSecret
				}
			}
		}

		// ---- exploit ----------------------------------------------------
		// {{findings.open}} resolves at job open to the open findings on this
		// run's target, server-side (gibson#497). A mission definition cannot
		// name finding ids: the run is what produces them.
		//
		// No acceptance block, so no verify loop runs and a person or an agent
		// closes the job. There is no component today whose job is to score
		// "did you record proof", and naming one that does not exist would
		// fail at the first turn rather than at the render.
		exploit: {
			id:   "exploit"
			type: missionv1.#NODE_TYPE_JOB
			jobConfig: {
				bankRef: _params.bank
				spec: {
					goal: "For each finding you are given, decide whether it is genuinely exploitable on this cluster, and record what you did as evidence. Do not change the cluster and do not change the manifests. A finding you cannot exploit is a result worth recording."
					repositories: [_manifests]
					credentialNames: [_params.kubeconfigSecret]
					inputs: ["{{findings.open}}"]
				}
			}
			dependencies: ["benchmark", "workloads"]
		}

		// ---- fix --------------------------------------------------------
		fix: {
			id:   "fix"
			type: missionv1.#NODE_TYPE_JOB
			jobConfig: {
				bankRef: _params.bank
				spec: {
					goal: "For each finding you are given that the manifests in this repository can fix, change the manifests and open one merge request per finding. Name the finding in the merge request. Leave a finding alone when the fix is not in this repository."
					repositories: [_manifests]
					credentialNames: [_params.kubeconfigSecret]
					inputs: ["{{findings.open}}"]
				}
			}
			dependencies: ["benchmark", "workloads"]
		}

		// ---- report -----------------------------------------------------
		// One completion for the whole assessment, so a later run knows every
		// branch finished looking before it decides a finding is gone.
		report: {
			id:   "report"
			type: missionv1.#NODE_TYPE_JOIN
			joinConfig: {
				waitFor: ["exploit", "fix"]
				strategy: missionv1.#MERGE_STRATEGY_CONCAT
			}
			dependencies: ["exploit", "fix"]
		}
	}

	edges: [
		{from: "benchmark", to: "exploit"},
		{from: "benchmark", to: "fix"},
		{from: "workloads", to: "exploit"},
		{from: "workloads", to: "fix"},
		{from: "exploit", to: "report"},
		{from: "fix", to: "report"},
	]

	entryPoints: ["benchmark", "workloads"]
	exitPoints: ["report"]
}
