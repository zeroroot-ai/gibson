// Cloud-config compliance check.
//
// Single-agent mission auditing cloud configuration against a
// policy baseline (e.g., CIS benchmarks for AWS / GCP / Azure).
//
// Override before submitting:
//   targetRef: "<cloud-target-name-or-id>"
//
// Spec: mission-authoring-cue Requirement 7.

import missionv1 "github.com/zero-day-ai/sdk/api/proto/gibson/mission/v1"

mission: missionv1.#MissionDefinition & {
	name:        "compliance-check"
	description: "Audit cloud configuration against a policy baseline."
	version:     "1.0.0"
	targetRef:   ""

	nodes: {
		inspect: {
			id:   "inspect"
			type: missionv1.#NODE_TYPE_AGENT
			agentConfig: {
				agentName: "compliance-agent"
			}
		}
	}
	entryPoints: ["inspect"]
	exitPoints: ["inspect"]
}
