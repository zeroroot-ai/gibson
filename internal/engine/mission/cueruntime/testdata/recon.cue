// Recon mission template.
//
// Discover the target's exposed surface with the tools the executor
// ships: subdomains (subfinder), their addresses (dnsx), live HTTP
// services (httpx), and open ports (naabu). Four tool nodes run in
// sequence; every node exists in gibson-executor today.
//
// Override before submitting:
//   targetRef: "<target-name-or-id>"
//
// Spec: mission-authoring-cue Requirement 7.

import missionv1 "github.com/zeroroot-ai/sdk/api/proto/gibson/mission/v1"

mission: missionv1.#MissionDefinition & {
	name:        "recon"
	description: "Reconnaissance across a target's exposed surface."
	version:     "1.0.0"
	targetRef:   ""

	nodes: {
		subdomains: {
			id:   "subdomains"
			type: missionv1.#NODE_TYPE_TOOL
			toolConfig: {
				toolName: "subfinder"
				input: {domain: "{{target.domain}}"}
			}
		}
		resolve: {
			id:   "resolve"
			type: missionv1.#NODE_TYPE_TOOL
			toolConfig: {
				toolName: "dnsx"
				input: {domain: "{{target.domain}}"}
			}
		}
		http: {
			id:   "http"
			type: missionv1.#NODE_TYPE_TOOL
			toolConfig: {
				toolName: "httpx"
				input: {target: "{{target.domain}}"}
			}
		}
		ports: {
			id:   "ports"
			type: missionv1.#NODE_TYPE_TOOL
			toolConfig: {
				toolName: "naabu"
				input: {target: "{{target.domain}}"}
			}
		}
	}
	edges: [
		{from: "subdomains", to: "resolve"},
		{from: "resolve", to: "http"},
		{from: "http", to: "ports"},
	]
	entryPoints: ["subdomains"]
	exitPoints: ["ports"]
}
