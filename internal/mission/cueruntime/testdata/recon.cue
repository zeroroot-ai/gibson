// Recon mission template.
//
// Discover the target's exposed surface (open ports, running
// services, reachable subdomains). Two agent nodes run
// sequentially: nmap-style scan followed by enrichment via
// passive sources.
//
// Override before submitting:
//   targetRef: "<target-name-or-id>"
//
// Spec: mission-authoring-cue Requirement 7.

import missionv1 "github.com/zero-day-ai/sdk/api/proto/gibson/mission/v1"

mission: missionv1.#MissionDefinition & {
	name:        "recon"
	description: "Reconnaissance across a target's exposed surface."
	version:     "1.0.0"
	targetRef:   ""

	nodes: {
		scan: {
			id:   "scan"
			type: missionv1.#NODE_TYPE_AGENT
			agentConfig: {
				agentName: "nmap-agent"
			}
		}
		enrich: {
			id:   "enrich"
			type: missionv1.#NODE_TYPE_AGENT
			agentConfig: {
				agentName: "shodan-agent"
			}
		}
	}
	edges: [
		{from: "scan", to: "enrich"},
	]
	entryPoints: ["scan"]
	exitPoints: ["enrich"]
}
