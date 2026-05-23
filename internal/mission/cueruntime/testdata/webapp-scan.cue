// Web application discovery + vulnerability scan.
//
// Crawl the target webapp's reachable surface, then run an
// active vulnerability scan against discovered endpoints.
//
// Override before submitting:
//   targetRef: "<target-name-or-id>"
//
// Spec: mission-authoring-cue Requirement 7.

import missionv1 "github.com/zero-day-ai/sdk/api/proto/gibson/mission/v1"

mission: missionv1.#MissionDefinition & {
	name:        "webapp-scan"
	description: "Crawl + active scan a web application."
	version:     "1.0.0"
	targetRef:   ""

	nodes: {
		crawl: {
			id:   "crawl"
			type: missionv1.#NODE_TYPE_AGENT
			agentConfig: {
				agentName: "webcrawl-agent"
			}
		}
		scan: {
			id:   "scan"
			type: missionv1.#NODE_TYPE_AGENT
			agentConfig: {
				agentName: "webvuln-agent"
			}
		}
	}
	edges: [
		{from: "crawl", to: "scan"},
	]
	entryPoints: ["crawl"]
	exitPoints: ["scan"]
}
