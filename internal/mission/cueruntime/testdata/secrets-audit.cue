// Secrets-in-repository audit.
//
// Single-agent mission running gitleaks-style pattern matching
// across a repository's history. Suitable for either a
// one-time audit (point at a single repo) or a recurring scan
// (point at a target that wraps the repo set).
//
// Override before submitting:
//   targetRef: "<repo-target-name-or-id>"
//
// Spec: mission-authoring-cue Requirement 7.

import missionv1 "github.com/zero-day-ai/sdk/api/proto/gibson/mission/v1"

mission: missionv1.#MissionDefinition & {
	name:        "secrets-audit"
	description: "Scan a repository for committed secrets."
	version:     "1.0.0"
	targetRef:   ""

	nodes: {
		leaks: {
			id:   "leaks"
			type: missionv1.#NODE_TYPE_AGENT
			agentConfig: {
				agentName: "gitleaks-agent"
			}
		}
	}
	entryPoints: ["leaks"]
	exitPoints: ["leaks"]
}
