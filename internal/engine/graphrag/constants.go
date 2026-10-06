// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package graphrag

// Property key constants for GraphRAG nodes and relationships.
// These constants should be used instead of hardcoded strings to ensure
// consistency across the codebase and prevent typos.
//
// Usage:
//   node.Properties[PropID] = id.String()
//   node.Properties[PropName] = "my-node"

// Node property keys
const (

	// PropName is the human-readable name of a node
	PropName = "name"

	// PropSeverity is the severity level of a finding (critical, high, medium, low, info)
	PropSeverity = "severity"

	// PropCategory is the category classification of a node
	PropCategory = "category"

	// PropConfidence is the confidence score (0.0 - 1.0)
	PropConfidence = "confidence"

	// PropDescription is the description text of a node
	PropDescription = "description"

	// PropTactics is the MITRE ATT&CK tactics (array of strings)
	PropTactics = "tactics"

	// PropPlatforms is the supported platforms (array of strings)
	PropPlatforms = "platforms"
)
