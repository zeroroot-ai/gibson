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
	// PropID is the unique identifier for a node (UUID string)
	PropID = "id"

	// PropName is the human-readable name of a node
	PropName = "name"

	// PropType is the type classification of a node
	PropType = "type"

	// PropContent is the textual content of a node
	PropContent = "content"

	// PropEmbedding is the vector embedding of a node
	PropEmbedding = "embedding"

	// PropCreatedAt is the creation timestamp of a node (RFC3339 format)
	PropCreatedAt = "created_at"

	// PropUpdatedAt is the last update timestamp of a node (RFC3339 format)
	PropUpdatedAt = "updated_at"

	// PropMissionID is the mission identifier associated with a node (UUID string)
	PropMissionID = "mission_id"

	// PropMissionName is the mission name associated with a node
	PropMissionName = "mission_name"

	// PropRunNumber is the mission run number
	PropRunNumber = "run_number"

	// PropCreatedInRun is the run ID where the node was first created
	PropCreatedInRun = "created_in_run"

	// PropUpdatedInRun is the run ID where the node was last updated
	PropUpdatedInRun = "updated_in_run"

	// PropLastSeenInRun is the run ID where the node was last observed
	PropLastSeenInRun = "last_seen_in_run"

	// PropFindingID is the finding identifier (UUID string)
	PropFindingID = "finding_id"

	// PropSeverity is the severity level of a finding (critical, high, medium, low, info)
	PropSeverity = "severity"

	// PropCategory is the category classification of a node
	PropCategory = "category"

	// PropSubcategory is the subcategory classification of a node
	PropSubcategory = "subcategory"

	// PropConfidence is the confidence score (0.0 - 1.0)
	PropConfidence = "confidence"

	// PropRiskScore is the risk score (0.0 - 10.0, CVSS-like)
	PropRiskScore = "risk_score"

	// PropStatus is the status of a node (e.g., open, confirmed, resolved)
	PropStatus = "status"

	// PropDescription is the description text of a node
	PropDescription = "description"

	// PropRemediation is the remediation guidance for a finding
	PropRemediation = "remediation"

	// PropAgentName is the name of the agent that created/modified a node
	PropAgentName = "agent_name"

	// PropDelegatedFrom is the name of the agent that delegated work
	PropDelegatedFrom = "delegated_from"

	// PropOccurrenceCount is the number of times a finding was observed
	PropOccurrenceCount = "occurrence_count"

	// PropTactics is the MITRE ATT&CK tactics (array of strings)
	PropTactics = "tactics"

	// PropPlatforms is the supported platforms (array of strings)
	PropPlatforms = "platforms"

	// PropMetadata is a map of additional metadata
	PropMetadata = "metadata"
)

// Relationship property keys
const (
	// PropSource is the source node ID of a relationship
	PropSource = "source"

	// PropTarget is the target node ID of a relationship
	PropTarget = "target"

	// PropWeight is the strength/confidence of a relationship (0.0 - 1.0)
	PropWeight = "weight"

	// PropRelType is the type of relationship
	PropRelType = "type"
)
