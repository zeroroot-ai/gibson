package state

// AllIndexDefinitions returns all predefined Gibson RediSearch indexes.
// These indexes provide full-text search, filtering, and sorting capabilities
// for all major Gibson entities.
func AllIndexDefinitions() []*IndexDefinition {
	return []*IndexDefinition{
		MissionIndex(),
		FindingIndex(),
		MissionMemoryIndex(),
		PayloadIndex(),
		CredentialIndex(),
		SessionIndex(),
		TargetIndex(),
		VectorIndex(),
	}
}

// MissionIndex defines the RediSearch index for mission documents.
// This index enables full-text search on mission names and descriptions,
// filtering by status and target, and sorting by timestamps and progress.
//
// Indexed Fields:
//   - name: Full-text searchable with 2.0 weight
//   - description: Full-text searchable
//   - status: Exact-match filtering (pending, running, completed, failed)
//   - target_id: Exact-match filtering by target
//   - created_at: Sortable timestamp (Unix milliseconds)
//   - updated_at: Sortable timestamp (Unix milliseconds)
//   - progress: Numeric field for range queries (0-100)
//   - findings_count: Numeric field for counting findings
//
// Example Queries:
//
//	// Find missions matching "API security"
//	FT.SEARCH gibson:idx:missions "API security"
//
//	// Find running missions for a specific target
//	FT.SEARCH gibson:idx:missions "@status:{running} @target_id:{tgt_123}"
//
//	// Find missions sorted by creation date
//	FT.SEARCH gibson:idx:missions "*" SORTBY created_at DESC
func MissionIndex() *IndexDefinition {
	return &IndexDefinition{
		Name:   "gibson:idx:missions",
		Prefix: "gibson:mission:",
		OnJSON: true,
		Schema: []FieldDefinition{
			{
				Path:   "$.name",
				Alias:  "name",
				Type:   FieldTypeText,
				Weight: 2.0,
			},
			{
				Path:  "$.description",
				Alias: "description",
				Type:  FieldTypeText,
			},
			{
				Path:  "$.status",
				Alias: "status",
				Type:  FieldTypeTag,
			},
			{
				Path:  "$.target_id",
				Alias: "target_id",
				Type:  FieldTypeTag,
			},
			{
				Path:     "$.created_at",
				Alias:    "created_at",
				Type:     FieldTypeNumeric,
				Sortable: true,
			},
			{
				Path:     "$.updated_at",
				Alias:    "updated_at",
				Type:     FieldTypeNumeric,
				Sortable: true,
			},
			{
				Path:  "$.progress",
				Alias: "progress",
				Type:  FieldTypeNumeric,
			},
			{
				Path:  "$.findings_count",
				Alias: "findings_count",
				Type:  FieldTypeNumeric,
			},
		},
	}
}

// FindingIndex defines the RediSearch index for security finding documents.
// This index enables full-text search on finding content with weighted fields,
// filtering by severity/status/category, and sorting by risk scores.
//
// Indexed Fields:
//   - title: Full-text searchable with 3.0 weight (highest priority)
//   - description: Full-text searchable with 2.0 weight
//   - remediation: Full-text searchable
//   - severity: Exact-match filtering (critical, high, medium, low, info)
//   - status: Exact-match filtering (open, confirmed, resolved, false_positive)
//   - mission_id: Exact-match filtering by mission
//   - agent_name: Exact-match filtering by discovering agent
//   - category: Exact-match filtering by finding category
//   - confidence: Numeric confidence score (0.0-1.0)
//   - risk_score: Sortable numeric risk score
//   - cvss_score: Sortable CVSS score (0.0-10.0)
//   - created_at: Sortable timestamp (Unix milliseconds)
//
// Example Queries:
//
//	// Find SQL injection findings
//	FT.SEARCH gibson:idx:findings "SQL injection"
//
//	// Find critical findings for a mission
//	FT.SEARCH gibson:idx:findings "@severity:{critical} @mission_id:{miss_123}"
//
//	// Find findings sorted by risk score
//	FT.SEARCH gibson:idx:findings "*" SORTBY risk_score DESC
func FindingIndex() *IndexDefinition {
	return &IndexDefinition{
		Name:   "gibson:idx:findings",
		Prefix: "gibson:finding:",
		OnJSON: true,
		Schema: []FieldDefinition{
			{
				Path:   "$.title",
				Alias:  "title",
				Type:   FieldTypeText,
				Weight: 3.0,
			},
			{
				Path:   "$.description",
				Alias:  "description",
				Type:   FieldTypeText,
				Weight: 2.0,
			},
			{
				Path:  "$.remediation",
				Alias: "remediation",
				Type:  FieldTypeText,
			},
			{
				Path:  "$.severity",
				Alias: "severity",
				Type:  FieldTypeTag,
			},
			{
				Path:  "$.status",
				Alias: "status",
				Type:  FieldTypeTag,
			},
			{
				Path:  "$.mission_id",
				Alias: "mission_id",
				Type:  FieldTypeTag,
			},
			{
				Path:  "$.agent_name",
				Alias: "agent_name",
				Type:  FieldTypeTag,
			},
			{
				Path:  "$.category",
				Alias: "category",
				Type:  FieldTypeTag,
			},
			{
				Path:  "$.confidence",
				Alias: "confidence",
				Type:  FieldTypeNumeric,
			},
			{
				Path:     "$.risk_score",
				Alias:    "risk_score",
				Type:     FieldTypeNumeric,
				Sortable: true,
			},
			{
				Path:     "$.cvss_score",
				Alias:    "cvss_score",
				Type:     FieldTypeNumeric,
				Sortable: true,
			},
			{
				Path:     "$.created_at",
				Alias:    "created_at",
				Type:     FieldTypeNumeric,
				Sortable: true,
			},
		},
	}
}

// MissionMemoryIndex defines the RediSearch index for mission memory documents.
// This index enables full-text search on memory keys and values, allowing
// agents to recall relevant mission context semantically.
//
// Indexed Fields:
//   - key: Full-text searchable with 2.0 weight
//   - value: Full-text searchable
//   - mission_id: Exact-match filtering by mission
//   - created_at: Sortable timestamp (Unix milliseconds)
//
// Example Queries:
//
//	// Search memory for "database credentials"
//	FT.SEARCH gibson:idx:memory "database credentials"
//
//	// Search memory for a specific mission
//	FT.SEARCH gibson:idx:memory "@mission_id:{miss_123} session"
//
//	// Find recent memory entries
//	FT.SEARCH gibson:idx:memory "*" SORTBY created_at DESC LIMIT 0 10
func MissionMemoryIndex() *IndexDefinition {
	return &IndexDefinition{
		Name:   "gibson:idx:memory",
		Prefix: "gibson:memory:",
		OnJSON: true,
		Schema: []FieldDefinition{
			{
				Path:   "$.key",
				Alias:  "key",
				Type:   FieldTypeText,
				Weight: 2.0,
			},
			{
				Path:  "$.value",
				Alias: "value",
				Type:  FieldTypeText,
			},
			{
				Path:  "$.mission_id",
				Alias: "mission_id",
				Type:  FieldTypeTag,
			},
			{
				Path:     "$.created_at",
				Alias:    "created_at",
				Type:     FieldTypeNumeric,
				Sortable: true,
			},
		},
	}
}

// PayloadIndex defines the RediSearch index for attack payload documents.
// This index enables full-text search on payload templates and descriptions,
// filtering by severity/category/tags, and finding enabled/built-in payloads.
//
// Indexed Fields:
//   - name: Full-text searchable with 3.0 weight (highest priority)
//   - description: Full-text searchable with 2.0 weight
//   - template: Full-text searchable payload template
//   - severity: Exact-match filtering (critical, high, medium, low)
//   - categories[*]: Multi-value tag filtering by payload categories
//   - tags[*]: Multi-value tag filtering by custom tags
//   - enabled: Exact-match filtering (true/false)
//   - built_in: Exact-match filtering (true/false for system payloads)
//   - created_at: Sortable timestamp (Unix milliseconds)
//
// Example Queries:
//
//	// Find XSS payloads
//	FT.SEARCH gibson:idx:payloads "XSS"
//
//	// Find enabled high-severity payloads
//	FT.SEARCH gibson:idx:payloads "@severity:{high} @enabled:{true}"
//
//	// Find payloads in specific category
//	FT.SEARCH gibson:idx:payloads "@categories:{injection}"
func PayloadIndex() *IndexDefinition {
	return &IndexDefinition{
		Name:   "gibson:idx:payloads",
		Prefix: "gibson:payload:",
		OnJSON: true,
		Schema: []FieldDefinition{
			{
				Path:   "$.name",
				Alias:  "name",
				Type:   FieldTypeText,
				Weight: 3.0,
			},
			{
				Path:   "$.description",
				Alias:  "description",
				Type:   FieldTypeText,
				Weight: 2.0,
			},
			{
				Path:  "$.template",
				Alias: "template",
				Type:  FieldTypeText,
			},
			{
				Path:  "$.severity",
				Alias: "severity",
				Type:  FieldTypeTag,
			},
			{
				Path:  "$.categories[*]",
				Alias: "categories",
				Type:  FieldTypeTag,
			},
			{
				Path:  "$.tags[*]",
				Alias: "tags",
				Type:  FieldTypeTag,
			},
			{
				Path:  "$.enabled",
				Alias: "enabled",
				Type:  FieldTypeTag,
			},
			{
				Path:  "$.built_in",
				Alias: "built_in",
				Type:  FieldTypeTag,
			},
			{
				Path:     "$.created_at",
				Alias:    "created_at",
				Type:     FieldTypeNumeric,
				Sortable: true,
			},
		},
	}
}

// CredentialIndex defines the RediSearch index for credential documents.
// This index enables filtering and sorting of credentials by type, provider,
// status, and tags. Note that encrypted values are NOT indexed for security.
//
// Indexed Fields:
//   - name: Exact-match, sortable credential name
//   - type: Exact-match filtering (api_key, password, token, certificate)
//   - provider: Exact-match filtering (anthropic, openai, aws, etc.)
//   - status: Exact-match filtering (active, expired, rotated, revoked)
//   - tags[*]: Multi-value tag filtering by custom tags
//   - created_at: Sortable timestamp (Unix milliseconds)
//   - last_used: Sortable timestamp (Unix milliseconds)
//
// Security Note:
//   - encrypted_value, encryption_iv, and key_derivation_salt are NOT indexed
//   - Only metadata fields are searchable
//
// Example Queries:
//
//	// Find active API keys
//	FT.SEARCH gibson:idx:credentials "@type:{api_key} @status:{active}"
//
//	// Find credentials by provider
//	FT.SEARCH gibson:idx:credentials "@provider:{anthropic}"
//
//	// Find credentials sorted by last use
//	FT.SEARCH gibson:idx:credentials "*" SORTBY last_used DESC
func CredentialIndex() *IndexDefinition {
	return &IndexDefinition{
		Name:   "gibson:idx:credentials",
		Prefix: "gibson:credential:",
		OnJSON: true,
		Schema: []FieldDefinition{
			{
				Path:     "$.name",
				Alias:    "name",
				Type:     FieldTypeTag,
				Sortable: true,
			},
			{
				Path:  "$.type",
				Alias: "type",
				Type:  FieldTypeTag,
			},
			{
				Path:  "$.provider",
				Alias: "provider",
				Type:  FieldTypeTag,
			},
			{
				Path:  "$.status",
				Alias: "status",
				Type:  FieldTypeTag,
			},
			{
				Path:  "$.tags[*]",
				Alias: "tags",
				Type:  FieldTypeTag,
			},
			{
				Path:     "$.created_at",
				Alias:    "created_at",
				Type:     FieldTypeNumeric,
				Sortable: true,
			},
			{
				Path:     "$.last_used",
				Alias:    "last_used",
				Type:     FieldTypeNumeric,
				Sortable: true,
			},
		},
	}
}

// SessionIndex defines the RediSearch index for agent session documents.
// This index enables filtering and sorting of active and historical agent sessions
// by status, agent, mission, and timestamps.
//
// Indexed Fields:
//   - status: Exact-match filtering (active, ended, disconnected, error)
//   - agent_id: Exact-match filtering by agent identifier
//   - mission_id: Exact-match filtering by mission
//   - created_at: Sortable timestamp (Unix milliseconds)
//   - ended_at: Sortable timestamp (Unix milliseconds)
//
// Example Queries:
//
//	// Find active sessions
//	FT.SEARCH gibson:idx:sessions "@status:{active}"
//
//	// Find sessions for a specific agent
//	FT.SEARCH gibson:idx:sessions "@agent_id:{agent_123}"
//
//	// Find sessions for a mission
//	FT.SEARCH gibson:idx:sessions "@mission_id:{miss_123}"
//
//	// Find sessions sorted by creation date
//	FT.SEARCH gibson:idx:sessions "*" SORTBY created_at DESC
func SessionIndex() *IndexDefinition {
	return &IndexDefinition{
		Name:   "gibson:idx:sessions",
		Prefix: "gibson:session:",
		OnJSON: true,
		Schema: []FieldDefinition{
			{
				Path:  "$.status",
				Alias: "status",
				Type:  FieldTypeTag,
			},
			{
				Path:  "$.agent_id",
				Alias: "agent_id",
				Type:  FieldTypeTag,
			},
			{
				Path:  "$.mission_id",
				Alias: "mission_id",
				Type:  FieldTypeTag,
			},
			{
				Path:     "$.created_at",
				Alias:    "created_at",
				Type:     FieldTypeNumeric,
				Sortable: true,
			},
			{
				Path:     "$.ended_at",
				Alias:    "ended_at",
				Type:     FieldTypeNumeric,
				Sortable: true,
			},
		},
	}
}

// TargetIndex defines the RediSearch index for target system documents.
// This index enables filtering and sorting of targets by provider, type,
// status, and tags.
//
// Indexed Fields:
//   - name: Exact-match, sortable target name
//   - type: Exact-match filtering (http_api, kubernetes, smart_contract, etc.)
//   - provider: Exact-match filtering (openai, anthropic, google, azure, ollama, custom)
//   - status: Exact-match filtering (active, inactive, error)
//   - tags[*]: Multi-value tag filtering by custom tags
//   - created_at: Sortable timestamp (Unix milliseconds)
//   - updated_at: Sortable timestamp (Unix milliseconds)
//
// Example Queries:
//
//	// Find active targets
//	FT.SEARCH gibson:idx:targets "@status:{active}"
//
//	// Find targets by provider
//	FT.SEARCH gibson:idx:targets "@provider:{openai}"
//
//	// Find targets by type
//	FT.SEARCH gibson:idx:targets "@type:{http_api}"
//
//	// Find targets sorted by creation date
//	FT.SEARCH gibson:idx:targets "*" SORTBY created_at DESC
func TargetIndex() *IndexDefinition {
	return &IndexDefinition{
		Name:   "gibson:idx:targets",
		Prefix: "gibson:target:",
		OnJSON: true,
		Schema: []FieldDefinition{
			{
				Path:     "$.name",
				Alias:    "name",
				Type:     FieldTypeTag,
				Sortable: true,
			},
			{
				Path:  "$.type",
				Alias: "type",
				Type:  FieldTypeTag,
			},
			{
				Path:  "$.provider",
				Alias: "provider",
				Type:  FieldTypeTag,
			},
			{
				Path:  "$.status",
				Alias: "status",
				Type:  FieldTypeTag,
			},
			{
				Path:  "$.tags[*]",
				Alias: "tags",
				Type:  FieldTypeTag,
			},
			{
				Path:     "$.created_at",
				Alias:    "created_at",
				Type:     FieldTypeNumeric,
				Sortable: true,
			},
			{
				Path:     "$.updated_at",
				Alias:    "updated_at",
				Type:     FieldTypeNumeric,
				Sortable: true,
			},
		},
	}
}

// VectorIndex defines the RediSearch index for knowledge vector documents.
// This index enables semantic search using vector similarity (KNN) combined
// with full-text search on content.
//
// Indexed Fields:
//   - content: Full-text searchable content
//   - embedding: 384-dimensional FLOAT32 vector with COSINE similarity
//   - created_at: Sortable timestamp (Unix milliseconds)
//
// Vector Configuration:
//   - Algorithm: HNSW (Hierarchical Navigable Small World for scalability)
//   - Dimensions: 384 (all-minilm-l6-v2 embedding model)
//   - Distance Metric: COSINE (normalized dot product)
//   - Data Type: FLOAT32 (4 bytes per dimension)
//   - M: 16 (bi-directional links per node, balances recall and memory)
//   - EF_CONSTRUCTION: 200 (construction-time candidate list size)
//
// HNSW scales better than FLAT for datasets with >10K vectors, providing
// sub-linear query time with minimal accuracy loss.
//
// Example Queries:
//
//	// Pure vector similarity search
//	FT.SEARCH gibson:idx:vectors "*=>[KNN 10 @embedding $vector]" \
//	  PARAMS 2 vector <binary-vector-blob> DIALECT 2
//
//	// Hybrid search (vector + full-text)
//	FT.SEARCH gibson:idx:vectors "@content:security *=>[KNN 10 @embedding $vector]" \
//	  PARAMS 2 vector <binary-vector-blob> DIALECT 2
//
//	// Vector search sorted by timestamp
//	FT.SEARCH gibson:idx:vectors "*=>[KNN 10 @embedding $vector]" \
//	  PARAMS 2 vector <binary-vector-blob> SORTBY created_at DESC DIALECT 2
func VectorIndex() *IndexDefinition {
	return &IndexDefinition{
		Name:   "gibson:idx:vectors",
		Prefix: "gibson:vector:",
		OnJSON: true,
		Schema: []FieldDefinition{
			{
				Path:  "$.content",
				Alias: "content",
				Type:  FieldTypeText,
			},
			{
				Path:     "$.created_at",
				Alias:    "created_at",
				Type:     FieldTypeNumeric,
				Sortable: true,
			},
			{
				Path:  "$.embedding",
				Alias: "embedding",
				Type:  FieldTypeVector,
				VectorOpts: &VectorOptions{
					Algorithm:      VectorAlgorithmHNSW,
					Type:           VectorDataTypeFloat32,
					Dim:            384,
					DistanceMetric: VectorDistanceMetricCosine,
					M:              16,
					EfConstruction: 200,
				},
			},
		},
	}
}
