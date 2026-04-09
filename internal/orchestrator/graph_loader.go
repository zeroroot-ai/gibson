package orchestrator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/zero-day-ai/gibson/internal/graphrag/graph"
	"github.com/zero-day-ai/gibson/internal/mission"
	"github.com/zero-day-ai/gibson/internal/types"
)

// GraphLoader implements MissionGraphLoader to store mission definitions in Neo4j.
// It links MissionDefinition nodes to existing Mission nodes for cross-mission
// meta-analysis, enabling queries like "which runs used the same definition?"
//
// Key features:
//   - Deduplication via content hash (same definition = same node)
//   - Links to existing Mission nodes via DEFINES relationship
//   - Stores full definition for auditing and reproducibility
type GraphLoader struct {
	graphClient graph.GraphClient
	logger      *slog.Logger
}

// NewGraphLoader creates a new GraphLoader with the given Neo4j client.
// The client must be connected before use; this function does not establish connections.
func NewGraphLoader(client graph.GraphClient, logger *slog.Logger) *GraphLoader {
	if logger == nil {
		logger = slog.Default()
	}
	return &GraphLoader{
		graphClient: client,
		logger:      logger.With("component", "graph_loader"),
	}
}

// LoadMission stores a mission definition in Neo4j and links it to the Mission node.
//
// Uses MERGE semantics with a content hash for deduplication - identical definitions
// (same YAML/JSON content) will share a single MissionDefinition node. This enables
// queries like "these 5 runs all used the same definition".
//
// Node structure:
//   - Label: :mission_definition
//   - Properties:
//   - id (UUID): Unique identifier for this definition instance
//   - definition_hash (string): SHA256 hash of canonical JSON for deduplication
//   - name (string): Mission name from definition
//   - description (string): Mission description
//   - version (string): Mission version
//   - target_ref (string): Target reference from definition
//   - nodes_json (string): JSON blob of mission nodes
//   - edges_json (string): JSON blob of mission edges
//   - metadata_json (string): JSON blob of additional metadata
//   - created_at (timestamp): When this definition was first stored
//
// Relationships:
//   - (MissionDefinition)-[:DEFINES]->(Mission)
//
// Returns the MissionDefinition node ID (existing or newly created).
func (g *GraphLoader) LoadMission(ctx context.Context, def *mission.MissionDefinition) (string, error) {
	if g.graphClient == nil {
		return "", types.NewError("GRAPH_LOADER", "graph client is nil")
	}

	if def == nil {
		return "", types.NewError("GRAPH_LOADER", "mission definition cannot be nil")
	}

	if def.Name == "" {
		return "", types.NewError("GRAPH_LOADER", "mission definition name cannot be empty")
	}

	// Compute content hash for deduplication
	hash, err := g.computeDefinitionHash(def)
	if err != nil {
		return "", fmt.Errorf("failed to compute definition hash: %w", err)
	}

	// Serialize nodes, edges, and metadata to JSON
	nodesJSON, err := json.Marshal(def.Nodes)
	if err != nil {
		return "", fmt.Errorf("failed to serialize nodes: %w", err)
	}

	edgesJSON, err := json.Marshal(def.Edges)
	if err != nil {
		return "", fmt.Errorf("failed to serialize edges: %w", err)
	}

	metadataJSON, err := json.Marshal(def.Metadata)
	if err != nil {
		return "", fmt.Errorf("failed to serialize metadata: %w", err)
	}

	// Generate new ID for potential creation
	newID := types.NewID()

	// MERGE by hash ensures same definition = same node
	// Then link to existing Mission node by name + target_ref
	cypher := `
		MERGE (md:mission_definition {definition_hash: $hash})
		ON CREATE SET
			md.id = $id,
			md.name = $name,
			md.description = $description,
			md.version = $version,
			md.target_ref = $target_ref,
			md.nodes_json = $nodes_json,
			md.edges_json = $edges_json,
			md.metadata_json = $metadata_json,
			md.created_at = timestamp()
		WITH md
		OPTIONAL MATCH (m:mission {name: $name, target_id: $target_ref})
		FOREACH (_ IN CASE WHEN m IS NOT NULL THEN [1] ELSE [] END |
			MERGE (md)-[:DEFINES]->(m)
		)
		RETURN md.id as definition_id
	`

	params := map[string]any{
		"id":            newID.String(),
		"hash":          hash,
		"name":          def.Name,
		"description":   def.Description,
		"version":       def.Version,
		"target_ref":    def.TargetRef,
		"nodes_json":    string(nodesJSON),
		"edges_json":    string(edgesJSON),
		"metadata_json": string(metadataJSON),
	}

	result, err := g.graphClient.Query(ctx, cypher, params)
	if err != nil {
		return "", fmt.Errorf("failed to store mission definition: %w", err)
	}

	if len(result.Records) == 0 {
		return "", types.NewError("GRAPH_LOADER", "query returned no records")
	}

	definitionID, ok := result.Records[0]["definition_id"].(string)
	if !ok {
		return "", types.NewError("GRAPH_LOADER", "definition_id has invalid type")
	}

	g.logger.Info("mission definition stored",
		"definition_id", definitionID,
		"definition_hash", hash,
		"name", def.Name,
		"version", def.Version,
	)

	return definitionID, nil
}

// computeDefinitionHash generates a SHA256 hash of the mission definition's
// canonical content for deduplication. The hash is computed from a deterministic
// JSON serialization of the definition's semantic content.
func (g *GraphLoader) computeDefinitionHash(def *mission.MissionDefinition) (string, error) {
	// Create a canonical representation for hashing
	// We exclude timestamps and IDs which may vary between loads of the same definition
	canonical := struct {
		Name        string                          `json:"name"`
		Description string                          `json:"description"`
		Version     string                          `json:"version"`
		TargetRef   string                          `json:"target_ref"`
		Nodes       map[string]*mission.MissionNode `json:"nodes"`
		Edges       []mission.MissionEdge           `json:"edges"`
		EntryPoints []string                        `json:"entry_points"`
		ExitPoints  []string                        `json:"exit_points"`
		Metadata    map[string]any                  `json:"metadata"`
	}{
		Name:        def.Name,
		Description: def.Description,
		Version:     def.Version,
		TargetRef:   def.TargetRef,
		Nodes:       def.Nodes,
		Edges:       def.Edges,
		EntryPoints: def.EntryPoints,
		ExitPoints:  def.ExitPoints,
		Metadata:    def.Metadata,
	}

	// Use json.Marshal for deterministic serialization
	// Note: Go's json.Marshal sorts map keys alphabetically
	data, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}
