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
	missionv1 "github.com/zero-day-ai/sdk/api/gen/gibson/mission/v1"
	"google.golang.org/protobuf/encoding/protojson"
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
func (g *GraphLoader) LoadMission(ctx context.Context, def *missionv1.MissionDefinition) (string, error) {
	if g.graphClient == nil {
		return "", types.NewError("GRAPH_LOADER", "graph client is nil")
	}

	if def == nil {
		return "", types.NewError("GRAPH_LOADER", "mission definition cannot be nil")
	}

	if def.GetName() == "" {
		return "", types.NewError("GRAPH_LOADER", "mission definition name cannot be empty")
	}

	// Compute content hash for deduplication
	hash, err := g.computeDefinitionHash(def)
	if err != nil {
		return "", fmt.Errorf("failed to compute definition hash: %w", err)
	}

	// Serialize nodes, edges, and metadata to JSON via protojson so the
	// stored bytes use the canonical proto wire shape (oneof envelopes
	// for per-noun configs, etc.). No call site reads these blobs back
	// into proto today; they are stored for downstream meta-analysis.
	//
	// Preserve the legacy nil → "null" wire format for absent nodes and
	// edges so existing Neo4j queries that special-case "null" continue
	// to behave identically.
	marshalProto := protojson.MarshalOptions{UseProtoNames: true}

	var nodesJSON []byte
	if len(def.GetNodes()) == 0 {
		nodesJSON = []byte("null")
	} else {
		nodesMap := make(map[string]json.RawMessage, len(def.GetNodes()))
		for id, n := range def.GetNodes() {
			raw, mErr := marshalProto.Marshal(n)
			if mErr != nil {
				return "", fmt.Errorf("failed to serialize node %s: %w", id, mErr)
			}
			nodesMap[id] = raw
		}
		nodesJSON, err = json.Marshal(nodesMap)
		if err != nil {
			return "", fmt.Errorf("failed to serialize nodes: %w", err)
		}
	}

	var edgesJSON []byte
	if len(def.GetEdges()) == 0 {
		edgesJSON = []byte("null")
	} else {
		edgesList := make([]json.RawMessage, 0, len(def.GetEdges()))
		for _, e := range def.GetEdges() {
			raw, mErr := marshalProto.Marshal(e)
			if mErr != nil {
				return "", fmt.Errorf("failed to serialize edge: %w", mErr)
			}
			edgesList = append(edgesList, raw)
		}
		edgesJSON, err = json.Marshal(edgesList)
		if err != nil {
			return "", fmt.Errorf("failed to serialize edges: %w", err)
		}
	}

	metadataJSON, err := json.Marshal(def.GetMetadata())
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
		"name":          def.GetName(),
		"description":   def.GetDescription(),
		"version":       def.GetVersion(),
		"target_ref":    def.GetTargetRef(),
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
		"name", def.GetName(),
		"version", def.GetVersion(),
	)

	return definitionID, nil
}

// computeDefinitionHash generates a SHA256 hash of the mission definition's
// canonical content for deduplication. Uses protojson with UseProtoNames=true
// for deterministic serialization (proto field IDs anchor field order, and
// repeated/map fields are sorted by the marshaler).
//
// Note: protojson.Marshal does not promise byte-for-byte determinism across
// versions of the protobuf library, but the combination of UseProtoNames +
// stable field IDs + sorted map keys is deterministic enough for content-
// addressed dedup in practice. If two equivalent definitions occasionally
// hash differently, the worst case is two MissionDefinition nodes for the
// same logical definition — a benign duplicate.
func (g *GraphLoader) computeDefinitionHash(def *missionv1.MissionDefinition) (string, error) {
	clone := &missionv1.MissionDefinition{
		Name:        def.GetName(),
		Description: def.GetDescription(),
		Version:     def.GetVersion(),
		TargetRef:   def.GetTargetRef(),
		Nodes:       def.GetNodes(),
		Edges:       def.GetEdges(),
		EntryPoints: def.GetEntryPoints(),
		ExitPoints:  def.GetExitPoints(),
		Metadata:    def.GetMetadata(),
	}

	data, err := mission.MarshalDefinitionJSON(clone)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}
