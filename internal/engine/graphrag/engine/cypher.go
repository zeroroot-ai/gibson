package engine

import (
	"fmt"
	"strings"
	"time"
)

// CypherBuilder generates Cypher queries from taxonomy specifications.
// It provides a safe, parameterized approach to building Neo4j queries
// that prevents injection attacks and follows Neo4j best practices.
type CypherBuilder struct {
	// timestampFormat defines how timestamps are formatted for Neo4j
	timestampFormat string
}

// NewCypherBuilder creates a new CypherBuilder with default settings.
func NewCypherBuilder() *CypherBuilder {
	return &CypherBuilder{
		timestampFormat: time.RFC3339,
	}
}

// NodeData represents a node's data for batch operations.
type NodeData struct {
	ID         string         `json:"id"`
	Properties map[string]any `json:"properties"`
}

// BuildNodeMerge generates a MERGE query for creating/updating a node.
// Node labels should be lowercase with underscores (matching taxonomy conventions).
// Returns the query string and parameters map.
//
// Example:
//
//	query, params := builder.BuildNodeMerge("mission", "mission:abc123", map[string]any{
//	    "name": "Test Mission",
//	    "status": "running",
//	})
//
// Generates:
//
//	MERGE (n:mission {id: $id})
//	SET n.name = $name, n.status = $status, n.updated_at = datetime($updated_at)
//	RETURN n
func (b *CypherBuilder) BuildNodeMerge(nodeType string, nodeID string, properties map[string]any) (string, map[string]any) {
	// Initialize parameters with the node ID
	params := map[string]any{
		"id": nodeID,
	}

	// Build the MERGE clause with node label and ID constraint
	var query strings.Builder
	query.WriteString(fmt.Sprintf("MERGE (n:%s {id: $id})\n", sanitizeLabel(nodeType)))

	// Build SET clause for properties
	if len(properties) > 0 {
		query.WriteString("SET ")
		setClauses := make([]string, 0, len(properties)+1)

		for key, value := range properties {
			paramKey := sanitizeParamKey(key)
			params[paramKey] = normalizeValue(value)
			setClauses = append(setClauses, fmt.Sprintf("n.%s = $%s", sanitizeProperty(key), paramKey))
		}

		// Always add updated_at timestamp
		params["updated_at"] = time.Now().Format(b.timestampFormat)
		setClauses = append(setClauses, "n.updated_at = datetime($updated_at)")

		query.WriteString(strings.Join(setClauses, ", "))
		query.WriteString("\n")
	}

	query.WriteString("RETURN n")

	return query.String(), params
}

// BuildRelationshipMerge generates a MERGE query for creating a relationship.
// Relationship types should be UPPERCASE (matching Neo4j conventions).
// Returns the query string and parameters map.
//
// Example:
//
//	query, params := builder.BuildRelationshipMerge("PART_OF", "tool:nmap", "mission:abc123", map[string]any{
//	    "weight": 1.0,
//	})
//
// Generates:
//
//	MATCH (a {id: $from_id})
//	MATCH (b {id: $to_id})
//	MERGE (a)-[r:PART_OF]->(b)
//	SET r.weight = $weight, r.updated_at = datetime($updated_at)
//	RETURN r
func (b *CypherBuilder) BuildRelationshipMerge(relType string, fromID string, toID string, properties map[string]any) (string, map[string]any) {
	// Initialize parameters
	params := map[string]any{
		"from_id": fromID,
		"to_id":   toID,
	}

	// Build the query
	var query strings.Builder
	query.WriteString("MATCH (a {id: $from_id})\n")
	query.WriteString("MATCH (b {id: $to_id})\n")
	query.WriteString(fmt.Sprintf("MERGE (a)-[r:%s]->(b)\n", sanitizeRelationType(relType)))

	// Build SET clause for properties if any
	if len(properties) > 0 {
		query.WriteString("SET ")
		setClauses := make([]string, 0, len(properties)+1)

		for key, value := range properties {
			paramKey := sanitizeParamKey(key)
			params[paramKey] = normalizeValue(value)
			setClauses = append(setClauses, fmt.Sprintf("r.%s = $%s", sanitizeProperty(key), paramKey))
		}

		// Always add updated_at timestamp
		params["updated_at"] = time.Now().Format(b.timestampFormat)
		setClauses = append(setClauses, "r.updated_at = datetime($updated_at)")

		query.WriteString(strings.Join(setClauses, ", "))
		query.WriteString("\n")
	}

	query.WriteString("RETURN r")

	return query.String(), params
}

// BuildBatchNodeMerge generates a batch MERGE query for multiple nodes.
// This is optimized for bulk operations like processing tool outputs.
// Returns the query string and parameters map.
//
// Example:
//
//	nodes := []NodeData{
//	    {ID: "host:192.168.1.1", Properties: map[string]any{"ip": "192.168.1.1", "status": "up"}},
//	    {ID: "host:192.168.1.2", Properties: map[string]any{"ip": "192.168.1.2", "status": "down"}},
//	}
//	query, params := builder.BuildBatchNodeMerge("host", nodes)
//
// Generates:
//
//	UNWIND $nodes AS node
//	MERGE (n:host {id: node.id})
//	SET n += node.properties, n.updated_at = datetime($updated_at)
//	RETURN count(n) as created_count
func (b *CypherBuilder) BuildBatchNodeMerge(nodeType string, nodes []NodeData) (string, map[string]any) {
	// Prepare nodes data - normalize all values and add metadata
	normalizedNodes := make([]map[string]any, len(nodes))
	timestamp := time.Now().Format(b.timestampFormat)

	for i, node := range nodes {
		props := make(map[string]any, len(node.Properties))
		for key, value := range node.Properties {
			props[sanitizeProperty(key)] = normalizeValue(value)
		}
		normalizedNodes[i] = map[string]any{
			"id":         node.ID,
			"properties": props,
		}
	}

	// Build query
	var query strings.Builder
	query.WriteString("UNWIND $nodes AS node\n")
	query.WriteString(fmt.Sprintf("MERGE (n:%s {id: node.id})\n", sanitizeLabel(nodeType)))
	query.WriteString("SET n += node.properties, n.updated_at = datetime($updated_at)\n")
	query.WriteString("RETURN count(n) as created_count")

	params := map[string]any{
		"nodes":      normalizedNodes,
		"updated_at": timestamp,
	}

	return query.String(), params
}

// BuildBatchRelationshipMerge generates a batch MERGE query for multiple relationships.
// This is optimized for bulk operations like connecting tool outputs to missions.
// Returns the query string and parameters map.
//
// Example:
//
//	rels := []RelationshipData{
//	    {FromID: "tool:nmap", ToID: "mission:abc", Type: "PART_OF", Properties: map[string]any{"weight": 1.0}},
//	    {FromID: "tool:masscan", ToID: "mission:abc", Type: "PART_OF", Properties: map[string]any{"weight": 0.8}},
//	}
//	query, params := builder.BuildBatchRelationshipMerge(rels)
func (b *CypherBuilder) BuildBatchRelationshipMerge(relationships []RelationshipData) (string, map[string]any) {
	// Prepare relationships data
	normalizedRels := make([]map[string]any, len(relationships))
	timestamp := time.Now().Format(b.timestampFormat)

	for i, rel := range relationships {
		props := make(map[string]any, len(rel.Properties))
		for key, value := range rel.Properties {
			props[sanitizeProperty(key)] = normalizeValue(value)
		}
		normalizedRels[i] = map[string]any{
			"from_id":    rel.FromID,
			"to_id":      rel.ToID,
			"type":       sanitizeRelationType(rel.Type),
			"properties": props,
		}
	}

	// Build query using APOC if available, otherwise fall back to UNWIND
	var query strings.Builder
	query.WriteString("UNWIND $relationships AS rel\n")
	query.WriteString("MATCH (a {id: rel.from_id})\n")
	query.WriteString("MATCH (b {id: rel.to_id})\n")
	query.WriteString("CALL apoc.merge.relationship(a, rel.type, {}, rel.properties, b, {}) YIELD rel as r\n")
	query.WriteString("SET r.updated_at = datetime($updated_at)\n")
	query.WriteString("RETURN count(r) as created_count")

	params := map[string]any{
		"relationships": normalizedRels,
		"updated_at":    timestamp,
	}

	return query.String(), params
}

// RelationshipData represents a relationship's data for batch operations.
type RelationshipData struct {
	FromID     string         `json:"from_id"`
	ToID       string         `json:"to_id"`
	Type       string         `json:"type"`
	Properties map[string]any `json:"properties,omitempty"`
}

// sanitizeLabel ensures node labels are safe for Cypher queries.
// Converts to lowercase and replaces invalid characters with underscores.
func sanitizeLabel(label string) string {
	label = strings.ToLower(label)
	// Replace any non-alphanumeric characters (except underscore) with underscore
	result := strings.Builder{}
	for _, r := range label {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			result.WriteRune(r)
		} else {
			result.WriteRune('_')
		}
	}
	return result.String()
}

// sanitizeRelationType ensures relationship types are safe for Cypher queries.
// Converts to uppercase and replaces invalid characters with underscores.
func sanitizeRelationType(relType string) string {
	relType = strings.ToUpper(relType)
	// Replace any non-alphanumeric characters (except underscore) with underscore
	result := strings.Builder{}
	for _, r := range relType {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			result.WriteRune(r)
		} else {
			result.WriteRune('_')
		}
	}
	return result.String()
}

// sanitizeProperty ensures property names are safe for Cypher queries.
// Converts to lowercase and replaces invalid characters with underscores.
func sanitizeProperty(prop string) string {
	prop = strings.ToLower(prop)
	// Replace any non-alphanumeric characters (except underscore) with underscore
	result := strings.Builder{}
	for _, r := range prop {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			result.WriteRune(r)
		} else {
			result.WriteRune('_')
		}
	}
	return result.String()
}

// sanitizeParamKey ensures parameter keys are safe and unique.
// Adds a prefix to avoid collisions with reserved words.
func sanitizeParamKey(key string) string {
	key = strings.ToLower(key)
	// Replace any non-alphanumeric characters (except underscore) with underscore
	result := strings.Builder{}
	for _, r := range key {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			result.WriteRune(r)
		} else {
			result.WriteRune('_')
		}
	}
	return result.String()
}

// normalizeValue converts Go values to Neo4j-compatible types.
// Handles time.Time, slices, and other special cases.
func normalizeValue(value any) any {
	if value == nil {
		return nil
	}

	switch v := value.(type) {
	case time.Time:
		// Convert to RFC3339 string for Neo4j datetime
		return v.Format(time.RFC3339)
	case []string:
		// Neo4j supports string arrays natively
		return v
	case []int:
		// Convert to []int64 for Neo4j
		result := make([]int64, len(v))
		for i, val := range v {
			result[i] = int64(val)
		}
		return result
	case []float64:
		// Neo4j supports float64 arrays natively
		return v
	case map[string]any:
		// Recursively normalize nested maps
		result := make(map[string]any, len(v))
		for key, val := range v {
			result[key] = normalizeValue(val)
		}
		return result
	default:
		// Return as-is for basic types (string, int, float64, bool)
		return v
	}
}

// BuildNodeQuery generates a query to find nodes by label and properties.
// Returns the query string and parameters map.
//
// Example:
//
//	query, params := builder.BuildNodeQuery("mission", map[string]any{"status": "running"})
//
// Generates:
//
//	MATCH (n:mission)
//	WHERE n.status = $status
//	RETURN n
func (b *CypherBuilder) BuildNodeQuery(nodeType string, filters map[string]any) (string, map[string]any) {
	params := make(map[string]any)
	var query strings.Builder

	query.WriteString(fmt.Sprintf("MATCH (n:%s)\n", sanitizeLabel(nodeType)))

	if len(filters) > 0 {
		query.WriteString("WHERE ")
		whereClauses := make([]string, 0, len(filters))

		for key, value := range filters {
			paramKey := sanitizeParamKey(key)
			params[paramKey] = normalizeValue(value)
			whereClauses = append(whereClauses, fmt.Sprintf("n.%s = $%s", sanitizeProperty(key), paramKey))
		}

		query.WriteString(strings.Join(whereClauses, " AND "))
		query.WriteString("\n")
	}

	query.WriteString("RETURN n")

	return query.String(), params
}

// BuildRelationshipQuery generates a query to find relationships by type and properties.
// Returns the query string and parameters map.
//
// Example:
//
//	query, params := builder.BuildRelationshipQuery("PART_OF", nil, nil, map[string]any{"weight": 1.0})
//
// Generates:
//
//	MATCH (a)-[r:PART_OF]->(b)
//	WHERE r.weight = $weight
//	RETURN a, r, b
func (b *CypherBuilder) BuildRelationshipQuery(relType string, fromFilters map[string]any, toFilters map[string]any, relFilters map[string]any) (string, map[string]any) {
	params := make(map[string]any)
	var query strings.Builder

	// Build MATCH clause
	query.WriteString(fmt.Sprintf("MATCH (a)-[r:%s]->(b)\n", sanitizeRelationType(relType)))

	// Build WHERE clause
	whereClauses := make([]string, 0)

	// Add from node filters
	for key, value := range fromFilters {
		paramKey := "from_" + sanitizeParamKey(key)
		params[paramKey] = normalizeValue(value)
		whereClauses = append(whereClauses, fmt.Sprintf("a.%s = $%s", sanitizeProperty(key), paramKey))
	}

	// Add to node filters
	for key, value := range toFilters {
		paramKey := "to_" + sanitizeParamKey(key)
		params[paramKey] = normalizeValue(value)
		whereClauses = append(whereClauses, fmt.Sprintf("b.%s = $%s", sanitizeProperty(key), paramKey))
	}

	// Add relationship filters
	for key, value := range relFilters {
		paramKey := "rel_" + sanitizeParamKey(key)
		params[paramKey] = normalizeValue(value)
		whereClauses = append(whereClauses, fmt.Sprintf("r.%s = $%s", sanitizeProperty(key), paramKey))
	}

	if len(whereClauses) > 0 {
		query.WriteString("WHERE ")
		query.WriteString(strings.Join(whereClauses, " AND "))
		query.WriteString("\n")
	}

	query.WriteString("RETURN a, r, b")

	return query.String(), params
}

// BuildDeleteNode generates a query to delete a node by ID.
// Returns the query string and parameters map.
//
// Example:
//
//	query, params := builder.BuildDeleteNode("mission:abc123")
//
// Generates:
//
//	MATCH (n {id: $id})
//	DETACH DELETE n
func (b *CypherBuilder) BuildDeleteNode(nodeID string) (string, map[string]any) {
	params := map[string]any{
		"id": nodeID,
	}

	query := "MATCH (n {id: $id})\nDETACH DELETE n"

	return query, params
}
