package orchestrator

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

const (
	// defaultQueryTimeout is the default timeout for graph queries
	defaultQueryTimeout = 500 * time.Millisecond

	// maxQueryResults is the maximum number of results per query
	maxQueryResults = 1000

	// maxTraversalDepth is the maximum traversal depth
	maxTraversalDepth = 5
)

var tracer = otel.Tracer("gibson.orchestrator.graph_querier")

// Neo4jGraphQuerier implements GraphQuerier using Neo4j as the backend.
// It provides entity lookup, relationship traversal, pattern matching,
// and semantic search against the GraphRAG knowledge graph.
type Neo4jGraphQuerier struct {
	driver   neo4j.DriverWithContext
	database string
}

// NewNeo4jGraphQuerier creates a new Neo4jGraphQuerier with the given driver.
func NewNeo4jGraphQuerier(driver neo4j.DriverWithContext, database string) *Neo4jGraphQuerier {
	if database == "" {
		database = "neo4j"
	}
	return &Neo4jGraphQuerier{
		driver:   driver,
		database: database,
	}
}

// EntityLookup retrieves entities matching specified criteria.
func (q *Neo4jGraphQuerier) EntityLookup(ctx context.Context, query EntityQuery) ([]EntityMatch, error) {
	ctx, span := tracer.Start(ctx, "Neo4jGraphQuerier.EntityLookup",
		trace.WithAttributes(
			attribute.StringSlice("entity_types", query.EntityTypes),
			attribute.String("mission_run_id", query.MissionRunID),
			attribute.Int("max_results", query.MaxResults),
		))
	defer span.End()

	// Apply timeout
	ctx, cancel := context.WithTimeout(ctx, defaultQueryTimeout)
	defer cancel()

	// Build Cypher query
	cypher, params := q.buildEntityLookupQuery(query)

	// Execute query
	session := q.driver.NewSession(ctx, neo4j.SessionConfig{
		DatabaseName: q.database,
		AccessMode:   neo4j.AccessModeRead,
	})
	defer session.Close(ctx)

	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		neoResult, err := tx.Run(ctx, cypher, params)
		if err != nil {
			return nil, err
		}

		records, err := neoResult.Collect(ctx)
		if err != nil {
			return nil, err
		}

		return q.convertEntityRecords(records), nil
	})

	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("entity lookup failed: %w", err)
	}

	return result.([]EntityMatch), nil
}

// buildEntityLookupQuery constructs a Cypher query for entity lookup.
func (q *Neo4jGraphQuerier) buildEntityLookupQuery(query EntityQuery) (string, map[string]any) {
	params := make(map[string]any)

	// Build MATCH clause with optional labels
	matchClause := "MATCH (n)"
	if len(query.EntityTypes) > 0 {
		// Convert entity types to Neo4j labels (capitalize first letter)
		labels := make([]string, len(query.EntityTypes))
		for i, t := range query.EntityTypes {
			labels[i] = strings.Title(t)
		}
		matchClause = fmt.Sprintf("MATCH (n:%s)", strings.Join(labels, "|"))
	}

	// Build WHERE clauses
	whereClauses := []string{}

	// Mission scope filter
	if query.MissionRunID != "" {
		whereClauses = append(whereClauses, "n.mission_run_id = $mission_run_id")
		params["mission_run_id"] = query.MissionRunID
	}

	// Property filters
	for key, value := range query.Filters {
		paramKey := "filter_" + key
		whereClauses = append(whereClauses, fmt.Sprintf("n.%s = $%s", key, paramKey))
		params[paramKey] = value
	}

	// Time range filter
	if !query.TimeRange.IsZero() {
		if !query.TimeRange.Start.IsZero() {
			whereClauses = append(whereClauses, "n.discovered_at >= $time_start")
			params["time_start"] = query.TimeRange.Start.UnixMilli()
		}
		if !query.TimeRange.End.IsZero() {
			whereClauses = append(whereClauses, "n.discovered_at <= $time_end")
			params["time_end"] = query.TimeRange.End.UnixMilli()
		}
	}

	// Combine WHERE clauses
	whereClause := ""
	if len(whereClauses) > 0 {
		whereClause = "WHERE " + strings.Join(whereClauses, " AND ")
	}

	// Set limits
	maxResults := query.MaxResults
	if maxResults <= 0 || maxResults > maxQueryResults {
		maxResults = 100
	}
	params["limit"] = maxResults

	offset := query.Offset
	if offset < 0 {
		offset = 0
	}
	params["offset"] = offset

	cypher := fmt.Sprintf(`
		%s
		%s
		RETURN n, labels(n) as labels
		ORDER BY n.discovered_at DESC
		SKIP $offset
		LIMIT $limit
	`, matchClause, whereClause)

	return cypher, params
}

// convertEntityRecords converts Neo4j records to EntityMatch slice.
func (q *Neo4jGraphQuerier) convertEntityRecords(records []*neo4j.Record) []EntityMatch {
	results := make([]EntityMatch, 0, len(records))

	for _, record := range records {
		nodeVal, ok := record.Get("n")
		if !ok {
			continue
		}

		node, ok := nodeVal.(neo4j.Node)
		if !ok {
			continue
		}

		labels, _ := record.Get("labels")
		labelSlice, _ := labels.([]interface{})

		entityType := ""
		if len(labelSlice) > 0 {
			if label, ok := labelSlice[0].(string); ok {
				entityType = strings.ToLower(label)
			}
		}

		match := EntityMatch{
			ID:         q.getStringProp(node.Props, "id"),
			Type:       entityType,
			Properties: node.Props,
			Score:      1.0, // Direct lookup has score 1.0
		}

		// Extract metadata fields
		if missionRunID, ok := node.Props["mission_run_id"].(string); ok {
			match.MissionRunID = missionRunID
		}
		if discoveredAt, ok := node.Props["discovered_at"].(int64); ok {
			match.DiscoveredAt = time.UnixMilli(discoveredAt)
		}
		if discoveredBy, ok := node.Props["discovered_by"].(string); ok {
			match.DiscoveredBy = discoveredBy
		}

		results = append(results, match)
	}

	return results
}

// RelationshipTraversal traverses relationships from a starting entity.
func (q *Neo4jGraphQuerier) RelationshipTraversal(ctx context.Context, query RelationshipQuery) ([]RelatedEntity, error) {
	ctx, span := tracer.Start(ctx, "Neo4jGraphQuerier.RelationshipTraversal",
		trace.WithAttributes(
			attribute.String("start_entity_id", query.StartEntityID),
			attribute.String("direction", query.Direction),
			attribute.Int("max_depth", query.MaxDepth),
		))
	defer span.End()

	// Apply timeout
	ctx, cancel := context.WithTimeout(ctx, defaultQueryTimeout)
	defer cancel()

	// Build Cypher query
	cypher, params := q.buildRelationshipTraversalQuery(query)

	// Execute query
	session := q.driver.NewSession(ctx, neo4j.SessionConfig{
		DatabaseName: q.database,
		AccessMode:   neo4j.AccessModeRead,
	})
	defer session.Close(ctx)

	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		neoResult, err := tx.Run(ctx, cypher, params)
		if err != nil {
			return nil, err
		}

		records, err := neoResult.Collect(ctx)
		if err != nil {
			return nil, err
		}

		return q.convertRelatedRecords(records, query.IncludeProperties), nil
	})

	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("relationship traversal failed: %w", err)
	}

	return result.([]RelatedEntity), nil
}

// buildRelationshipTraversalQuery constructs a Cypher query for traversal.
func (q *Neo4jGraphQuerier) buildRelationshipTraversalQuery(query RelationshipQuery) (string, map[string]any) {
	params := map[string]any{
		"start_id": query.StartEntityID,
	}

	// Determine traversal depth
	maxDepth := query.MaxDepth
	if maxDepth <= 0 {
		maxDepth = 2
	}
	if maxDepth > maxTraversalDepth {
		maxDepth = maxTraversalDepth
	}

	// Build relationship pattern
	relPattern := "*1.." + fmt.Sprint(maxDepth)
	if len(query.RelationshipTypes) > 0 {
		relPattern = ":" + strings.Join(query.RelationshipTypes, "|") + relPattern
	}

	// Build direction pattern
	directionPattern := ""
	switch query.Direction {
	case "incoming":
		directionPattern = fmt.Sprintf("<-[r%s]-", relPattern)
	case "both":
		directionPattern = fmt.Sprintf("-[r%s]-", relPattern)
	default: // "outgoing"
		directionPattern = fmt.Sprintf("-[r%s]->", relPattern)
	}

	// Set max results
	maxResults := query.MaxResults
	if maxResults <= 0 || maxResults > maxQueryResults {
		maxResults = 100
	}
	params["limit"] = maxResults

	cypher := fmt.Sprintf(`
		MATCH (start {id: $start_id})%s(related)
		WITH related, r, length(relationships(r)) as depth
		RETURN DISTINCT related, labels(related) as labels, type(r) as rel_type, depth
		ORDER BY depth ASC
		LIMIT $limit
	`, directionPattern)

	return cypher, params
}

// convertRelatedRecords converts Neo4j records to RelatedEntity slice.
func (q *Neo4jGraphQuerier) convertRelatedRecords(records []*neo4j.Record, includeProps bool) []RelatedEntity {
	results := make([]RelatedEntity, 0, len(records))

	for _, record := range records {
		nodeVal, ok := record.Get("related")
		if !ok {
			continue
		}

		node, ok := nodeVal.(neo4j.Node)
		if !ok {
			continue
		}

		labels, _ := record.Get("labels")
		labelSlice, _ := labels.([]interface{})
		relType, _ := record.Get("rel_type")
		depth, _ := record.Get("depth")

		entityType := ""
		if len(labelSlice) > 0 {
			if label, ok := labelSlice[0].(string); ok {
				entityType = strings.ToLower(label)
			}
		}

		props := node.Props
		if !includeProps {
			// Only include key identifying properties
			props = map[string]any{
				"id": node.Props["id"],
			}
			if ip, ok := node.Props["ip"]; ok {
				props["ip"] = ip
			}
			if name, ok := node.Props["name"]; ok {
				props["name"] = name
			}
		}

		relEntity := RelatedEntity{
			Entity: EntityMatch{
				ID:         q.getStringProp(node.Props, "id"),
				Type:       entityType,
				Properties: props,
				Score:      1.0,
			},
			Relationship: RelationshipInfo{
				Type: fmt.Sprint(relType),
			},
		}

		if d, ok := depth.(int64); ok {
			relEntity.Depth = int(d)
		}

		results = append(results, relEntity)
	}

	return results
}

// PatternMatch finds subgraph patterns in the knowledge graph.
func (q *Neo4jGraphQuerier) PatternMatch(ctx context.Context, query PatternQuery) ([]PatternMatchResult, error) {
	ctx, span := tracer.Start(ctx, "Neo4jGraphQuerier.PatternMatch",
		trace.WithAttributes(
			attribute.String("pattern", query.Pattern),
			attribute.String("mission_run_id", query.MissionRunID),
		))
	defer span.End()

	// Apply timeout
	ctx, cancel := context.WithTimeout(ctx, defaultQueryTimeout)
	defer cancel()

	// Parse and build Cypher from pattern
	cypher, params, aliases, err := q.buildPatternMatchQuery(query)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("invalid pattern: %w", err)
	}

	// Execute query
	session := q.driver.NewSession(ctx, neo4j.SessionConfig{
		DatabaseName: q.database,
		AccessMode:   neo4j.AccessModeRead,
	})
	defer session.Close(ctx)

	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		neoResult, err := tx.Run(ctx, cypher, params)
		if err != nil {
			return nil, err
		}

		records, err := neoResult.Collect(ctx)
		if err != nil {
			return nil, err
		}

		return q.convertPatternRecords(records, aliases), nil
	})

	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("pattern match failed: %w", err)
	}

	return result.([]PatternMatchResult), nil
}

// buildPatternMatchQuery parses the pattern and builds a Cypher query.
// Pattern format: "entity_type:alias -[relationship]-> entity_type:alias"
func (q *Neo4jGraphQuerier) buildPatternMatchQuery(query PatternQuery) (string, map[string]any, []string, error) {
	params := make(map[string]any)
	aliases := []string{}

	// Simple pattern parsing
	// Expected format: "host:h -[HAS_PORT]-> port:p -[RUNS_SERVICE]-> service:s"
	parts := strings.Split(query.Pattern, " ")

	matchParts := []string{}

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Check if it's an entity reference (type:alias)
		if strings.Contains(part, ":") && !strings.HasPrefix(part, "-[") && !strings.HasPrefix(part, "->") {
			typeAlias := strings.Split(part, ":")
			if len(typeAlias) == 2 {
				entityType := strings.Title(typeAlias[0])
				alias := typeAlias[1]
				aliases = append(aliases, alias)

				matchParts = append(matchParts, fmt.Sprintf("(%s:%s)", alias, entityType))
			}
		} else if strings.HasPrefix(part, "-[") {
			// Relationship pattern
			relPart := strings.TrimPrefix(part, "-[")
			relPart = strings.TrimSuffix(relPart, "]->")
			relPart = strings.TrimSuffix(relPart, "]-")
			matchParts = append(matchParts, fmt.Sprintf("-[:%s]->", relPart))
		}
	}

	if len(matchParts) == 0 {
		return "", nil, nil, fmt.Errorf("could not parse pattern: %s", query.Pattern)
	}

	// Build WHERE clauses for filters
	whereClauses := []string{}

	// Mission scope
	if query.MissionRunID != "" && len(aliases) > 0 {
		whereClauses = append(whereClauses, fmt.Sprintf("%s.mission_run_id = $mission_run_id", aliases[0]))
		params["mission_run_id"] = query.MissionRunID
	}

	// Property filters per alias
	for alias, filters := range query.Filters {
		for key, value := range filters {
			paramKey := fmt.Sprintf("%s_%s", alias, key)
			whereClauses = append(whereClauses, fmt.Sprintf("%s.%s = $%s", alias, key, paramKey))
			params[paramKey] = value
		}
	}

	whereClause := ""
	if len(whereClauses) > 0 {
		whereClause = "WHERE " + strings.Join(whereClauses, " AND ")
	}

	// Set max results
	maxResults := query.MaxResults
	if maxResults <= 0 || maxResults > maxQueryResults {
		maxResults = 100
	}
	params["limit"] = maxResults

	// Build RETURN clause
	returnParts := make([]string, len(aliases))
	for i, alias := range aliases {
		returnParts[i] = alias
	}

	cypher := fmt.Sprintf(`
		MATCH %s
		%s
		RETURN %s
		LIMIT $limit
	`, strings.Join(matchParts, ""), whereClause, strings.Join(returnParts, ", "))

	return cypher, params, aliases, nil
}

// convertPatternRecords converts Neo4j records to PatternMatchResult slice.
func (q *Neo4jGraphQuerier) convertPatternRecords(records []*neo4j.Record, aliases []string) []PatternMatchResult {
	results := make([]PatternMatchResult, 0, len(records))

	for _, record := range records {
		match := PatternMatchResult{
			Bindings: make(map[string]EntityMatch),
			Score:    1.0,
		}

		for _, alias := range aliases {
			nodeVal, ok := record.Get(alias)
			if !ok {
				continue
			}

			node, ok := nodeVal.(neo4j.Node)
			if !ok {
				continue
			}

			entityType := ""
			if len(node.Labels) > 0 {
				entityType = strings.ToLower(node.Labels[0])
			}

			match.Bindings[alias] = EntityMatch{
				ID:         q.getStringProp(node.Props, "id"),
				Type:       entityType,
				Properties: node.Props,
				Score:      1.0,
			}
		}

		if len(match.Bindings) > 0 {
			results = append(results, match)
		}
	}

	return results
}

// SemanticSearch performs vector similarity search on entity descriptions.
// Note: This requires entities to have embeddings stored in the graph.
func (q *Neo4jGraphQuerier) SemanticSearch(ctx context.Context, query SemanticQuery) ([]EntityMatch, error) {
	ctx, span := tracer.Start(ctx, "Neo4jGraphQuerier.SemanticSearch",
		trace.WithAttributes(
			attribute.String("query", query.Query),
			attribute.Float64("min_similarity", query.MinSimilarity),
		))
	defer span.End()

	// Apply timeout
	ctx, cancel := context.WithTimeout(ctx, defaultQueryTimeout)
	defer cancel()

	// Note: Full semantic search requires vector embeddings and similarity functions.
	// This is a placeholder that does text-based matching on descriptions.
	// For production, integrate with Neo4j's vector search or external embedding service.

	params := map[string]any{
		"query_text": "%" + query.Query + "%",
	}

	// Build label filter
	labelFilter := ""
	if len(query.EntityTypes) > 0 {
		labels := make([]string, len(query.EntityTypes))
		for i, t := range query.EntityTypes {
			labels[i] = strings.Title(t)
		}
		labelFilter = ":" + strings.Join(labels, "|")
	}

	// Mission filter
	missionFilter := ""
	if query.MissionRunID != "" {
		missionFilter = "AND n.mission_run_id = $mission_run_id"
		params["mission_run_id"] = query.MissionRunID
	}

	// Set max results
	maxResults := query.MaxResults
	if maxResults <= 0 || maxResults > 100 {
		maxResults = 20
	}
	params["limit"] = maxResults

	cypher := fmt.Sprintf(`
		MATCH (n%s)
		WHERE (n.description CONTAINS $query_text
			OR n.name CONTAINS $query_text
			OR n.title CONTAINS $query_text
			OR n.ip CONTAINS $query_text
			OR n.url CONTAINS $query_text)
		%s
		RETURN n, labels(n) as labels
		LIMIT $limit
	`, labelFilter, missionFilter)

	// Execute query
	session := q.driver.NewSession(ctx, neo4j.SessionConfig{
		DatabaseName: q.database,
		AccessMode:   neo4j.AccessModeRead,
	})
	defer session.Close(ctx)

	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		neoResult, err := tx.Run(ctx, cypher, params)
		if err != nil {
			return nil, err
		}

		records, err := neoResult.Collect(ctx)
		if err != nil {
			return nil, err
		}

		matches := q.convertEntityRecords(records)

		// Apply simple text similarity scoring
		for i := range matches {
			matches[i].Score = q.calculateTextSimilarity(query.Query, matches[i].Properties)
		}

		return matches, nil
	})

	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("semantic search failed: %w", err)
	}

	matches := result.([]EntityMatch)

	// Filter by minimum similarity
	if query.MinSimilarity > 0 {
		filtered := make([]EntityMatch, 0, len(matches))
		for _, m := range matches {
			if m.Score >= query.MinSimilarity {
				filtered = append(filtered, m)
			}
		}
		matches = filtered
	}

	return matches, nil
}

// calculateTextSimilarity calculates a simple text similarity score.
// This is a placeholder - production should use proper embeddings.
func (q *Neo4jGraphQuerier) calculateTextSimilarity(query string, props map[string]any) float64 {
	queryLower := strings.ToLower(query)
	queryWords := strings.Fields(queryLower)

	matchCount := 0
	totalWords := len(queryWords)

	if totalWords == 0 {
		return 0.5
	}

	// Check each property for matching words
	for _, value := range props {
		if strVal, ok := value.(string); ok {
			strLower := strings.ToLower(strVal)
			for _, word := range queryWords {
				if strings.Contains(strLower, word) {
					matchCount++
				}
			}
		}
	}

	// Normalize score
	score := float64(matchCount) / float64(totalWords)
	if score > 1.0 {
		score = 1.0
	}

	return score
}

// getStringProp safely extracts a string property from a map.
func (q *Neo4jGraphQuerier) getStringProp(props map[string]any, key string) string {
	if val, ok := props[key]; ok {
		if strVal, ok := val.(string); ok {
			return strVal
		}
	}
	return ""
}

// Ensure Neo4jGraphQuerier implements GraphQuerier.
var _ GraphQuerier = (*Neo4jGraphQuerier)(nil)
