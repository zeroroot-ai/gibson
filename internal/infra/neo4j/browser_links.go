package neo4j

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// QueryType represents the type of Neo4j query to generate.
type QueryType int

const (
	// QueryTypeFull retrieves all entities and relationships for a mission.
	QueryTypeFull QueryType = iota

	// QueryTypeHosts retrieves hosts with their ports for a mission.
	QueryTypeHosts

	// QueryTypeVulnerabilities retrieves vulnerabilities with affected services for a mission.
	QueryTypeVulnerabilities

	// QueryTypeAttackPaths retrieves shortest paths from hosts to vulnerabilities for a mission.
	QueryTypeAttackPaths
)

// String returns the string representation of a QueryType.
func (q QueryType) String() string {
	switch q {
	case QueryTypeFull:
		return "full"
	case QueryTypeHosts:
		return "hosts"
	case QueryTypeVulnerabilities:
		return "vulnerabilities"
	case QueryTypeAttackPaths:
		return "attack_paths"
	default:
		return "unknown"
	}
}

// BrowserURL generates a Neo4j Browser URL with a pre-populated Cypher query.
// The URL follows the Neo4j Browser URL scheme: {baseURL}/browser/?cmd=edit&arg={encoded_cypher}
//
// Parameters:
//   - baseURL: The base URL of the Neo4j Browser (e.g., "http://localhost:7474")
//   - missionID: The mission ID to query for
//   - queryType: The type of query to generate (Full, Hosts, Vulnerabilities, or AttackPaths)
//
// Returns:
//   - string: A fully-formed Neo4j Browser URL with encoded Cypher query
//   - error: If baseURL is invalid or missionID is empty
//
// Example:
//
//	url, err := neo4j.BrowserURL("http://localhost:7474", "mission-123", QueryTypeFull)
//	// Returns: "http://localhost:7474/browser/?cmd=edit&arg=MATCH%20(m:Mission%20{id:..."
func BrowserURL(baseURL string, missionID types.ID, queryType QueryType) (string, error) {
	// Validate inputs
	if baseURL == "" {
		return "", fmt.Errorf("baseURL cannot be empty")
	}
	if missionID == "" {
		return "", fmt.Errorf("missionID cannot be empty")
	}

	// Parse and validate base URL
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid baseURL: %w", err)
	}

	// Ensure URL has scheme and host
	if parsedURL.Scheme == "" {
		return "", fmt.Errorf("baseURL must include scheme (http or https)")
	}
	if parsedURL.Host == "" {
		return "", fmt.Errorf("baseURL must include host")
	}

	// Generate the appropriate Cypher query
	cypherQuery := generateCypherQuery(missionID, queryType)

	// URL-encode the Cypher query
	encodedQuery := url.QueryEscape(cypherQuery)

	// Construct the Neo4j Browser URL
	// Neo4j Browser URL format: {baseURL}/browser/?cmd=edit&arg={encoded_cypher}
	browserURL := fmt.Sprintf("%s/browser/?cmd=edit&arg=%s", strings.TrimRight(baseURL, "/"), encodedQuery)

	return browserURL, nil
}

// generateCypherQuery generates the appropriate Cypher query based on queryType.
func generateCypherQuery(missionID types.ID, queryType QueryType) string {
	missionIDStr := missionID.String()

	switch queryType {
	case QueryTypeFull:
		// Return all entities and relationships connected to the mission
		return fmt.Sprintf(`MATCH (m:Mission {id: "%s"})
OPTIONAL MATCH (m)-[*]-(n)
WITH m, collect(DISTINCT n) as nodes
OPTIONAL MATCH (m)-[*]-(a)-[r]->(b)
WHERE a IN nodes AND b IN nodes
RETURN m, nodes, collect(DISTINCT r) as relationships`, missionIDStr)

	case QueryTypeHosts:
		// Return hosts with their ports
		return fmt.Sprintf(`MATCH (m:Mission {id: "%s"})
MATCH (m)-[:HAS_TARGET]->(h:Host)
OPTIONAL MATCH (h)-[:HAS_PORT]->(p:Port)
RETURN h, collect(p) as ports`, missionIDStr)

	case QueryTypeVulnerabilities:
		// Return vulnerabilities with affected services
		return fmt.Sprintf(`MATCH (m:Mission {id: "%s"})
MATCH (m)-[*]-(v:Vulnerability)
OPTIONAL MATCH (v)-[:AFFECTS]->(s:Service)
RETURN v, collect(s) as affected_services`, missionIDStr)

	case QueryTypeAttackPaths:
		// Return shortest paths from hosts to vulnerabilities
		return fmt.Sprintf(`MATCH (m:Mission {id: "%s"})
MATCH (m)-[:HAS_TARGET]->(h:Host)
MATCH (m)-[*]-(v:Vulnerability)
MATCH path = shortestPath((h)-[*]-(v))
RETURN path`, missionIDStr)

	default:
		// Fallback to full query
		return generateCypherQuery(missionID, QueryTypeFull)
	}
}

// QueryReference creates a plain-text Cypher query reference for logging.
// This is useful for including the actual query in span metadata alongside the browser URL.
//
// Parameters:
//   - missionID: The mission ID to query for
//   - queryType: The type of query to generate
//
// Returns:
//   - string: The Cypher query as plain text
func QueryReference(missionID types.ID, queryType QueryType) string {
	return generateCypherQuery(missionID, queryType)
}

// MustBrowserURL is like BrowserURL but panics on error.
// This should only be used in contexts where the inputs are guaranteed to be valid
// (e.g., after validation has already occurred).
//
// Parameters:
//   - baseURL: The base URL of the Neo4j Browser
//   - missionID: The mission ID to query for
//   - queryType: The type of query to generate
//
// Returns:
//   - string: A fully-formed Neo4j Browser URL with encoded Cypher query
//
// Panics:
//   - If baseURL is invalid or missionID is empty
func MustBrowserURL(baseURL string, missionID types.ID, queryType QueryType) string {
	browserURL, err := BrowserURL(baseURL, missionID, queryType)
	if err != nil {
		panic(fmt.Sprintf("BrowserURL failed: %v", err))
	}
	return browserURL
}
