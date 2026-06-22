// Package engine provides Cypher query building utilities for GraphRAG.
//
// # Overview
//
// The engine package provides CypherBuilder, a utility for generating safe,
// parameterized Neo4j Cypher queries. It follows Neo4j best practices for
// query construction and prevents injection attacks through proper parameter
// handling.
//
// # CypherBuilder
//
// CypherBuilder generates Cypher queries for common graph operations:
//
//   - Node MERGE (create or update)
//   - Relationship MERGE (create or update)
//   - Batch node operations
//   - Batch relationship operations
//   - Node queries
//   - Relationship queries
//   - Node deletion
//
// # Basic Usage
//
// Create a CypherBuilder and use it to generate queries:
//
//	builder := NewCypherBuilder()
//
//	// Create/update a node
//	query, params := builder.BuildNodeMerge("mission", "mission:abc123", map[string]any{
//	    "name": "Test Mission",
//	    "status": "running",
//	})
//
//	// Create a relationship
//	query, params := builder.BuildRelationshipMerge("PART_OF", "tool:nmap", "mission:abc123", nil)
//
// # Label and Type Conventions
//
// The builder enforces naming conventions:
//   - Node labels: lowercase with underscores (e.g., "mission", "agent_run")
//   - Relationship types: UPPERCASE with underscores (e.g., "PART_OF", "DISCOVERED")
//   - Property names: lowercase with underscores (e.g., "created_at", "ip_address")
//
// # Thread Safety
//
// CypherBuilder is safe for concurrent use. Multiple goroutines can call
// its methods simultaneously.
package engine
