// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package migrations holds the Neo4j schema version contract for the Gibson
// daemon and the tenant operator.
//
// The tenant Neo4j schema is not a set of migration files. The graph projector
// derives the constraints and indexes from the taxonomy and applies them once
// per tenant before its first write
// (internal/server/daemon/graph_projector_schema.go, applySchema).
// It records Neo4jSchemaVersion in the :_SchemaVersion node, and the tenant
// operator compares that node with LatestNeo4jVersion for its pending-migration
// metric.
//
// Postgres migrations live in github.com/zeroroot-ai/gibson/pkg/platform/migrations.
package migrations

// Neo4jSchemaVersion is the schema version the projector writes to the
// :_SchemaVersion node. It equals taxonomy.Version. This package cannot import
// the taxonomy, because the tenant operator imports this package and never
// internal/engine. A test in internal/server/daemon fails when the two differ.
const Neo4jSchemaVersion uint = 4

// LatestNeo4jVersion returns the schema version a tenant Neo4j database is
// expected to report.
func LatestNeo4jVersion() (uint, error) {
	return Neo4jSchemaVersion, nil
}
