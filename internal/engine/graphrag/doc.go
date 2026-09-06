// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package graphrag is the daemon's hybrid graph + vector retrieval layer over
// Neo4j: it answers queries that combine vector similarity with graph
// traversal.
//
// It is READ-ONLY. ADR-0012 makes the projector the single writer of the
// knowledge graph, and sdk#451 took the last write RPC off the wire, so the
// store and provider write halves were removed in gibson#1322. Nothing here
// builds Cypher that writes.
//
// Top-level files:
//
//	api.go              — public GraphRAGStore interface + constructors
//	store.go            — DefaultGraphRAGStore lifecycle (Query/GetNode/TraverseGraph/etc.)
//	store_findings.go   — Finding reads (FindSimilarFindings, GetRelatedFindings, …)
//	store_attacks.go    — AttackPattern reads (FindSimilarAttacks, GetAttackChains, …)
//	query.go            — GraphRAGQuery input type + builders + Validate
//	result.go           — GraphRAGResult output type + scoring helpers
//	node_query.go       — NodeQuery (direct lookup), TraversalFilters, MissionScope
//	attack_chain.go     — AttackChain + AttackStep types
//	vector_result.go    — VectorResult (vector-only search result)
//	query_pipeline.go   — QueryPipeline interface + DefaultQueryPipeline (hybrid pipeline)
//	merge.go            — MergeReranker (vector + graph score combination)
//	traced_store.go     — OpenTelemetry-wrapped store
//	provider.go         — GraphRAGProvider storage abstraction (impls in provider/ subpkg)
//	mission_graph_manager.go — per-mission subgraph lifecycle
//	types.go            — graph nodes, relationships, labels (the wire types)
//	attributes.go       — observability attribute keys
//	config.go           — GraphRAGConfig
//	errors.go           — typed errors (Embedding, Query, NodeNotFound, …)
//
// Subpackages:
//
//	graph/         — thin Neo4j driver wrapper (low-level)
//	cypher/        — Cypher predicate builders
//	engine/        — Cypher query engine
//	queries/       — per-target Cypher query builders (used by orchestrator Path A)
//	intelligence/  — cross-mission analytics (5 RPCs)
//	loader/        — DiscoveryResult → Neo4j ingest pipeline
//	ingest/        — DiscoveryProcessor (consumes tool field 100, calls loader)
//	schema/        — Neo4j schema migrations
//	provider/      — GraphRAGProvider concrete impls (cloud=Neo4j, hybrid, local)
//
// DefaultGraphRAGStore is safe for concurrent use.
package graphrag
