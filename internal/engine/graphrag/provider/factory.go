package provider

import (
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/engine/graphrag"
)

// NewProvider creates the GraphRAGProvider for the configured graph database.
// As of 2026-04-28 (spec internal-package-restructure / Phase B), there is
// exactly one supported provider: a Neo4j-backed local store. The historical
// "cloud" and "hybrid" providers were deleted in that spec because they
// proxied to a hypothetical Gibson Cloud GraphRAG API that was never built.
//
// Accepted config.Provider values:
//   - "neo4j" (canonical)
//   - "local" (historical alias retained for back-compat)
func NewProvider(config graphrag.GraphRAGConfig) (graphrag.GraphRAGProvider, error) {
	if err := config.Validate(); err != nil {
		return nil, graphrag.NewConfigError("invalid GraphRAG configuration", err)
	}

	switch config.Provider {
	case "neo4j", "local":
		return NewLocalProvider(config)
	default:
		return nil, graphrag.NewConfigError(
			fmt.Sprintf("unsupported provider type %q (only \"neo4j\" / \"local\" are supported; \"cloud\" and \"hybrid\" were removed in spec internal-package-restructure)", config.Provider),
			nil,
		)
	}
}
