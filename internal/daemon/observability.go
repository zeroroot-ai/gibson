package daemon

import (
	"context"
	"fmt"
	"time"

	"github.com/zero-day-ai/gibson/internal/graphrag/graph"
)

// initGraphRAG initializes Neo4j client for GraphRAG.
func (d *daemonImpl) initGraphRAG(ctx context.Context) (*graph.Neo4jClient, error) {
	cfg := d.config.GraphRAG.Neo4j

	// Apply defaults
	maxConns := cfg.MaxConnections
	if maxConns == 0 {
		maxConns = 20
	}
	connTimeout := cfg.ConnectionTimeout
	if connTimeout == 0 {
		connTimeout = 30 * time.Second
	}

	graphConfig := graph.GraphClientConfig{
		URI:                     cfg.URI,
		Username:                cfg.Username,
		Password:                cfg.Password,
		MaxConnectionPoolSize:   maxConns,
		ConnectionTimeout:       connTimeout,
		MaxTransactionRetryTime: 30 * time.Second, // Required by validation
	}

	client, err := graph.NewNeo4jClient(graphConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Neo4j client: %w", err)
	}

	if err := client.Connect(ctx); err != nil {
		return nil, fmt.Errorf("failed to connect to Neo4j: %w", err)
	}

	return client, nil
}
