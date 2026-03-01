package daemon

import (
	"context"
	"fmt"
	"time"

	"github.com/zero-day-ai/gibson/internal/graphrag/graph"
	"github.com/zero-day-ai/gibson/internal/observability"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// initLangfuseTracing initializes Langfuse tracing exporter with optional Neo4j graph span processor.
// If neo4jClient is provided, spans will be recorded to both Langfuse and Neo4j for observability.
// Returns the tracer provider and a slice of span processors that were registered.
func (d *daemonImpl) initLangfuseTracing(ctx context.Context, neo4jClient *graph.Neo4jClient) (*sdktrace.TracerProvider, []sdktrace.SpanProcessor, error) {
	cfg := d.config.Langfuse

	// Validate required Langfuse configuration fields
	if cfg.Host == "" {
		return nil, nil, fmt.Errorf("langfuse.host is required when langfuse.enabled = true")
	}
	if cfg.PublicKey == "" {
		return nil, nil, fmt.Errorf("langfuse.public_key is required when langfuse.enabled = true")
	}
	if cfg.SecretKey == "" {
		return nil, nil, fmt.Errorf("langfuse.secret_key is required when langfuse.enabled = true")
	}

	d.logger.Info(ctx, "langfuse observability enabled",
		"host", cfg.Host,
		"public_key_configured", cfg.PublicKey != "",
	)

	langfuseCfg := observability.LangfuseConfig{
		Host:      cfg.Host,
		PublicKey: cfg.PublicKey,
		SecretKey: cfg.SecretKey,
	}

	tracingCfg := observability.TracingConfig{
		Enabled:     true,
		Provider:    "langfuse",
		Endpoint:    cfg.Host, // Langfuse host serves as endpoint
		ServiceName: "gibson",
		SampleRate:  1.0,
	}

	// Initialize the tracer provider with Langfuse exporter
	tracerProvider, err := observability.InitTracing(ctx, tracingCfg, &langfuseCfg)
	if err != nil {
		return nil, nil, err
	}

	// Track span processors for callback service
	// NOTE: GraphSpanProcessor has been removed along with the taxonomy engine.
	// When GraphLoader-based span recording is implemented, it can be added here.
	var spanProcessors []sdktrace.SpanProcessor

	return tracerProvider, spanProcessors, nil
}

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
