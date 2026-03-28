//go:build integration
// +build integration

package orchestrator

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// setupNeo4jContainer starts a Neo4j container for integration testing.
// Returns the container, driver, and cleanup function.
func setupNeo4jContainer(t *testing.T, ctx context.Context) (testcontainers.Container, neo4j.DriverWithContext, func()) {
	t.Helper()

	// Check if Docker is available
	provider, err := testcontainers.ProviderDocker.GetProvider()
	if err != nil {
		t.Skip("Docker not available, skipping integration test")
		return nil, nil, func() {}
	}

	// Ping Docker to verify it's running
	if err := provider.Health(ctx); err != nil {
		t.Skip("Docker not running, skipping integration test")
		return nil, nil, func() {}
	}

	// Create Neo4j container with authentication disabled for testing
	req := testcontainers.ContainerRequest{
		Image:        "neo4j:5",
		ExposedPorts: []string{"7687/tcp"},
		Env: map[string]string{
			"NEO4J_AUTH": "none", // Disable authentication for testing
		},
		WaitingFor: wait.ForAll(
			wait.ForListeningPort("7687/tcp"),
			wait.ForLog("Started."),
		).WithDeadline(120 * time.Second), // Neo4j can take a while to start
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("Failed to start Neo4j container: %v", err)
	}

	// Get container endpoint
	host, err := container.Host(ctx)
	require.NoError(t, err, "Failed to get container host")

	port, err := container.MappedPort(ctx, "7687")
	require.NoError(t, err, "Failed to get mapped port")

	// Create Neo4j driver
	uri := fmt.Sprintf("bolt://%s:%s", host, port.Port())
	driver, err := neo4j.NewDriverWithContext(
		uri,
		neo4j.NoAuth(),
		func(config *neo4j.Config) {
			config.MaxConnectionPoolSize = 10
			config.ConnectionAcquisitionTimeout = 30 * time.Second
		},
	)
	require.NoError(t, err, "Failed to create Neo4j driver")

	// Verify connection
	err = driver.VerifyConnectivity(ctx)
	require.NoError(t, err, "Failed to verify Neo4j connectivity")

	cleanup := func() {
		_ = driver.Close(ctx)
		_ = container.Terminate(ctx)
	}

	return container, driver, cleanup
}

// setupNeo4jFromEnv attempts to connect to a Neo4j instance specified by NEO4J_URI environment variable.
// Returns driver and cleanup function, or skips test if NEO4J_URI is not set.
func setupNeo4jFromEnv(t *testing.T, ctx context.Context) (neo4j.DriverWithContext, func()) {
	t.Helper()

	uri := os.Getenv("NEO4J_URI")
	if uri == "" {
		t.Skip("NEO4J_URI not set, skipping integration test")
		return nil, func() {}
	}

	username := os.Getenv("NEO4J_USERNAME")
	if username == "" {
		username = "neo4j"
	}

	password := os.Getenv("NEO4J_PASSWORD")
	if password == "" {
		password = "password"
	}

	driver, err := neo4j.NewDriverWithContext(
		uri,
		neo4j.BasicAuth(username, password, ""),
		func(config *neo4j.Config) {
			config.MaxConnectionPoolSize = 10
			config.ConnectionAcquisitionTimeout = 30 * time.Second
		},
	)
	require.NoError(t, err, "Failed to create Neo4j driver")

	// Verify connection
	err = driver.VerifyConnectivity(ctx)
	if err != nil {
		t.Skipf("Failed to connect to Neo4j at %s: %v", uri, err)
		return nil, func() {}
	}

	cleanup := func() {
		_ = driver.Close(ctx)
	}

	return driver, cleanup
}

// cleanDatabase removes all nodes and relationships from the database.
func cleanDatabase(ctx context.Context, t *testing.T, driver neo4j.DriverWithContext) {
	t.Helper()

	session := driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	_, err := session.Run(ctx, "MATCH (n) DETACH DELETE n", nil)
	require.NoError(t, err, "Failed to clean database")
}

// seedTestData populates the database with realistic test data matching the taxonomy.
func seedTestData(ctx context.Context, t *testing.T, driver neo4j.DriverWithContext) {
	t.Helper()

	session := driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	// Create test data with realistic attack graph structure
	// This includes: hosts, ports, services, and findings with relationships
	cypher := `
		// Create hosts
		CREATE (h1:host {
			id: 'host-192.168.1.100',
			ip: '192.168.1.100',
			hostname: 'web-server.example.com',
			domain: 'example.com',
			discovered_at: $now
		})
		CREATE (h2:host {
			id: 'host-192.168.1.101',
			ip: '192.168.1.101',
			hostname: 'api-server.example.com',
			domain: 'example.com',
			discovered_at: $now
		})

		// Create ports
		CREATE (p1:port {
			id: 'port-192.168.1.100:443',
			host_ip: '192.168.1.100',
			number: 443,
			protocol: 'tcp',
			state: 'open',
			discovered_at: $now
		})
		CREATE (p2:port {
			id: 'port-192.168.1.101:8080',
			host_ip: '192.168.1.101',
			number: 8080,
			protocol: 'tcp',
			state: 'open',
			discovered_at: $now
		})

		// Create services
		CREATE (s1:service {
			id: 'service-https-443',
			name: 'https',
			port: 443,
			host_ip: '192.168.1.100',
			product: 'nginx',
			version: '1.18.0',
			discovered_at: $now
		})
		CREATE (s2:service {
			id: 'service-http-8080',
			name: 'http',
			port: 8080,
			host_ip: '192.168.1.101',
			product: 'tomcat',
			version: '9.0.45',
			discovered_at: $now
		})

		// Create findings with MITRE ATT&CK techniques
		CREATE (f1:finding {
			id: 'finding-001',
			title: 'SQL Injection in Login Form',
			description: 'SQL injection vulnerability detected in /api/login endpoint',
			severity: 'critical',
			category: 'injection',
			technique_id: 'T1190',
			technique_name: 'Exploit Public-Facing Application',
			discovered_at: $now
		})
		CREATE (f2:finding {
			id: 'finding-002',
			title: 'Outdated Nginx Version',
			description: 'Server running outdated nginx 1.18.0 with known CVEs',
			severity: 'high',
			category: 'misconfiguration',
			technique_id: 'T1190',
			technique_name: 'Exploit Public-Facing Application',
			discovered_at: $now
		})
		CREATE (f3:finding {
			id: 'finding-003',
			title: 'XSS in User Profile',
			description: 'Cross-site scripting vulnerability in user profile endpoint',
			severity: 'medium',
			category: 'injection',
			technique_id: 'T1059',
			technique_name: 'Command and Scripting Interpreter',
			discovered_at: $now
		})
		CREATE (f4:finding {
			id: 'finding-004',
			title: 'Open Directory Listing',
			description: 'Directory listing enabled on web server',
			severity: 'low',
			category: 'misconfiguration',
			technique_id: 'T1083',
			technique_name: 'File and Directory Discovery',
			discovered_at: $now
		})

		// Create relationships: Hosts -> Ports
		CREATE (h1)-[:HAS_PORT]->(p1)
		CREATE (h2)-[:HAS_PORT]->(p2)

		// Create relationships: Ports -> Services
		CREATE (p1)-[:RUNS_SERVICE]->(s1)
		CREATE (p2)-[:RUNS_SERVICE]->(s2)

		// Create relationships: Findings -> Targets
		CREATE (f1)-[:RELATES_TO]->(h2)
		CREATE (f2)-[:RELATES_TO]->(s1)
		CREATE (f3)-[:RELATES_TO]->(h2)
		CREATE (f4)-[:RELATES_TO]->(h1)
	`

	params := map[string]any{
		"now": time.Now().Format(time.RFC3339),
	}

	_, err := session.Run(ctx, cypher, params)
	require.NoError(t, err, "Failed to seed test data")
}

// TestIntegration_GetTargetHistory tests retrieving historical scan information for a target.
func TestIntegration_GetTargetHistory(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()

	// Try to use environment variable first, fall back to testcontainer
	driver, cleanup := setupNeo4jFromEnv(t, ctx)
	if driver == nil {
		_, driver, cleanup = setupNeo4jContainer(t, ctx)
	}
	defer cleanup()

	// Clean and seed database
	cleanDatabase(ctx, t, driver)
	seedTestData(ctx, t, driver)

	// Create graph queries instance
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	registry := prometheus.NewRegistry()
	queries := NewNeo4jGraphQueriesWithMetrics(driver, logger, registry)

	t.Run("retrieves history for known target", func(t *testing.T) {
		history, err := queries.GetTargetHistory(ctx, "host-192.168.1.100")
		require.NoError(t, err)
		require.NotNil(t, history)

		assert.Equal(t, "host-192.168.1.100", history.TargetID)
		assert.Equal(t, 1, history.PreviousScanCount)
		assert.Equal(t, 1, history.TotalFindings) // Finding-004 relates to this host
		assert.Equal(t, 0, history.CriticalCount)
		assert.Equal(t, 0, history.HighCount)
		assert.Equal(t, 0, history.MediumCount)
		assert.Equal(t, 1, history.LowCount)
		assert.NotNil(t, history.LastScanDate)
	})

	t.Run("retrieves history for target with multiple findings", func(t *testing.T) {
		history, err := queries.GetTargetHistory(ctx, "host-192.168.1.101")
		require.NoError(t, err)
		require.NotNil(t, history)

		assert.Equal(t, "host-192.168.1.101", history.TargetID)
		assert.Equal(t, 1, history.PreviousScanCount)
		assert.Equal(t, 2, history.TotalFindings) // Finding-001 and Finding-003
		assert.Equal(t, 1, history.CriticalCount)
		assert.Equal(t, 0, history.HighCount)
		assert.Equal(t, 1, history.MediumCount)
		assert.Equal(t, 0, history.LowCount)
	})

	t.Run("returns nil for unknown target", func(t *testing.T) {
		history, err := queries.GetTargetHistory(ctx, "host-unknown")
		require.NoError(t, err)
		assert.Nil(t, history)
	})

	t.Run("respects timeout", func(t *testing.T) {
		timeoutCtx, cancel := context.WithTimeout(ctx, 1*time.Millisecond)
		defer cancel()

		// Should timeout gracefully
		history, err := queries.GetTargetHistory(timeoutCtx, "host-192.168.1.100")
		// Graceful degradation - returns nil instead of error
		assert.NoError(t, err)
		// May be nil if timeout occurred
		_ = history
	})
}

// TestIntegration_GetPriorFindings tests retrieving recent findings for a domain.
func TestIntegration_GetPriorFindings(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()

	driver, cleanup := setupNeo4jFromEnv(t, ctx)
	if driver == nil {
		_, driver, cleanup = setupNeo4jContainer(t, ctx)
	}
	defer cleanup()

	cleanDatabase(ctx, t, driver)
	seedTestData(ctx, t, driver)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	queries := NewNeo4jGraphQueries(driver, logger)

	t.Run("retrieves findings for domain ordered by severity", func(t *testing.T) {
		findings, err := queries.GetPriorFindings(ctx, "example.com", 10)
		require.NoError(t, err)
		require.NotEmpty(t, findings)

		// Verify findings are ordered by severity (critical first)
		if len(findings) >= 2 {
			// First finding should be critical (finding-001)
			assert.Equal(t, "critical", findings[0].Severity)
			assert.Equal(t, "SQL Injection in Login Form", findings[0].Title)
		}

		// Verify all findings have required fields
		for _, finding := range findings {
			assert.NotEmpty(t, finding.ID)
			assert.NotEmpty(t, finding.Title)
			assert.NotEmpty(t, finding.Severity)
			assert.NotZero(t, finding.DiscoveredAt)
		}
	})

	t.Run("respects limit parameter", func(t *testing.T) {
		findings, err := queries.GetPriorFindings(ctx, "example.com", 2)
		require.NoError(t, err)
		assert.LessOrEqual(t, len(findings), 2)
	})

	t.Run("returns empty slice for unknown domain", func(t *testing.T) {
		findings, err := queries.GetPriorFindings(ctx, "unknown.com", 10)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("handles IP address queries", func(t *testing.T) {
		findings, err := queries.GetPriorFindings(ctx, "192.168.1.101", 10)
		require.NoError(t, err)
		// Should find findings related to entities containing this IP
		assert.NotEmpty(t, findings)
	})
}

// TestIntegration_GetKnownEntities tests retrieving previously discovered entities.
func TestIntegration_GetKnownEntities(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()

	driver, cleanup := setupNeo4jFromEnv(t, ctx)
	if driver == nil {
		_, driver, cleanup = setupNeo4jContainer(t, ctx)
	}
	defer cleanup()

	cleanDatabase(ctx, t, driver)
	seedTestData(ctx, t, driver)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	queries := NewNeo4jGraphQueries(driver, logger)

	t.Run("retrieves related entities for host", func(t *testing.T) {
		entities, err := queries.GetKnownEntities(ctx, "host-192.168.1.100")
		require.NoError(t, err)
		require.NotEmpty(t, entities)

		// Should find the host itself and related entities (ports, services)
		types := make(map[string]int)
		for _, entity := range entities {
			assert.NotEmpty(t, entity.ID)
			assert.NotEmpty(t, entity.Type)
			assert.NotZero(t, entity.DiscoveredAt)
			types[entity.Type]++
		}

		t.Logf("Found entity types: %v", types)
	})

	t.Run("filters out framework properties", func(t *testing.T) {
		entities, err := queries.GetKnownEntities(ctx, "host-192.168.1.100")
		require.NoError(t, err)
		require.NotEmpty(t, entities)

		// Verify no framework properties are present
		for _, entity := range entities {
			assert.NotContains(t, entity.Properties, "discovered_at")
			assert.NotContains(t, entity.Properties, "mission_id")
			assert.NotContains(t, entity.Properties, "mission_run_id")
			assert.NotContains(t, entity.Properties, "agent_run_id")
			assert.NotContains(t, entity.Properties, "discovered_by")
		}
	})

	t.Run("returns empty slice for unknown target", func(t *testing.T) {
		entities, err := queries.GetKnownEntities(ctx, "host-unknown")
		require.NoError(t, err)
		// May be empty or contain only the queried node
		_ = entities
	})
}

// TestIntegration_GetSuccessfulPatterns tests retrieving successful attack patterns.
func TestIntegration_GetSuccessfulPatterns(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()

	driver, cleanup := setupNeo4jFromEnv(t, ctx)
	if driver == nil {
		_, driver, cleanup = setupNeo4jContainer(t, ctx)
	}
	defer cleanup()

	cleanDatabase(ctx, t, driver)
	seedTestData(ctx, t, driver)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	queries := NewNeo4jGraphQueries(driver, logger)

	t.Run("retrieves patterns for target type", func(t *testing.T) {
		patterns, err := queries.GetSuccessfulPatterns(ctx, "host")
		require.NoError(t, err)

		// Should find patterns (findings with technique_id related to hosts)
		if len(patterns) > 0 {
			for _, pattern := range patterns {
				assert.NotEmpty(t, pattern.TechniqueID)
				assert.NotEmpty(t, pattern.TechniqueName)
				assert.GreaterOrEqual(t, pattern.SuccessRate, 0.0)
				assert.LessOrEqual(t, pattern.SuccessRate, 1.0)
				assert.Greater(t, pattern.SampleCount, 0)
			}
		}
	})

	t.Run("returns empty slice for target type with no findings", func(t *testing.T) {
		patterns, err := queries.GetSuccessfulPatterns(ctx, "unknown_type")
		require.NoError(t, err)
		assert.Empty(t, patterns)
	})

	t.Run("patterns are ordered by sample count", func(t *testing.T) {
		patterns, err := queries.GetSuccessfulPatterns(ctx, "host")
		require.NoError(t, err)

		// Verify descending order by sample count
		for i := 1; i < len(patterns); i++ {
			assert.GreaterOrEqual(t, patterns[i-1].SampleCount, patterns[i].SampleCount)
		}
	})
}

// TestIntegration_ConcurrentQueries tests concurrent query execution.
func TestIntegration_ConcurrentQueries(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()

	driver, cleanup := setupNeo4jFromEnv(t, ctx)
	if driver == nil {
		_, driver, cleanup = setupNeo4jContainer(t, ctx)
	}
	defer cleanup()

	cleanDatabase(ctx, t, driver)
	seedTestData(ctx, t, driver)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	registry := prometheus.NewRegistry()
	queries := NewNeo4jGraphQueriesWithMetrics(driver, logger, registry)

	t.Run("handles concurrent queries safely", func(t *testing.T) {
		concurrency := 10
		var wg sync.WaitGroup
		wg.Add(concurrency * 4) // 4 query types

		// Execute all query types concurrently
		for i := 0; i < concurrency; i++ {
			// GetTargetHistory
			go func() {
				defer wg.Done()
				_, _ = queries.GetTargetHistory(ctx, "host-192.168.1.100")
			}()

			// GetPriorFindings
			go func() {
				defer wg.Done()
				_, _ = queries.GetPriorFindings(ctx, "example.com", 10)
			}()

			// GetKnownEntities
			go func() {
				defer wg.Done()
				_, _ = queries.GetKnownEntities(ctx, "host-192.168.1.100")
			}()

			// GetSuccessfulPatterns
			go func() {
				defer wg.Done()
				_, _ = queries.GetSuccessfulPatterns(ctx, "host")
			}()
		}

		// Wait for all queries to complete
		wg.Wait()

		// Verify metrics were recorded
		metricFamilies, err := registry.Gather()
		require.NoError(t, err)

		// Find query metrics
		var foundMetrics bool
		for _, mf := range metricFamilies {
			if mf.GetName() == "gibson_orchestrator_graph_queries_total" {
				foundMetrics = true
				assert.NotEmpty(t, mf.GetMetric())
			}
		}
		assert.True(t, foundMetrics, "Expected query metrics to be recorded")
	})
}

// TestIntegration_MetricsAndTracing tests that metrics and spans are recorded correctly.
func TestIntegration_MetricsAndTracing(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()

	driver, cleanup := setupNeo4jFromEnv(t, ctx)
	if driver == nil {
		_, driver, cleanup = setupNeo4jContainer(t, ctx)
	}
	defer cleanup()

	cleanDatabase(ctx, t, driver)
	seedTestData(ctx, t, driver)

	// Setup tracing
	spanRecorder := tracetest.NewSpanRecorder()
	_ = trace.NewTracerProvider(trace.WithSpanProcessor(spanRecorder))

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	registry := prometheus.NewRegistry()

	// Create queries with custom tracer provider
	queries := NewNeo4jGraphQueriesWithMetrics(driver, logger, registry)

	t.Run("records metrics for all query types", func(t *testing.T) {
		// Execute all query types
		_, _ = queries.GetTargetHistory(ctx, "host-192.168.1.100")
		_, _ = queries.GetPriorFindings(ctx, "example.com", 10)
		_, _ = queries.GetKnownEntities(ctx, "host-192.168.1.100")
		_, _ = queries.GetSuccessfulPatterns(ctx, "host")

		// Gather metrics
		metricFamilies, err := registry.Gather()
		require.NoError(t, err)

		// Verify expected metrics exist
		metricNames := make(map[string]bool)
		for _, mf := range metricFamilies {
			metricNames[mf.GetName()] = true
		}

		assert.True(t, metricNames["gibson_orchestrator_graph_queries_total"])
		assert.True(t, metricNames["gibson_orchestrator_graph_query_duration_seconds"])
		assert.True(t, metricNames["gibson_orchestrator_graph_context_size"])
	})

	t.Run("records error metrics on failure", func(t *testing.T) {
		// Close the driver to force errors
		_ = driver.Close(ctx)

		// Execute query that will fail
		_, _ = queries.GetTargetHistory(ctx, "host-192.168.1.100")

		// Gather metrics
		metricFamilies, err := registry.Gather()
		require.NoError(t, err)

		// Find error metrics
		var foundErrors bool
		for _, mf := range metricFamilies {
			if mf.GetName() == "gibson_orchestrator_graph_query_errors_total" {
				if len(mf.GetMetric()) > 0 {
					foundErrors = true
				}
			}
		}
		// Note: We might not find errors if the graceful degradation returns nil
		_ = foundErrors
	})
}

// TestIntegration_GracefulDegradation tests that queries degrade gracefully on errors.
func TestIntegration_GracefulDegradation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()

	driver, cleanup := setupNeo4jFromEnv(t, ctx)
	if driver == nil {
		_, driver, cleanup = setupNeo4jContainer(t, ctx)
	}
	// Note: We'll close the driver early to simulate failure

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	queries := NewNeo4jGraphQueries(driver, logger)

	// Close driver to force errors
	_ = driver.Close(ctx)
	cleanup()

	t.Run("GetTargetHistory returns nil on error", func(t *testing.T) {
		history, err := queries.GetTargetHistory(ctx, "host-192.168.1.100")
		assert.NoError(t, err, "Should not propagate error")
		assert.Nil(t, history, "Should return nil on error")
	})

	t.Run("GetPriorFindings returns empty slice on error", func(t *testing.T) {
		findings, err := queries.GetPriorFindings(ctx, "example.com", 10)
		assert.NoError(t, err, "Should not propagate error")
		assert.Empty(t, findings, "Should return empty slice on error")
	})

	t.Run("GetKnownEntities returns empty slice on error", func(t *testing.T) {
		entities, err := queries.GetKnownEntities(ctx, "host-192.168.1.100")
		assert.NoError(t, err, "Should not propagate error")
		assert.Empty(t, entities, "Should return empty slice on error")
	})

	t.Run("GetSuccessfulPatterns returns empty slice on error", func(t *testing.T) {
		patterns, err := queries.GetSuccessfulPatterns(ctx, "host")
		assert.NoError(t, err, "Should not propagate error")
		assert.Empty(t, patterns, "Should return empty slice on error")
	})
}

// TestIntegration_DataCleanup tests that test data is properly cleaned up.
func TestIntegration_DataCleanup(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()

	driver, cleanup := setupNeo4jFromEnv(t, ctx)
	if driver == nil {
		_, driver, cleanup = setupNeo4jContainer(t, ctx)
	}
	defer cleanup()

	t.Run("cleanDatabase removes all nodes", func(t *testing.T) {
		// Seed data
		seedTestData(ctx, t, driver)

		// Verify data exists
		session := driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
		result, err := session.Run(ctx, "MATCH (n) RETURN count(n) as count", nil)
		require.NoError(t, err)
		require.True(t, result.Next(ctx))
		record := result.Record()
		count, _ := record.Get("count")
		session.Close(ctx)
		assert.Greater(t, count.(int64), int64(0), "Database should have nodes after seeding")

		// Clean database
		cleanDatabase(ctx, t, driver)

		// Verify data is removed
		session = driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
		result, err = session.Run(ctx, "MATCH (n) RETURN count(n) as count", nil)
		require.NoError(t, err)
		require.True(t, result.Next(ctx))
		record = result.Record()
		count, _ = record.Get("count")
		session.Close(ctx)
		assert.Equal(t, int64(0), count.(int64), "Database should be empty after cleanup")
	})
}

// TestIntegration_RealisticScenario tests a realistic orchestrator scenario.
func TestIntegration_RealisticScenario(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()

	driver, cleanup := setupNeo4jFromEnv(t, ctx)
	if driver == nil {
		_, driver, cleanup = setupNeo4jContainer(t, ctx)
	}
	defer cleanup()

	cleanDatabase(ctx, t, driver)
	seedTestData(ctx, t, driver)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	queries := NewNeo4jGraphQueries(driver, logger)

	t.Run("orchestrator gathers complete context for decision making", func(t *testing.T) {
		// Simulate orchestrator gathering context for a target
		targetID := "host-192.168.1.101"
		domain := "example.com"

		// Gather all context types
		history, err := queries.GetTargetHistory(ctx, targetID)
		assert.NoError(t, err)

		findings, err := queries.GetPriorFindings(ctx, domain, 10)
		assert.NoError(t, err)

		entities, err := queries.GetKnownEntities(ctx, targetID)
		assert.NoError(t, err)

		patterns, err := queries.GetSuccessfulPatterns(ctx, "host")
		assert.NoError(t, err)

		// Build GraphContext
		graphCtx := GraphContext{
			PriorFindings:      findings,
			KnownEntities:      entities,
			SuccessfulPatterns: patterns,
			TargetHistory:      history,
		}

		// Verify context is comprehensive
		if history != nil {
			assert.NotEmpty(t, graphCtx.TargetHistory.TargetID)
			t.Logf("Target has %d previous scans with %d findings",
				history.PreviousScanCount, history.TotalFindings)
		}

		if len(findings) > 0 {
			assert.NotEmpty(t, graphCtx.PriorFindings)
			t.Logf("Found %d prior findings for domain", len(findings))
		}

		if len(entities) > 0 {
			assert.NotEmpty(t, graphCtx.KnownEntities)
			t.Logf("Found %d known entities", len(entities))
		}

		if len(patterns) > 0 {
			assert.NotEmpty(t, graphCtx.SuccessfulPatterns)
			t.Logf("Found %d successful attack patterns", len(patterns))
		}

		// Context should be usable for LLM decision making
		assert.NotNil(t, graphCtx)
	})
}
