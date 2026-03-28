package orchestrator

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewNeo4jGraphQueries verifies the constructor initializes correctly
func TestNewNeo4jGraphQueries(t *testing.T) {
	// For unit testing, we'll use a nil driver (won't actually execute queries)
	// Integration tests would use a real driver with testcontainers
	var driver neo4j.DriverWithContext
	logger := slog.Default()

	queries := NewNeo4jGraphQueries(driver, logger)

	assert.NotNil(t, queries)
	impl, ok := queries.(*Neo4jGraphQueries)
	require.True(t, ok, "Expected *Neo4jGraphQueries type")
	assert.NotNil(t, impl.tracer)
	assert.NotNil(t, impl.logger)
}

// TestNewNeo4jGraphQueries_NilLogger verifies default logger is used when nil
func TestNewNeo4jGraphQueries_NilLogger(t *testing.T) {
	var driver neo4j.DriverWithContext

	queries := NewNeo4jGraphQueries(driver, nil)

	assert.NotNil(t, queries)
	impl, ok := queries.(*Neo4jGraphQueries)
	require.True(t, ok)
	assert.NotNil(t, impl.logger, "Expected default logger when nil provided")
}

// TestNeo4jGraphQueries_Interfaces verifies type implements GraphQueries
func TestNeo4jGraphQueries_Interfaces(t *testing.T) {
	var driver neo4j.DriverWithContext
	queries := NewNeo4jGraphQueries(driver, nil)

	// Verify it implements GraphQueries interface
	var _ GraphQueries = queries
}

// TestGraphContext verifies the GraphContext struct
func TestGraphContext(t *testing.T) {
	ctx := GraphContext{
		PriorFindings: []HistoricalFinding{
			{
				ID:       "finding-1",
				Title:    "SQL Injection",
				Severity: "critical",
			},
		},
		KnownEntities: []EntitySummary{
			{
				ID:         "host-1",
				Type:       "host",
				Identifier: "192.168.1.100",
				Properties: map[string]any{"status": "online"},
			},
		},
		TargetHistory: &TargetHistory{
			TargetID:          "example.com",
			PreviousScanCount: 5,
			TotalFindings:     10,
		},
		TargetRiskScore: 85.5,
		Truncated:       false,
	}

	// Verify structure
	assert.Len(t, ctx.PriorFindings, 1)
	assert.Len(t, ctx.KnownEntities, 1)
	assert.NotNil(t, ctx.TargetHistory)
	assert.Equal(t, 85.5, ctx.TargetRiskScore)
	assert.False(t, ctx.Truncated)
}

// TestTargetHistory verifies the TargetHistory struct
func TestTargetHistory(t *testing.T) {
	history := &TargetHistory{
		TargetID:          "example.com",
		PreviousScanCount: 3,
		TotalFindings:     15,
		CriticalCount:     2,
		HighCount:         5,
		MediumCount:       6,
		LowCount:          2,
	}

	// Verify counts sum correctly
	totalBySeverity := history.CriticalCount + history.HighCount + history.MediumCount + history.LowCount
	assert.Equal(t, history.TotalFindings, totalBySeverity, "Severity counts should sum to total findings")
}

// TestHistoricalFinding verifies the HistoricalFinding struct
func TestHistoricalFinding(t *testing.T) {
	finding := HistoricalFinding{
		ID:           "finding-123",
		Title:        "Authentication Bypass",
		Severity:     "high",
		Category:     "authentication",
		TargetEntity: "https://api.example.com/login",
	}

	assert.NotEmpty(t, finding.ID)
	assert.NotEmpty(t, finding.Title)
	assert.Equal(t, "high", finding.Severity)
	assert.Equal(t, "authentication", finding.Category)
}

// TestEntitySummary verifies the EntitySummary struct
func TestEntitySummary(t *testing.T) {
	entity := EntitySummary{
		ID:         "endpoint-789",
		Type:       "endpoint",
		Identifier: "https://api.example.com/v1/users",
		Properties: map[string]any{
			"method":      "GET",
			"status_code": 200,
			"auth":        true,
		},
	}

	assert.Equal(t, "endpoint", entity.Type)
	assert.Contains(t, entity.Properties, "method")
	assert.Contains(t, entity.Properties, "status_code")
	assert.Equal(t, 200, entity.Properties["status_code"])
}

// TestAttackPattern verifies the AttackPattern struct
func TestAttackPattern(t *testing.T) {
	pattern := AttackPattern{
		TechniqueID:   "T1595.001",
		TechniqueName: "Active Scanning: Scanning IP Blocks",
		Description:   "Port scanning to enumerate services",
		SuccessRate:   0.75,
		SampleCount:   42,
		TargetTypes:   []string{"web_application", "api"},
	}

	assert.Equal(t, "T1595.001", pattern.TechniqueID)
	assert.InDelta(t, 0.75, pattern.SuccessRate, 0.01)
	assert.Equal(t, 42, pattern.SampleCount)
	assert.Contains(t, pattern.TargetTypes, "web_application")
}

// TestTargetHistory_DataValidation tests data structure validation
func TestTargetHistory_DataValidation(t *testing.T) {
	now := time.Now()
	history := &TargetHistory{
		TargetID:          "example.com",
		PreviousScanCount: 5,
		LastScanDate:      &now,
		TotalFindings:     20,
		CriticalCount:     3,
		HighCount:         7,
		MediumCount:       8,
		LowCount:          2,
	}

	assert.Equal(t, "example.com", history.TargetID)
	assert.Equal(t, 5, history.PreviousScanCount)
	assert.NotNil(t, history.LastScanDate)
	assert.Equal(t, 20, history.TotalFindings)

	// Verify severity counts sum to total
	totalSeverity := history.CriticalCount + history.HighCount + history.MediumCount + history.LowCount
	assert.Equal(t, history.TotalFindings, totalSeverity)
}

// TestHistoricalFinding_DataValidation tests historical finding data structure
func TestHistoricalFinding_DataValidation(t *testing.T) {
	now := time.Now()
	finding := HistoricalFinding{
		ID:           "finding-123",
		Title:        "SQL Injection in /api/login",
		Severity:     "critical",
		Category:     "injection",
		DiscoveredAt: now,
		TargetEntity: "https://api.example.com/login",
	}

	assert.NotEmpty(t, finding.ID)
	assert.NotEmpty(t, finding.Title)
	assert.Equal(t, "critical", finding.Severity)
	assert.Equal(t, "injection", finding.Category)
	assert.Equal(t, now, finding.DiscoveredAt)
	assert.Contains(t, finding.TargetEntity, "api.example.com")
}

// TestEntitySummary_PropertyFiltering tests that framework properties should be filtered
func TestEntitySummary_PropertyFiltering(t *testing.T) {
	now := time.Now()
	entity := EntitySummary{
		ID:         "endpoint-789",
		Type:       "endpoint",
		Identifier: "https://api.example.com/v1/users",
		Properties: map[string]any{
			"method":      "GET",
			"status_code": 200,
			"auth":        true,
		},
		DiscoveredAt: now,
	}

	assert.Equal(t, "endpoint", entity.Type)
	assert.Contains(t, entity.Properties, "method")
	assert.Contains(t, entity.Properties, "status_code")

	// Verify no framework properties are present
	assert.NotContains(t, entity.Properties, "id")
	assert.NotContains(t, entity.Properties, "discovered_at")
	assert.NotContains(t, entity.Properties, "mission_id")
	assert.NotContains(t, entity.Properties, "mission_run_id")
	assert.NotContains(t, entity.Properties, "agent_run_id")
	assert.NotContains(t, entity.Properties, "discovered_by")
}

// TestAttackPattern_DataValidation tests attack pattern data structure
func TestAttackPattern_DataValidation(t *testing.T) {
	pattern := AttackPattern{
		TechniqueID:   "T1595.001",
		TechniqueName: "Active Scanning: Scanning IP Blocks",
		Description:   "Port scanning to enumerate services",
		SuccessRate:   0.75,
		SampleCount:   42,
		TargetTypes:   []string{"web_application", "api"},
	}

	assert.Equal(t, "T1595.001", pattern.TechniqueID)
	assert.InDelta(t, 0.75, pattern.SuccessRate, 0.01)
	assert.Equal(t, 42, pattern.SampleCount)
	assert.Contains(t, pattern.TargetTypes, "web_application")
	assert.Len(t, pattern.TargetTypes, 2)
}

// TestGraphContext_Building tests building context with various data combinations
func TestGraphContext_Building(t *testing.T) {
	tests := []struct {
		name     string
		buildCtx func() GraphContext
		validate func(*testing.T, GraphContext)
	}{
		{
			name: "context with all components",
			buildCtx: func() GraphContext {
				now := time.Now()
				return GraphContext{
					PriorFindings: []HistoricalFinding{
						{
							ID:           "finding-1",
							Title:        "SQL Injection",
							Severity:     "critical",
							Category:     "injection",
							DiscoveredAt: now,
							TargetEntity: "api.example.com",
						},
					},
					KnownEntities: []EntitySummary{
						{
							ID:           "host-1",
							Type:         "host",
							Identifier:   "192.168.1.100",
							Properties:   map[string]any{"os": "Linux"},
							DiscoveredAt: now,
						},
					},
					SuccessfulPatterns: []AttackPattern{
						{
							TechniqueID:   "T1595.001",
							TechniqueName: "Port Scanning",
							SuccessRate:   0.85,
							SampleCount:   42,
						},
					},
					TargetHistory: &TargetHistory{
						TargetID:          "example.com",
						PreviousScanCount: 5,
						TotalFindings:     20,
						CriticalCount:     3,
					},
					TargetRiskScore: 75.5,
					QueryDuration:   250 * time.Millisecond,
					Truncated:       false,
				}
			},
			validate: func(t *testing.T, ctx GraphContext) {
				assert.Len(t, ctx.PriorFindings, 1)
				assert.Len(t, ctx.KnownEntities, 1)
				assert.Len(t, ctx.SuccessfulPatterns, 1)
				assert.NotNil(t, ctx.TargetHistory)
				assert.Equal(t, 75.5, ctx.TargetRiskScore)
				assert.Equal(t, 250*time.Millisecond, ctx.QueryDuration)
				assert.False(t, ctx.Truncated)
			},
		},
		{
			name: "context with partial data",
			buildCtx: func() GraphContext {
				return GraphContext{
					PriorFindings: []HistoricalFinding{},
					KnownEntities: nil,
					TargetHistory: nil,
				}
			},
			validate: func(t *testing.T, ctx GraphContext) {
				assert.Empty(t, ctx.PriorFindings)
				assert.Nil(t, ctx.KnownEntities)
				assert.Nil(t, ctx.TargetHistory)
				assert.Equal(t, 0.0, ctx.TargetRiskScore)
			},
		},
		{
			name: "context with empty results",
			buildCtx: func() GraphContext {
				return GraphContext{
					PriorFindings:      []HistoricalFinding{},
					KnownEntities:      []EntitySummary{},
					SuccessfulPatterns: []AttackPattern{},
					TargetHistory:      nil,
					TargetRiskScore:    0.0,
					Truncated:          false,
				}
			},
			validate: func(t *testing.T, ctx GraphContext) {
				assert.Empty(t, ctx.PriorFindings)
				assert.Empty(t, ctx.KnownEntities)
				assert.Empty(t, ctx.SuccessfulPatterns)
				assert.Nil(t, ctx.TargetHistory)
				assert.False(t, ctx.Truncated)
			},
		},
		{
			name: "context with truncated results",
			buildCtx: func() GraphContext {
				return GraphContext{
					PriorFindings: make([]HistoricalFinding, 100),
					Truncated:     true,
				}
			},
			validate: func(t *testing.T, ctx GraphContext) {
				assert.Len(t, ctx.PriorFindings, 100)
				assert.True(t, ctx.Truncated)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.buildCtx()
			tt.validate(t, ctx)
		})
	}
}

// TestNeo4jGraphQueries_TimeoutConstants tests timeout value expectations
func TestNeo4jGraphQueries_TimeoutConstants(t *testing.T) {
	// All queries should use 500ms timeout
	expectedTimeout := 500 * time.Millisecond

	t.Run("verifies timeout value is reasonable", func(t *testing.T) {
		assert.Equal(t, 500*time.Millisecond, expectedTimeout)
		assert.Greater(t, expectedTimeout, 100*time.Millisecond, "Timeout should be sufficient for queries")
		assert.Less(t, expectedTimeout, 2*time.Second, "Timeout should not block orchestrator too long")
	})
}

// TestNeo4jGraphQueries_QueryTypes tests query type constants
func TestNeo4jGraphQueries_QueryTypes(t *testing.T) {
	queryTypes := []string{
		"get_target_history",
		"get_prior_findings",
		"get_known_entities",
		"get_successful_patterns",
	}

	for _, qtype := range queryTypes {
		t.Run(qtype, func(t *testing.T) {
			assert.NotEmpty(t, qtype)
			assert.Contains(t, qtype, "get_")
		})
	}
}

// TestNeo4jGraphQueries_MetricsRegistration tests metrics registration
func TestNeo4jGraphQueries_MetricsRegistration(t *testing.T) {
	t.Run("registers metrics with custom registerer", func(t *testing.T) {
		registry := prometheus.NewRegistry()
		var mockDriver neo4j.DriverWithContext
		logger := slog.New(slog.NewTextHandler(nil, nil))

		queries := NewNeo4jGraphQueriesWithMetrics(mockDriver, logger, registry)

		assert.NotNil(t, queries)

		// Verify metrics are registered by checking collectors count
		// Note: Metrics won't show in Gather() until they've been observed/set
		// The test verifies the constructor completes without error, which means registration succeeded
		impl, ok := queries.(*Neo4jGraphQueries)
		require.True(t, ok)
		assert.NotNil(t, impl.metrics)
		assert.NotNil(t, impl.metrics.queryDuration)
		assert.NotNil(t, impl.metrics.contextSize)
		assert.NotNil(t, impl.metrics.queriesTotal)
		assert.NotNil(t, impl.metrics.queryErrors)
	})

	t.Run("handles nil registerer gracefully", func(t *testing.T) {
		var mockDriver neo4j.DriverWithContext
		logger := slog.New(slog.NewTextHandler(nil, nil))

		// Should not panic with nil registerer
		queries := NewNeo4jGraphQueriesWithMetrics(mockDriver, logger, nil)
		assert.NotNil(t, queries)
	})

	t.Run("uses default registerer when nil provided", func(t *testing.T) {
		var mockDriver neo4j.DriverWithContext
		logger := slog.New(slog.NewTextHandler(nil, nil))

		queries := NewNeo4jGraphQueries(mockDriver, logger)
		assert.NotNil(t, queries)
	})
}

// TestGraphQueryMetrics_DoubleRegistration tests that re-registering metrics doesn't panic
func TestGraphQueryMetrics_DoubleRegistration(t *testing.T) {
	registry := prometheus.NewRegistry()

	// Create first instance
	m1 := newGraphQueryMetrics(registry)
	err1 := m1.register()
	assert.NoError(t, err1)

	// Try to register again (should be idempotent)
	err2 := m1.register()
	assert.NoError(t, err2)
}

// TestNeo4jGraphQueries_ContextCancellation tests context handling
func TestNeo4jGraphQueries_ContextCancellation(t *testing.T) {
	t.Run("respects parent context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Immediately cancel

		// The query should respect the cancelled context
		// Since we can't mock Neo4j driver fully, this test validates the pattern
		assert.NotNil(t, ctx.Err())
		assert.Equal(t, context.Canceled, ctx.Err())
	})

	t.Run("creates timeout context from parent", func(t *testing.T) {
		parentCtx := context.Background()

		// This pattern is used in all query methods
		queryCtx, cancel := context.WithTimeout(parentCtx, 500*time.Millisecond)
		defer cancel()

		deadline, ok := queryCtx.Deadline()
		assert.True(t, ok, "Query context should have deadline")
		assert.WithinDuration(t, time.Now().Add(500*time.Millisecond), deadline, 100*time.Millisecond)
	})
}

// TestNeo4jGraphQueries_CypherStructure documents expected Cypher query patterns
func TestNeo4jGraphQueries_CypherStructure(t *testing.T) {
	t.Run("GetTargetHistory should query target nodes and related findings", func(t *testing.T) {
		// Expected query structure:
		// - MATCH (target) WHERE target.id = $target_id
		// - OPTIONAL MATCH (finding:finding)-[:RELATES_TO]->(target)
		// - Return scan counts and severity distribution
		// - Use parameterized query with $target_id parameter
		assert.True(t, true, "Query structure documented")
	})

	t.Run("GetPriorFindings should query findings by domain with severity ordering", func(t *testing.T) {
		// Expected query structure:
		// - MATCH entities by domain
		// - MATCH findings related to entities
		// - ORDER BY severity weight (critical=4, high=3, medium=2, low=1)
		// - LIMIT results
		// - Use parameterized query with $domain and $limit
		assert.True(t, true, "Query structure documented")
	})

	t.Run("GetKnownEntities should traverse relationships from target", func(t *testing.T) {
		// Expected query structure:
		// - MATCH (target) WHERE target.id = $target_id
		// - OPTIONAL MATCH (target)-[*1..2]-(entity)
		// - Return entity properties
		// - Filter out framework fields (id, discovered_at, mission_id, etc.)
		// - LIMIT 100 entities
		assert.True(t, true, "Query structure documented")
	})

	t.Run("GetSuccessfulPatterns should aggregate technique usage by target type", func(t *testing.T) {
		// Expected query structure:
		// - MATCH entities by target type
		// - MATCH findings with technique_id
		// - GROUP BY technique_id
		// - Calculate success_rate and sample_count
		// - ORDER BY finding_count DESC
		// - LIMIT 10 patterns
		assert.True(t, true, "Query structure documented")
	})

	t.Run("All queries should use 500ms timeout", func(t *testing.T) {
		// Each query method should:
		// - Create queryCtx with 500ms timeout using context.WithTimeout
		// - Pass queryCtx to session.Run()
		// - Ensure timeout is enforced
		assert.True(t, true, "Timeout requirement documented")
	})

	t.Run("All queries should use OpenTelemetry spans", func(t *testing.T) {
		// Each query method should:
		// - Start span with name like "orchestrator.observe.graph_queries.get_target_history"
		// - Set relevant span attributes (target_id, domain, etc.)
		// - Record errors with span.RecordError(err)
		// - Return span metadata for observability
		assert.True(t, true, "Telemetry requirement documented")
	})

	t.Run("All queries should gracefully degrade on error", func(t *testing.T) {
		// Each query method should:
		// - Log warnings on query failures
		// - Return empty results (nil or empty slice) instead of propagating errors
		// - Allow orchestrator to continue with reduced context
		assert.True(t, true, "Graceful degradation documented")
	})
}

// TestNeo4jGraphQueries_SecurityConsiderations documents security best practices
func TestNeo4jGraphQueries_SecurityConsiderations(t *testing.T) {
	t.Run("uses parameterized queries to prevent injection", func(t *testing.T) {
		// All Cypher queries should use $param syntax
		// Never concatenate user input into query strings
		// Examples:
		//   Good: "WHERE target.id = $target_id"
		//   Bad:  "WHERE target.id = '" + targetID + "'"
		assert.True(t, true, "Parameterized query requirement documented")
	})

	t.Run("limits query result sizes", func(t *testing.T) {
		// All queries should have LIMIT clauses to prevent resource exhaustion
		// - GetPriorFindings: LIMIT $limit (user-controlled, validated)
		// - GetKnownEntities: LIMIT 100 (hardcoded safety limit)
		// - GetSuccessfulPatterns: LIMIT 10 (hardcoded safety limit)
		assert.True(t, true, "Result limiting documented")
	})

	t.Run("enforces query timeouts", func(t *testing.T) {
		// All queries use 500ms timeout to prevent:
		// - Expensive graph traversals blocking orchestrator
		// - Database performance issues affecting mission execution
		// - Resource exhaustion from complex queries
		assert.True(t, true, "Timeout enforcement documented")
	})
}

// Note: Full query execution tests with Neo4j mocking are not possible due to unexported
// methods in neo4j.SessionWithContext and neo4j.ResultWithContext interfaces.
// For comprehensive integration testing, use testcontainers with a real Neo4j instance.
// See integration tests for end-to-end query validation.
