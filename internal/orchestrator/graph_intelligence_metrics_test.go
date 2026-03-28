package orchestrator

import (
	"testing"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGraphQueryMetrics verifies that metrics are properly initialized and registered
func TestGraphQueryMetrics(t *testing.T) {
	t.Run("creates metrics with default registerer", func(t *testing.T) {
		metrics := newGraphQueryMetrics(nil)
		require.NotNil(t, metrics)
		assert.NotNil(t, metrics.queryDuration)
		assert.NotNil(t, metrics.contextSize)
		assert.NotNil(t, metrics.queriesTotal)
		assert.NotNil(t, metrics.queryErrors)
		assert.NotNil(t, metrics.registerer)
		assert.False(t, metrics.registered)
	})

	t.Run("creates metrics with custom registerer", func(t *testing.T) {
		registry := prometheus.NewRegistry()
		metrics := newGraphQueryMetrics(registry)
		require.NotNil(t, metrics)
		assert.Equal(t, registry, metrics.registerer)
	})

	t.Run("registers metrics successfully", func(t *testing.T) {
		registry := prometheus.NewRegistry()
		metrics := newGraphQueryMetrics(registry)

		err := metrics.register()
		assert.NoError(t, err)
		assert.True(t, metrics.registered)
	})

	t.Run("register is idempotent", func(t *testing.T) {
		registry := prometheus.NewRegistry()
		metrics := newGraphQueryMetrics(registry)

		// First registration
		err := metrics.register()
		assert.NoError(t, err)
		assert.True(t, metrics.registered)

		// Second registration should be no-op
		err = metrics.register()
		assert.NoError(t, err)
		assert.True(t, metrics.registered)
	})
}

// TestNeo4jGraphQueriesWithMetrics verifies that the constructor with metrics works correctly
func TestNeo4jGraphQueriesWithMetrics(t *testing.T) {
	t.Run("creates instance with default registerer", func(t *testing.T) {
		var driver neo4j.DriverWithContext
		queries := NewNeo4jGraphQueries(driver, nil)

		require.NotNil(t, queries)
		impl, ok := queries.(*Neo4jGraphQueries)
		require.True(t, ok)
		assert.NotNil(t, impl.metrics)
		assert.NotNil(t, impl.tracer)
		assert.NotNil(t, impl.logger)
	})

	t.Run("creates instance with custom registerer", func(t *testing.T) {
		var driver neo4j.DriverWithContext
		registry := prometheus.NewRegistry()
		queries := NewNeo4jGraphQueriesWithMetrics(driver, nil, registry)

		require.NotNil(t, queries)
		impl, ok := queries.(*Neo4jGraphQueries)
		require.True(t, ok)
		assert.NotNil(t, impl.metrics)
		assert.Equal(t, registry, impl.metrics.registerer)
	})

	t.Run("metrics are registered on creation", func(t *testing.T) {
		var driver neo4j.DriverWithContext
		registry := prometheus.NewRegistry()
		queries := NewNeo4jGraphQueriesWithMetrics(driver, nil, registry)

		impl, ok := queries.(*Neo4jGraphQueries)
		require.True(t, ok)
		assert.True(t, impl.metrics.registered)

		// Record values to make metrics visible (Prometheus only shows metrics with values)
		impl.metrics.queryDuration.WithLabelValues("test").Observe(0.1)
		impl.metrics.contextSize.WithLabelValues("test").Set(100)
		impl.metrics.queriesTotal.WithLabelValues("test", "success").Inc()
		impl.metrics.queryErrors.WithLabelValues("test", "test_error").Inc()

		// Verify metrics are actually in the registry
		metricFamilies, err := registry.Gather()
		assert.NoError(t, err)
		assert.NotEmpty(t, metricFamilies, "Expected metrics to be registered")

		// Check for our specific metrics
		metricNames := make(map[string]bool)
		for _, mf := range metricFamilies {
			metricNames[mf.GetName()] = true
		}

		assert.True(t, metricNames["gibson_orchestrator_graph_query_duration_seconds"],
			"Expected gibson_orchestrator_graph_query_duration_seconds to be registered")
		assert.True(t, metricNames["gibson_orchestrator_graph_context_size"],
			"Expected gibson_orchestrator_graph_context_size to be registered")
		assert.True(t, metricNames["gibson_orchestrator_graph_queries_total"],
			"Expected gibson_orchestrator_graph_queries_total to be registered")
		assert.True(t, metricNames["gibson_orchestrator_graph_query_errors_total"],
			"Expected gibson_orchestrator_graph_query_errors_total to be registered")
	})
}

// TestMetricLabels verifies that metrics have the correct labels
func TestMetricLabels(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := newGraphQueryMetrics(registry)
	err := metrics.register()
	require.NoError(t, err)

	t.Run("queryDuration has query_type label", func(t *testing.T) {
		// Record a metric to create the time series
		metrics.queryDuration.WithLabelValues("get_target_history").Observe(0.1)

		metricFamilies, err := registry.Gather()
		assert.NoError(t, err)

		for _, mf := range metricFamilies {
			if mf.GetName() == "gibson_orchestrator_graph_query_duration_seconds" {
				assert.NotEmpty(t, mf.GetMetric())
				metric := mf.GetMetric()[0]
				assert.NotEmpty(t, metric.GetLabel())
				assert.Equal(t, "query_type", metric.GetLabel()[0].GetName())
				assert.Equal(t, "get_target_history", metric.GetLabel()[0].GetValue())
				return
			}
		}
		t.Error("Expected to find gibson_orchestrator_graph_query_duration_seconds metric")
	})

	t.Run("contextSize has context_type label", func(t *testing.T) {
		metrics.contextSize.WithLabelValues("prior_findings").Set(5)

		metricFamilies, err := registry.Gather()
		assert.NoError(t, err)

		for _, mf := range metricFamilies {
			if mf.GetName() == "gibson_orchestrator_graph_context_size" {
				assert.NotEmpty(t, mf.GetMetric())
				metric := mf.GetMetric()[0]
				assert.NotEmpty(t, metric.GetLabel())
				assert.Equal(t, "context_type", metric.GetLabel()[0].GetName())
				assert.Equal(t, "prior_findings", metric.GetLabel()[0].GetValue())
				return
			}
		}
		t.Error("Expected to find gibson_orchestrator_graph_context_size metric")
	})

	t.Run("queriesTotal has query_type and status labels", func(t *testing.T) {
		metrics.queriesTotal.WithLabelValues("get_known_entities", "success").Inc()

		metricFamilies, err := registry.Gather()
		assert.NoError(t, err)

		for _, mf := range metricFamilies {
			if mf.GetName() == "gibson_orchestrator_graph_queries_total" {
				assert.NotEmpty(t, mf.GetMetric())
				metric := mf.GetMetric()[0]
				assert.Len(t, metric.GetLabel(), 2)
				labels := make(map[string]string)
				for _, label := range metric.GetLabel() {
					labels[label.GetName()] = label.GetValue()
				}
				assert.Equal(t, "get_known_entities", labels["query_type"])
				assert.Equal(t, "success", labels["status"])
				return
			}
		}
		t.Error("Expected to find gibson_orchestrator_graph_queries_total metric")
	})
}
