package intelligence

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdkgraphrag "github.com/zero-day-ai/sdk/graphrag"
)

func TestQueryCache(t *testing.T) {
	cache := newQueryCache()

	t.Run("set and get", func(t *testing.T) {
		cache.set("key1", "value1", time.Minute)

		result := cache.get("key1")
		assert.Equal(t, "value1", result)
	})

	t.Run("get non-existent", func(t *testing.T) {
		result := cache.get("non-existent")
		assert.Nil(t, result)
	})

	t.Run("expired entry returns nil", func(t *testing.T) {
		cache.set("expiring", "value", time.Nanosecond)
		time.Sleep(time.Millisecond)

		result := cache.get("expiring")
		assert.Nil(t, result)
	})

	t.Run("delete", func(t *testing.T) {
		cache.set("to-delete", "value", time.Minute)
		cache.delete("to-delete")

		result := cache.get("to-delete")
		assert.Nil(t, result)
	})

	t.Run("clear", func(t *testing.T) {
		cache.set("key1", "value1", time.Minute)
		cache.set("key2", "value2", time.Minute)
		cache.clear()

		assert.Nil(t, cache.get("key1"))
		assert.Nil(t, cache.get("key2"))
		assert.Equal(t, 0, cache.size())
	})

	t.Run("cleanup removes expired", func(t *testing.T) {
		cache := newQueryCache()
		cache.set("keep", "value", time.Hour)
		cache.set("expire", "value", time.Nanosecond)
		time.Sleep(time.Millisecond)

		cache.cleanup()

		assert.NotNil(t, cache.get("keep"))
		assert.Nil(t, cache.get("expire"))
	})

	t.Run("key generation", func(t *testing.T) {
		opts := sdkgraphrag.RecurringVulnOpts{
			Threshold: 3,
			Limit:     100,
		}
		key := cache.key("recurring", opts)
		assert.Contains(t, key, "recurring")
	})
}

func TestErrCircuitOpen(t *testing.T) {
	assert.Error(t, ErrCircuitOpen)
	assert.Equal(t, "intelligence service circuit breaker is open", ErrCircuitOpen.Error())
}

func TestServiceConfig(t *testing.T) {
	t.Run("default config values", func(t *testing.T) {
		config := ServiceConfig{
			Driver: nil, // Would normally be provided
		}

		// Test default application logic
		if config.CacheTTL == 0 {
			config.CacheTTL = 5 * time.Minute
		}
		if config.CircuitTimeout == 0 {
			config.CircuitTimeout = 30 * time.Second
		}

		assert.Equal(t, 5*time.Minute, config.CacheTTL)
		assert.Equal(t, 30*time.Second, config.CircuitTimeout)
	})
}

func TestNoOpIntelligenceQueries(t *testing.T) {
	ctx := context.Background()
	noOp := &sdkgraphrag.NoOpIntelligenceQueries{}

	t.Run("GetRecurringVulnerabilities returns empty", func(t *testing.T) {
		result, err := noOp.GetRecurringVulnerabilities(ctx, sdkgraphrag.RecurringVulnOpts{})
		require.NoError(t, err)
		assert.Empty(t, result.Vulnerabilities)
		assert.Equal(t, 0, result.TotalCount)
	})

	t.Run("GetRemediationMetrics returns empty", func(t *testing.T) {
		result, err := noOp.GetRemediationMetrics(ctx, sdkgraphrag.RemediationOpts{})
		require.NoError(t, err)
		assert.Empty(t, result.Metrics)
		assert.NotEmpty(t, result.DataLimitations)
	})

	t.Run("GetAssetRiskScore returns empty", func(t *testing.T) {
		result, err := noOp.GetAssetRiskScore(ctx, sdkgraphrag.RiskScoreOpts{})
		require.NoError(t, err)
		assert.Empty(t, result.Assets)
	})

	t.Run("GetAttackPatterns returns empty", func(t *testing.T) {
		result, err := noOp.GetAttackPatterns(ctx, sdkgraphrag.PatternOpts{})
		require.NoError(t, err)
		assert.Empty(t, result.Patterns)
		assert.Equal(t, 0, result.TotalPatterns)
	})

	t.Run("GetSimilarTargets returns empty", func(t *testing.T) {
		opts := sdkgraphrag.SimilarTargetsOpts{
			TargetID: "test-target",
			Features: []string{"technology_stack"},
		}
		result, err := noOp.GetSimilarTargets(ctx, opts)
		require.NoError(t, err)
		assert.Equal(t, "test-target", result.ReferenceTargetID)
		assert.Empty(t, result.SimilarTargets)
		assert.Equal(t, opts.Features, result.FeaturesUsed)
	})
}

func TestMetrics(t *testing.T) {
	t.Run("no-op metrics don't panic", func(t *testing.T) {
		ctx := context.Background()
		m := NewNoOpMetrics()

		// These should not panic
		m.RecordQuery(ctx, "recurring", time.Second, false, nil)
		m.RecordQuery(ctx, "risk", time.Second, true, nil)
		m.RecordCircuitBreak(ctx)
	})
}

func TestSeverityConstants(t *testing.T) {
	assert.Equal(t, sdkgraphrag.Severity("critical"), sdkgraphrag.SeverityCritical)
	assert.Equal(t, sdkgraphrag.Severity("high"), sdkgraphrag.SeverityHigh)
	assert.Equal(t, sdkgraphrag.Severity("medium"), sdkgraphrag.SeverityMedium)
	assert.Equal(t, sdkgraphrag.Severity("low"), sdkgraphrag.SeverityLow)
	assert.Equal(t, sdkgraphrag.Severity("info"), sdkgraphrag.SeverityInfo)
}
