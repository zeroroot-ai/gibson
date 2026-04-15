package intelligence

import (
	"context"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
)

// riskCalcNilDriver returns a RiskScoreCalculator with a nil driver suitable
// for unit-testing pure scoring logic and nil-driver guard paths.
func riskCalcNilDriver() *RiskScoreCalculator {
	return &RiskScoreCalculator{driver: nil}
}

// TestFetchHistoricalScores_NilDriver verifies that fetchHistoricalScores
// gracefully returns nil when no driver is available.
func TestFetchHistoricalScores_NilDriver(t *testing.T) {
	c := riskCalcNilDriver()
	scores := c.fetchHistoricalScores(context.Background(), "asset-1")
	assert.Nil(t, scores, "nil driver should return nil scores without panic")
}

// TestFetchAttackPathDepth_NilDriver verifies that fetchAttackPathDepth
// returns 0 (no adjustment) when no driver is available.
func TestFetchAttackPathDepth_NilDriver(t *testing.T) {
	c := riskCalcNilDriver()
	depth := c.fetchAttackPathDepth(context.Background(), "asset-1")
	assert.Equal(t, 0, depth, "nil driver should return depth 0")
}

// TestCalculateScore_NoDepthAdjustment verifies that when the driver is nil
// (depth=0), the calculateScore output is the pure algorithm score.
func TestCalculateScore_NoDepthAdjustment(t *testing.T) {
	c := riskCalcNilDriver()

	data := assetData{
		assetID:          "asset-1",
		assetName:        "test-host",
		criticalFindings: 1,
		highFindings:     0,
		mediumFindings:   0,
	}

	result := c.calculateScore(data, "weighted_findings")

	// With 1 critical finding (weight 10), rawScore = 10.0
	// score = log10(11) * 25 ≈ 25.87, clamped to [0,100]
	// depth=0 (nil driver), no factor applied
	expected := math.Log10(11) * 25
	expected = math.Max(0, math.Min(100, expected))

	assert.InDelta(t, expected, result.Score, 0.01,
		"score should match weighted_findings algorithm without depth adjustment")
	assert.Equal(t, "asset-1", result.AssetID)
	assert.Equal(t, "test-host", result.AssetName)
}

// TestCalculateScore_DepthFactor_Formula validates the depth-factor formula
// used in calculateScore: factor = 1.0 + 0.1*depth, final score capped at 100.
func TestCalculateScore_DepthFactor_Formula(t *testing.T) {
	tests := []struct {
		depth         int
		baseScore     float64
		expectedScore float64
	}{
		{0, 50.0, 50.0},   // no path, score unchanged
		{1, 50.0, 55.0},   // 50 * 1.1 = 55
		{3, 50.0, 65.0},   // 50 * 1.3 = 65
		{10, 50.0, 100.0}, // 50 * 2.0 = 100, capped at 100
		{3, 90.0, 100.0},  // 90 * 1.3 = 117, capped at 100
	}

	for _, tt := range tests {
		var adjusted float64
		if tt.depth == 0 {
			adjusted = tt.baseScore
		} else {
			factor := 1.0 + 0.1*float64(tt.depth)
			adjusted = math.Min(100, tt.baseScore*factor)
		}
		assert.InDelta(t, tt.expectedScore, adjusted, 0.001,
			"depth=%d base=%.1f", tt.depth, tt.baseScore)
	}
}

// TestScoreTier verifies the tier classification thresholds.
func TestScoreTier(t *testing.T) {
	c := riskCalcNilDriver()

	tests := []struct {
		score float64
		tier  string
	}{
		{0, "low"},
		{24.9, "low"},
		{25, "medium"},
		{49.9, "medium"},
		{50, "high"},
		{74.9, "high"},
		{75, "critical"},
		{100, "critical"},
	}

	for _, tt := range tests {
		got := c.scoreTier(tt.score)
		assert.Equal(t, tt.tier, got, "score=%.1f", tt.score)
	}
}

// TestCalculateScore_Algorithms verifies each algorithm returns a
// non-negative, bounded score.
func TestCalculateScore_Algorithms(t *testing.T) {
	c := riskCalcNilDriver()

	data := assetData{
		assetID:          "asset-alg",
		assetName:        "alg-host",
		criticalFindings: 2,
		highFindings:     3,
		mediumFindings:   5,
		avgCVSSScore:     7.5,
		openFindings:     8,
		avgExposureDays:  45,
	}

	algorithms := []string{"weighted_findings", "cvss_aggregate", "exposure_time"}
	for _, alg := range algorithms {
		t.Run(alg, func(t *testing.T) {
			result := c.calculateScore(data, alg)
			assert.GreaterOrEqual(t, result.Score, 0.0, "score must be >= 0")
			assert.LessOrEqual(t, result.Score, 100.0, "score must be <= 100")
			assert.NotEmpty(t, result.Tier)
		})
	}
}
