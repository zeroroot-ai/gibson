package finding

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/agent"
)

// makeFinding builds a minimal agent.Finding for testing.
func makeFinding(title, description string) agent.Finding {
	f := agent.NewFinding(title, description, agent.SeverityMedium)
	return f
}

func TestCompositeClassifier_Stats_InitialZero(t *testing.T) {
	heuristic := NewHeuristicClassifier()
	// LLMFindingClassifier requires a caller; we use nil and won't trigger LLM path.
	cc := NewCompositeClassifier(heuristic, nil, WithHeuristicThreshold(0.0))

	stats := cc.Stats()
	assert.Equal(t, 0, stats.TotalClassifications)
	assert.Equal(t, 0, stats.HeuristicOnly)
	assert.Equal(t, 0, stats.LLMFallback)
	assert.Equal(t, 0.0, stats.HeuristicRate)
}

func TestCompositeClassifier_Stats_HeuristicPath(t *testing.T) {
	// A threshold of 0.0 means heuristic is always confident enough.
	heuristic := NewHeuristicClassifier()
	cc := NewCompositeClassifier(heuristic, nil, WithHeuristicThreshold(0.0))

	ctx := context.Background()
	findings := []agent.Finding{
		makeFinding("SQL injection in login", "classic sqli"),
		makeFinding("SQL injection in search", "another sqli"),
		makeFinding("XSS reflected attack", "reflected xss"),
	}

	for _, f := range findings {
		_, err := cc.Classify(ctx, f)
		require.NoError(t, err)
	}

	stats := cc.Stats()
	assert.Equal(t, 3, stats.TotalClassifications)
	assert.Equal(t, 3, stats.HeuristicOnly)
	assert.Equal(t, 0, stats.LLMFallback)
	assert.InDelta(t, 1.0, stats.HeuristicRate, 0.001)
}

func TestCompositeClassifier_Stats_MetricsHook(t *testing.T) {
	heuristic := NewHeuristicClassifier()
	cc := NewCompositeClassifier(heuristic, nil, WithHeuristicThreshold(0.0))

	var recorded []struct{ category, path string }
	cc.WithClassificationRecorder(func(_ context.Context, category, path string) {
		recorded = append(recorded, struct{ category, path string }{category, path})
	})

	ctx := context.Background()
	_, err := cc.Classify(ctx, makeFinding("SQL injection in login", "sqli"))
	require.NoError(t, err)

	require.Len(t, recorded, 1)
	assert.Equal(t, "heuristic", recorded[0].path)
}

func TestCompositeClassifier_Stats_HeuristicRate_Correct(t *testing.T) {
	heuristic := NewHeuristicClassifier()
	cc := NewCompositeClassifier(heuristic, nil, WithHeuristicThreshold(0.0))

	ctx := context.Background()
	_, _ = cc.Classify(ctx, makeFinding("SQL injection", "sqli test"))
	_, _ = cc.Classify(ctx, makeFinding("SQL injection", "sqli test 2"))

	stats := cc.Stats()
	assert.Equal(t, 2, stats.TotalClassifications)
	assert.InDelta(t, 1.0, stats.HeuristicRate, 0.001)
}
