package resolver

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/component"
)

type fixedPrometheusQuerier struct {
	val float64
	err error
}

func (f *fixedPrometheusQuerier) QueryInstant(_ context.Context, _ string) (float64, error) {
	return f.val, f.err
}

func TestScoreLoad_WithPrometheus_LowLoad(t *testing.T) {
	scorer := NewComponentScorer(nil, nil).(*DefaultComponentScorer)
	scorer.WithPrometheusQuerier(&fixedPrometheusQuerier{val: 10.0})

	comp := &component.Component{Status: component.ComponentStatusRunning}
	score := scorer.scoreLoad(context.Background(), comp)

	// depth=10 → 1 - 10/100 = 0.9
	assert.InDelta(t, 0.9, score, 0.001)
}

func TestScoreLoad_WithPrometheus_HighLoad(t *testing.T) {
	scorer := NewComponentScorer(nil, nil).(*DefaultComponentScorer)
	scorer.WithPrometheusQuerier(&fixedPrometheusQuerier{val: 100.0})

	comp := &component.Component{Status: component.ComponentStatusRunning}
	score := scorer.scoreLoad(context.Background(), comp)

	// depth=100 → 1 - 100/100 = 0.0
	assert.InDelta(t, 0.0, score, 0.001)
}

func TestScoreLoad_WithPrometheus_OverMax_Clipped(t *testing.T) {
	scorer := NewComponentScorer(nil, nil).(*DefaultComponentScorer)
	scorer.WithPrometheusQuerier(&fixedPrometheusQuerier{val: 200.0})

	comp := &component.Component{Status: component.ComponentStatusRunning}
	score := scorer.scoreLoad(context.Background(), comp)

	// depth=200 → 1 - 200/100 = -1 → clipped to 0
	assert.InDelta(t, 0.0, score, 0.001)
}

func TestScoreLoad_WithPrometheus_Error_ReturnsNeutral(t *testing.T) {
	scorer := NewComponentScorer(nil, nil).(*DefaultComponentScorer)
	scorer.WithPrometheusQuerier(&fixedPrometheusQuerier{err: errors.New("prom down")})

	comp := &component.Component{Status: component.ComponentStatusRunning}
	score := scorer.scoreLoad(context.Background(), comp)

	assert.InDelta(t, 0.5, score, 0.001)
}

func TestScoreLoad_WithoutPrometheus_Running(t *testing.T) {
	scorer := NewComponentScorer(nil, nil).(*DefaultComponentScorer)
	comp := &component.Component{Status: component.ComponentStatusRunning}
	score := scorer.scoreLoad(context.Background(), comp)
	assert.InDelta(t, 0.5, score, 0.001)
}

func TestScoreLoad_WithoutPrometheus_Stopped(t *testing.T) {
	scorer := NewComponentScorer(nil, nil).(*DefaultComponentScorer)
	comp := &component.Component{Status: component.ComponentStatusStopped}
	score := scorer.scoreLoad(context.Background(), comp)
	assert.InDelta(t, 1.0, score, 0.001)
}

func TestScore_Full_WithPrometheus(t *testing.T) {
	pq := &fixedPrometheusQuerier{val: 0}
	scorer := NewComponentScorer(nil, nil).(*DefaultComponentScorer)
	scorer.WithPrometheusQuerier(pq)

	comp := &component.Component{
		Status:  component.ComponentStatusRunning,
		Version: "1.0.0",
	}
	s, err := scorer.Score(context.Background(), comp, nil, "")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, s, 0.0)
	assert.LessOrEqual(t, s, 1.0)
}
