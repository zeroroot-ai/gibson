// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package fit

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/brain/beliefvi"
)

func baseModel(t *testing.T) beliefvi.ModelArtifact {
	t.Helper()
	base, err := beliefvi.DefaultArtifact()
	require.NoError(t, err)
	return base
}

// With no row, each column keeps the value of the base model.
func TestFit_NoRowKeepsTheBase(t *testing.T) {
	base := baseModel(t)
	got, err := Fit(base, nil, "v1")
	require.NoError(t, err)
	assert.Equal(t, "v1", got.Version)
	for name, spec := range base.CPDs {
		for c, want := range spec.Values[1] {
			assert.InDelta(t, want, got.CPDs[name].Values[1][c], 1e-4, "%s column %d", name, c)
		}
	}
}

// Rows move a column away from the base toward what they show, and the base
// keeps a weight of two rows.
func TestFit_RowsMoveTheColumn(t *testing.T) {
	base := baseModel(t)
	rows := []Row{{"svc_ssh": true}, {"svc_ssh": true}, {"svc_ssh": true}, {"svc_ssh": true}}
	got, err := Fit(base, rows, "v1")
	require.NoError(t, err)
	want := (4 + basePriorWeight*base.CPDs["svc_ssh"].Values[1][0]) / (4 + basePriorWeight)
	assert.InDelta(t, want, got.CPDs["svc_ssh"].Values[1][0], 1e-4)
	assert.InDelta(t, 1, got.CPDs["svc_ssh"].Values[0][0]+got.CPDs["svc_ssh"].Values[1][0], 1e-9)

	// A row with reachable and exploitable true lands in the column where
	// reachable is the only true parent of exploitable.
	rows = []Row{{"reachable": true, "exploitable": true}}
	got, err = Fit(base, rows, "v1")
	require.NoError(t, err)
	col := 1 << (len(base.CPDs["exploitable"].Evidence) - 1) // reachable is the first parent
	require.Equal(t, "reachable", base.CPDs["exploitable"].Evidence[0])
	assert.Greater(t, got.CPDs["exploitable"].Values[1][col], base.CPDs["exploitable"].Values[1][col])
}

func TestFit_RefusesBadInput(t *testing.T) {
	base := baseModel(t)
	_, err := Fit(base, nil, "")
	require.Error(t, err)

	bad := baseModel(t)
	bad.CPDs = map[string]beliefvi.CPDSpec{"reachable": {Values: [][]float64{{1}}}}
	_, err = Fit(bad, nil, "v1")
	require.ErrorContains(t, err, "not binary")

	bad.CPDs = map[string]beliefvi.CPDSpec{"reachable": {Values: [][]float64{{0.5, 0.5}, {0.5, 0.5}}}}
	_, err = Fit(bad, nil, "v1")
	require.ErrorContains(t, err, "columns")

	bad = baseModel(t)
	delete(bad.CPDs, "juicy")
	_, err = Fit(bad, nil, "v1")
	require.ErrorContains(t, err, "not valid")
}

// The edge posterior is the outcome count on the uninformative prior, and the
// JSON round trip gives the same artifact.
func TestFitEdgePosteriors_RoundTrip(t *testing.T) {
	a, err := EdgePosteriors(map[string]OutcomeCount{"RESOLVES_TO": {Successes: 7, Failures: 3}}, "v1")
	require.NoError(t, err)
	assert.Equal(t, BetaPosterior{Alpha: 8, Beta: 4}, a.Posteriors["RESOLVES_TO"])

	raw, err := json.Marshal(a)
	require.NoError(t, err)
	back, err := ParseEdgePosteriorArtifact(raw)
	require.NoError(t, err)
	assert.Equal(t, a, back)
}

func TestFitEdgePosteriors_RefusesBadInput(t *testing.T) {
	_, err := EdgePosteriors(nil, "")
	require.Error(t, err)
	_, err = EdgePosteriors(map[string]OutcomeCount{"X": {Successes: -1}}, "v1")
	require.ErrorContains(t, err, "negative")

	for name, raw := range map[string]string{
		"not JSON":   `nope`,
		"no version": `{"posteriors":{}}`,
		"zero alpha": `{"version":"v1","posteriors":{"X":{"alpha":0,"beta":1}}}`,
	} {
		_, err := ParseEdgePosteriorArtifact([]byte(raw))
		assert.Error(t, err, name)
	}
}
