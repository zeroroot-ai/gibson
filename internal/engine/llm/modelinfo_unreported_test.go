// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package llm

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestModelInfo_ContextWindowAtLeast(t *testing.T) {
	cases := []struct {
		name  string
		model ModelInfo
		min   int
		want  bool
	}{
		{"no minimum", ModelInfo{ContextWindow: 10}, 0, true},
		{"reported and large enough", ModelInfo{ContextWindow: 200000}, 100000, true},
		{"reported and exactly enough", ModelInfo{ContextWindow: 100000}, 100000, true},
		{"reported and too small", ModelInfo{ContextWindow: 8192}, 100000, false},
		{"reported zero is too small", ModelInfo{}, 100000, false},
		{"unreported is unknown", ModelInfo{ContextWindowUnreported: true}, 100000, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.model.ContextWindowAtLeast(tc.min))
		})
	}
}

func TestModelInfo_MissingFeatures(t *testing.T) {
	reported := ModelInfo{Features: []string{"chat", "vision"}}
	assert.Empty(t, reported.MissingFeatures([]string{"vision"}))
	assert.Equal(t, []string{"streaming"}, reported.MissingFeatures([]string{"vision", "streaming"}))
	assert.Equal(t, []string{"vision"}, ModelInfo{}.MissingFeatures([]string{"vision"}), "an empty reported set lacks the feature")

	unreported := ModelInfo{Features: []string{"chat"}, FeaturesUnreported: true}
	assert.Empty(t, unreported.MissingFeatures([]string{"vision", "streaming", "json_mode"}))
}

type savedModelStub struct{ LLMProvider }

func (savedModelStub) DefaultModel() string { return "saved" }

type plainStub struct{ LLMProvider }

func TestSavedModel(t *testing.T) {
	assert.Equal(t, "saved", SavedModel(savedModelStub{}))
	assert.Empty(t, SavedModel(plainStub{}))
}
