// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package celenv

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeContent(t *testing.T) {
	t.Run("nil content normalizes to nil", func(t *testing.T) {
		assert.Nil(t, normalizeContent(nil))
	})

	t.Run("content that will not JSON-marshal normalizes to nil", func(t *testing.T) {
		assert.Nil(t, normalizeContent(make(chan int)))
	})

	t.Run("a JSON-able struct round-trips into JSON's own shapes", func(t *testing.T) {
		got := normalizeContent(struct {
			A int    `json:"a"`
			B string `json:"b"`
		}{A: 1, B: "x"})

		m, ok := got.(map[string]any)
		if assert.True(t, ok, "expected a map[string]any, got %T", got) {
			assert.InDelta(t, float64(1), m["a"], 0.0001)
			assert.Equal(t, "x", m["b"])
		}
	})
}
