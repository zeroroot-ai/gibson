// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInt32Count(t *testing.T) {
	assert.Equal(t, int32(0), int32Count(-1), "a negative count must clamp to 0, never wrap")
	assert.Equal(t, int32(0), int32Count(0))
	assert.Equal(t, int32(5), int32Count(5))
	assert.Equal(t, int32(math.MaxInt32), int32Count(math.MaxInt32+1),
		"a count over math.MaxInt32 must saturate, never overflow into a negative int32 (gosec G115)")
}

func TestSortedPredicateKeys(t *testing.T) {
	assert.Nil(t, sortedPredicateKeys(nil))
	assert.Nil(t, sortedPredicateKeys(map[string]string{}))
	assert.Equal(t, []string{"a", "b", "c"}, sortedPredicateKeys(map[string]string{"c": "x", "a": "y", "b": "z"}))
}

func TestClonePredicates(t *testing.T) {
	assert.Nil(t, clonePredicates(nil))
	assert.Nil(t, clonePredicates(map[string]string{}))

	src := map[string]string{"a": "expr"}
	got := clonePredicates(src)
	assert.Equal(t, src, got)

	// Mutating the clone must never alias the source map.
	got["a"] = "TAMPERED"
	assert.Equal(t, "expr", src["a"])
}
