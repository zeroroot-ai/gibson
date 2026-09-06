// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package mission

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

func TestMissionTargetSet(t *testing.T) {
	t.Run("only TargetID set returns one-element set (backward compat)", func(t *testing.T) {
		target := types.NewID()
		m := &Mission{TargetID: target}

		got := m.TargetSet()

		assert.Equal(t, []types.ID{target}, got)
	})

	t.Run("zero TargetID and no additional targets returns empty set", func(t *testing.T) {
		m := &Mission{}

		got := m.TargetSet()

		assert.Empty(t, got)
	})

	t.Run("TargetID plus AdditionalTargetIDs returns the union, TargetID first", func(t *testing.T) {
		primary := types.NewID()
		extra1 := types.NewID()
		extra2 := types.NewID()
		m := &Mission{
			TargetID:            primary,
			AdditionalTargetIDs: []types.ID{extra1, extra2},
		}

		got := m.TargetSet()

		assert.Equal(t, []types.ID{primary, extra1, extra2}, got)
	})

	t.Run("duplicates across TargetID and AdditionalTargetIDs are deduplicated", func(t *testing.T) {
		primary := types.NewID()
		extra := types.NewID()
		m := &Mission{
			TargetID:            primary,
			AdditionalTargetIDs: []types.ID{primary, extra, extra},
		}

		got := m.TargetSet()

		assert.Equal(t, []types.ID{primary, extra}, got)
	})

	t.Run("zero TargetID with only AdditionalTargetIDs still returns the additional set", func(t *testing.T) {
		extra := types.NewID()
		m := &Mission{AdditionalTargetIDs: []types.ID{extra}}

		got := m.TargetSet()

		assert.Equal(t, []types.ID{extra}, got)
	})

	t.Run("nil Mission returns nil, not a panic", func(t *testing.T) {
		var m *Mission

		assert.Nil(t, m.TargetSet())
	})
}

func TestTargetSetSubset(t *testing.T) {
	a := types.NewID()
	b := types.NewID()
	c := types.NewID()

	tests := []struct {
		name   string
		child  []types.ID
		parent []types.ID
		want   bool
	}{
		{
			name:   "empty child is a subset of a non-empty parent",
			child:  nil,
			parent: []types.ID{a},
			want:   true,
		},
		{
			name:   "empty child is a subset of an empty parent",
			child:  nil,
			parent: nil,
			want:   true,
		},
		{
			name:   "non-empty child against empty parent is never a subset",
			child:  []types.ID{a},
			parent: nil,
			want:   false,
		},
		{
			name:   "single-element child matching parent's only target",
			child:  []types.ID{a},
			parent: []types.ID{a},
			want:   true,
		},
		{
			name:   "child fully contained in a larger parent set",
			child:  []types.ID{a, b},
			parent: []types.ID{a, b, c},
			want:   true,
		},
		{
			name:   "child with one target outside the parent set is rejected",
			child:  []types.ID{a, c},
			parent: []types.ID{a, b},
			want:   false,
		},
		{
			name:   "duplicate IDs in child do not change the result",
			child:  []types.ID{a, a, b},
			parent: []types.ID{a, b},
			want:   true,
		},
		{
			name:   "duplicate IDs in parent do not change the result",
			child:  []types.ID{a},
			parent: []types.ID{a, a},
			want:   true,
		},
		{
			name:   "order does not matter on either side",
			child:  []types.ID{c, a},
			parent: []types.ID{a, b, c},
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TargetSetSubset(tt.child, tt.parent)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestTargetSetSubsetWithMissionTargetSet exercises the exact call shape
// gibson#1358 PR4's origination handler uses: comparing a candidate child
// target set against an already-loaded parent Mission's TargetSet().
func TestTargetSetSubsetWithMissionTargetSet(t *testing.T) {
	allowed := types.NewID()
	other := types.NewID()
	parent := &Mission{TargetID: allowed}

	t.Run("child naming the parent's single target is in scope", func(t *testing.T) {
		assert.True(t, TargetSetSubset([]types.ID{allowed}, parent.TargetSet()))
	})

	t.Run("child naming a target outside the parent's scope is rejected", func(t *testing.T) {
		assert.False(t, TargetSetSubset([]types.ID{other}, parent.TargetSet()))
	})
}
