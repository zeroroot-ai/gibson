// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package mission

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

func newTestReservationLedger(t *testing.T) ReservationLedger {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return NewRedisReservationLedger(rdb)
}

func missionWithCostCap(dollars, spent float64) *Mission {
	return &Mission{
		ID:          types.NewID(),
		Constraints: &missionv1.MissionConstraints{MaxCost: dollars},
		Metrics:     &MissionMetrics{TotalCost: spent},
	}
}

func TestReservationLedger_Reserve(t *testing.T) {
	ctx := context.Background()

	t.Run("unbounded parent and unbounded request grants unbounded", func(t *testing.T) {
		ledger := newTestReservationLedger(t)
		parent := &Mission{ID: types.NewID()}

		granted, err := ledger.Reserve(ctx, parent, types.NewID(), ChildBudget{})

		require.NoError(t, err)
		assert.Nil(t, granted.CostUSDCents)
		assert.Nil(t, granted.Tokens)
	})

	t.Run("capped parent grants exactly what is requested when it fits", func(t *testing.T) {
		ledger := newTestReservationLedger(t)
		parent := missionWithCostCap(10.00, 0)

		granted, err := ledger.Reserve(ctx, parent, types.NewID(), ChildBudget{CostUSDCents: costPtr(300)})

		require.NoError(t, err)
		require.NotNil(t, granted.CostUSDCents)
		assert.Equal(t, int64(300), *granted.CostUSDCents)
	})

	t.Run("capped parent clamps a request larger than what remains", func(t *testing.T) {
		ledger := newTestReservationLedger(t)
		parent := missionWithCostCap(10.00, 4.00) // $6.00 remaining = 600 cents

		granted, err := ledger.Reserve(ctx, parent, types.NewID(), ChildBudget{CostUSDCents: costPtr(10_000)})

		require.NoError(t, err)
		require.NotNil(t, granted.CostUSDCents)
		assert.Equal(t, int64(600), *granted.CostUSDCents)
	})

	t.Run("unbounded request against a capped parent grants the full remainder", func(t *testing.T) {
		ledger := newTestReservationLedger(t)
		parent := missionWithCostCap(10.00, 2.50) // $7.50 remaining = 750 cents

		granted, err := ledger.Reserve(ctx, parent, types.NewID(), ChildBudget{})

		require.NoError(t, err)
		require.NotNil(t, granted.CostUSDCents)
		assert.Equal(t, int64(750), *granted.CostUSDCents)
	})

	t.Run("a fully spent parent refuses any further reservation", func(t *testing.T) {
		ledger := newTestReservationLedger(t)
		parent := missionWithCostCap(10.00, 10.00) // 0 remaining

		_, err := ledger.Reserve(ctx, parent, types.NewID(), ChildBudget{CostUSDCents: costPtr(1)})

		assert.Error(t, err)
	})

	t.Run("an over-spent parent (over budget) also refuses, never grants a negative reservation", func(t *testing.T) {
		ledger := newTestReservationLedger(t)
		parent := missionWithCostCap(10.00, 12.00)

		_, err := ledger.Reserve(ctx, parent, types.NewID(), ChildBudget{})

		assert.Error(t, err)
	})

	t.Run("two children against the same parent split the remaining envelope without over-committing", func(t *testing.T) {
		ledger := newTestReservationLedger(t)
		parent := missionWithCostCap(10.00, 0) // $10.00 = 1000 cents available

		child1 := types.NewID()
		g1, err := ledger.Reserve(ctx, parent, child1, ChildBudget{CostUSDCents: costPtr(700)})
		require.NoError(t, err)
		require.NotNil(t, g1.CostUSDCents)
		assert.Equal(t, int64(700), *g1.CostUSDCents)

		child2 := types.NewID()
		g2, err := ledger.Reserve(ctx, parent, child2, ChildBudget{CostUSDCents: costPtr(700)})
		require.NoError(t, err)
		require.NotNil(t, g2.CostUSDCents)
		// Only 300 cents remained after child1's reservation.
		assert.Equal(t, int64(300), *g2.CostUSDCents)
	})

	t.Run("a fully consumed token cap refuses any further reservation, independent of cost", func(t *testing.T) {
		ledger := newTestReservationLedger(t)
		parent := &Mission{
			ID:          types.NewID(),
			Constraints: &missionv1.MissionConstraints{MaxTokens: 1000},
			Metrics:     &MissionMetrics{TotalTokens: 1000},
		}

		_, err := ledger.Reserve(ctx, parent, types.NewID(), ChildBudget{})

		assert.Error(t, err)
	})

	t.Run("token cap is independent of cost cap", func(t *testing.T) {
		ledger := newTestReservationLedger(t)
		parent := &Mission{
			ID:          types.NewID(),
			Constraints: &missionv1.MissionConstraints{MaxTokens: 1000},
			Metrics:     &MissionMetrics{TotalTokens: 200},
		}

		granted, err := ledger.Reserve(ctx, parent, types.NewID(), ChildBudget{})

		require.NoError(t, err)
		assert.Nil(t, granted.CostUSDCents, "no cost cap on parent -> unbounded cost grant")
		require.NotNil(t, granted.Tokens)
		assert.Equal(t, int64(800), *granted.Tokens)
	})

	t.Run("nil parent is rejected", func(t *testing.T) {
		ledger := newTestReservationLedger(t)

		_, err := ledger.Reserve(ctx, nil, types.NewID(), ChildBudget{})

		assert.Error(t, err)
	})

	t.Run("zero child ID is rejected", func(t *testing.T) {
		ledger := newTestReservationLedger(t)
		parent := &Mission{ID: types.NewID()}

		_, err := ledger.Reserve(ctx, parent, types.ID(""), ChildBudget{})

		assert.Error(t, err)
	})
}

func TestReservationLedger_Release(t *testing.T) {
	ctx := context.Background()

	t.Run("release returns a reservation's room to the parent envelope", func(t *testing.T) {
		ledger := newTestReservationLedger(t)
		parent := missionWithCostCap(10.00, 0)

		child1 := types.NewID()
		_, err := ledger.Reserve(ctx, parent, child1, ChildBudget{CostUSDCents: costPtr(1000)})
		require.NoError(t, err)

		// Parent is now fully committed; a second reservation must fail.
		_, err = ledger.Reserve(ctx, parent, types.NewID(), ChildBudget{CostUSDCents: costPtr(1)})
		require.Error(t, err)

		require.NoError(t, ledger.Release(ctx, parent.ID, child1))

		// Room is available again.
		granted, err := ledger.Reserve(ctx, parent, types.NewID(), ChildBudget{CostUSDCents: costPtr(1000)})
		require.NoError(t, err)
		require.NotNil(t, granted.CostUSDCents)
		assert.Equal(t, int64(1000), *granted.CostUSDCents)
	})

	t.Run("releasing an unknown child is a no-op, not an error", func(t *testing.T) {
		ledger := newTestReservationLedger(t)

		err := ledger.Release(ctx, types.NewID(), types.NewID())

		assert.NoError(t, err)
	})

	t.Run("releasing twice is a no-op the second time", func(t *testing.T) {
		ledger := newTestReservationLedger(t)
		parent := missionWithCostCap(10.00, 0)
		child := types.NewID()
		_, err := ledger.Reserve(ctx, parent, child, ChildBudget{CostUSDCents: costPtr(100)})
		require.NoError(t, err)

		require.NoError(t, ledger.Release(ctx, parent.ID, child))
		assert.NoError(t, ledger.Release(ctx, parent.ID, child))
	})

	t.Run("zero IDs are a no-op rather than an error", func(t *testing.T) {
		ledger := newTestReservationLedger(t)
		assert.NoError(t, ledger.Release(ctx, types.ID(""), types.ID("")))
	})
}

func TestReservationLedger_Reserved(t *testing.T) {
	ctx := context.Background()

	t.Run("sums cost across every live reservation", func(t *testing.T) {
		ledger := newTestReservationLedger(t)
		parent := missionWithCostCap(10.00, 0)

		_, err := ledger.Reserve(ctx, parent, types.NewID(), ChildBudget{CostUSDCents: costPtr(200)})
		require.NoError(t, err)
		_, err = ledger.Reserve(ctx, parent, types.NewID(), ChildBudget{CostUSDCents: costPtr(300)})
		require.NoError(t, err)

		total, err := ledger.Reserved(ctx, parent.ID)
		require.NoError(t, err)
		require.NotNil(t, total.CostUSDCents)
		assert.Equal(t, int64(500), *total.CostUSDCents)
	})

	t.Run("a parent with no reservations reports nil, not zero", func(t *testing.T) {
		ledger := newTestReservationLedger(t)

		total, err := ledger.Reserved(ctx, types.NewID())

		require.NoError(t, err)
		assert.Nil(t, total.CostUSDCents)
		assert.Nil(t, total.Tokens)
	})
}

func TestCostCentsDollarsRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		dollars float64
		cents   int64
	}{
		{"zero", 0, 0},
		{"negative treated as zero", -5, 0},
		{"whole dollar", 10, 1000},
		{"exact cents", 19.99, 1999},
		{"sub-cent rounds down", 1.005, 100},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.cents, CostCentsFromDollars(tt.dollars))
		})
	}

	t.Run("DollarsFromCostCents inverts a whole-cent value", func(t *testing.T) {
		assert.InDelta(t, 19.99, DollarsFromCostCents(1999), 1e-9)
	})
}

// TestReservationLedger_ReserveGuards covers the two input guards on Reserve:
// a nil parent and a zero child id are both refused before any Redis call.
func TestReservationLedger_ReserveGuards(t *testing.T) {
	ledger := newTestReservationLedger(t)
	ctx := context.Background()

	_, err := ledger.Reserve(ctx, nil, types.NewID(), ChildBudget{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "parent mission is required")

	_, err = ledger.Reserve(ctx, missionWithCostCap(10, 0), types.ID(""), ChildBudget{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "child mission ID is required")
}
