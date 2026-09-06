// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/engine/mission"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// TestReleaseChildReservation covers the relocation of the child-budget release
// from the (now-deleted) store UpdateStatus hook to the World-derived terminal
// block in executeMission (gibson#1358 / gibson#1112): a child mission reaching
// terminal returns its reserved budget to its parent.
func TestReleaseChildReservation(t *testing.T) {
	conn, cleanup := newMiniredisConn(t)
	defer cleanup()
	mm := &missionManager{logger: slog.New(slog.DiscardHandler)}
	ctx := context.Background()

	parent := &mission.Mission{ID: types.NewID()}
	childID := types.NewID()

	// Reserve some of the parent's budget for the child.
	cost := int64(500)
	ledger := mission.NewRedisReservationLedger(conn.Redis)
	_, err := ledger.Reserve(ctx, parent, childID, mission.ChildBudget{CostUSDCents: &cost})
	require.NoError(t, err)
	reserved, err := ledger.Reserved(ctx, parent.ID)
	require.NoError(t, err)
	require.NotNil(t, reserved.CostUSDCents, "precondition: budget reserved")
	require.Equal(t, int64(500), *reserved.CostUSDCents)

	// The child reaches terminal — release must return the budget to the parent.
	child := &mission.Mission{ID: childID, ParentMissionID: &parent.ID}
	mm.releaseChildReservation(ctx, conn, child)

	after, err := ledger.Reserved(ctx, parent.ID)
	require.NoError(t, err)
	require.Nil(t, after.CostUSDCents, "child's reservation must be released back to the parent")
}

func TestReleaseChildReservation_LedgerErrorIsLoggedNotFatal(t *testing.T) {
	conn, cleanup := newMiniredisConn(t)
	// Close the backing Redis so the ledger's HDEL fails — the release must log
	// and swallow the error, never panic or propagate.
	cleanup()
	mm := &missionManager{logger: slog.New(slog.DiscardHandler)}

	parentID := types.NewID()
	child := &mission.Mission{ID: types.NewID(), ParentMissionID: &parentID}
	mm.releaseChildReservation(context.Background(), conn, child) // must not panic
}

func TestReleaseChildReservation_NoParentIsNoop(t *testing.T) {
	conn, cleanup := newMiniredisConn(t)
	defer cleanup()
	mm := &missionManager{logger: slog.New(slog.DiscardHandler)}

	// A parentless mission reserved nothing; release must not touch Redis or panic.
	mm.releaseChildReservation(context.Background(), conn, &mission.Mission{ID: types.NewID()})
}
