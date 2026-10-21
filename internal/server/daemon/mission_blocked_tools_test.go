// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/mission"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/sdk/auth"
)

// dataPlane is a pool that hands out one connection, or an error.
type dataPlane struct {
	datapool.Pool
	conn *datapool.Conn
	err  error
}

func (p dataPlane) For(context.Context, auth.TenantID) (*datapool.Conn, error) {
	return p.conn, p.err
}

// The deny list is read from the stored definition of the mission. A record with
// no definition has none, and a definition that does not parse is an error.
func TestBlockedToolsOf(t *testing.T) {
	got, err := blockedToolsOf(&mission.Mission{})
	require.NoError(t, err)
	assert.Empty(t, got)

	got, err = blockedToolsOf(&mission.Mission{MissionDefinitionJSON: `{"name":"m","constraints":{"blockedTools":["mcp:gitlab:delete_project"]}}`})
	require.NoError(t, err)
	assert.Equal(t, []string{"mcp:gitlab:delete_project"}, got)

	_, err = blockedToolsOf(&mission.Mission{MissionDefinitionJSON: `{not json`})
	require.Error(t, err)
}

// Each way that the stored deny list cannot be read is an error, so the caller
// refuses the call.
func TestStoredBlockedTools_Refusals(t *testing.T) {
	ctx := context.Background()
	const missionID = "0e4f7f5e-6f5c-4c43-9f0a-1c0b3a3f9a11"

	d := &daemonImpl{}
	_, err := d.storedBlockedTools(ctx, "acme", missionID)
	require.Error(t, err, "no pool")

	d.pool = dataPlane{err: errors.New("not provisioned")}
	_, err = d.storedBlockedTools(ctx, "BAD TENANT", missionID)
	require.Error(t, err, "a tenant that does not parse")
	_, err = d.storedBlockedTools(ctx, "acme", "not-a-mission-id")
	require.Error(t, err, "a mission id that does not parse")
	_, err = d.storedBlockedTools(ctx, "acme", missionID)
	require.Error(t, err, "a pool that fails")

	conn, cleanup := newMiniredisConn(t)
	defer cleanup()
	d.pool = dataPlane{conn: conn}
	_, err = d.storedBlockedTools(ctx, "acme", missionID)
	require.Error(t, err, "a record that cannot be read")
}
