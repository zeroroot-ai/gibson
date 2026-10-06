// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"testing"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/graphrag/schema"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// rowSession runs each transaction against a fake transaction. A data write
// returns one row when hasRow is set. runErr and consumeErr fail the data
// write only, so the schema DDL of the first write still succeeds.
type rowSession struct {
	neo4j.SessionWithContext
	hasRow     bool
	runErr     error
	consumeErr error
	params     []map[string]any
}

type rowTx struct {
	neo4j.ManagedTransaction
	s *rowSession
}

type rowResult struct {
	neo4j.ResultWithContext
	hasRow     bool
	consumeErr error
}

func (r rowResult) Next(context.Context) bool { return r.hasRow }

func (r rowResult) Consume(context.Context) (neo4j.ResultSummary, error) {
	return nil, r.consumeErr
}

func (t rowTx) Run(_ context.Context, cypher string, params map[string]any) (neo4j.ResultWithContext, error) {
	switch cypher {
	case upsertMissionRunCypher, upsertMissionNodeCypher, linkMissionNodesCypher:
	default:
		return rowResult{}, nil // a schema statement
	}
	if t.s.runErr != nil {
		return nil, t.s.runErr
	}
	t.s.params = append(t.s.params, params)
	return rowResult{hasRow: t.s.hasRow, consumeErr: t.s.consumeErr}, nil
}

func (s *rowSession) ExecuteWrite(_ context.Context, work neo4j.ManagedTransactionWork, _ ...func(*neo4j.TransactionConfig)) (any, error) {
	return work(rowTx{s: s})
}

func (*rowSession) Close(context.Context) error { return nil }

func missionGraphWriter(conn *datapool.Conn) *neo4jGraphWriter {
	pool := &mockPool{conn: conn}
	return newNeo4jGraphWriter(func() datapool.Pool { return pool })
}

func validMissionNode() *schema.MissionNode {
	return schema.NewAgentNode(types.NewID(), types.NewID(), "scan", "scan the fleet", "recon")
}

// Each of the three writes succeeds when the MATCH finds its endpoint.
func TestMissionGraphWrites_WriteWhenTheEndpointExists(t *testing.T) {
	sess := &rowSession{hasRow: true}
	w := missionGraphWriter(&datapool.Conn{Neo4j: sess})
	ctx := context.Background()
	node := validMissionNode()

	require.NoError(t, w.UpsertMissionRun(ctx, "acme", MissionRunProjection{ID: "run-1", MissionID: "m1", RunNumber: 1}))
	require.NoError(t, w.UpsertMissionNode(ctx, "acme", node))
	require.NoError(t, w.LinkMissionNodes(ctx, "acme", "a", "b"))

	require.Len(t, sess.params, 3)
	assert.Equal(t, "run-1", sess.params[0]["run_id"])
	assert.Equal(t, node.ID.String(), sess.params[1]["id"])
	assert.Equal(t, map[string]any{"from_id": "a", "to_id": "b"}, sess.params[2])
}

// A write that finds no endpoint returns the error that names the missing node.
func TestMissionGraphWrites_NoRowIsAnError(t *testing.T) {
	w := missionGraphWriter(&datapool.Conn{Neo4j: &rowSession{}})
	ctx := context.Background()

	err := w.UpsertMissionRun(ctx, "acme", MissionRunProjection{ID: "run-1", MissionID: "m1"})
	require.ErrorIs(t, err, errMissionNotInGraph)
	err = w.UpsertMissionNode(ctx, "acme", validMissionNode())
	require.ErrorIs(t, err, errMissionNotInGraph)
	err = w.LinkMissionNodes(ctx, "acme", "a", "b")
	require.ErrorIs(t, err, errMissionNodeNotInGraph)
}

// A failed run and a failed consume reach the caller wrapped.
func TestMissionGraphWrites_SurfaceADriverError(t *testing.T) {
	driverErr := errors.New("simulated neo4j failure")
	ctx := context.Background()

	w := missionGraphWriter(&datapool.Conn{Neo4j: &rowSession{runErr: driverErr}})
	require.ErrorIs(t, w.LinkMissionNodes(ctx, "acme", "a", "b"), driverErr)

	w = missionGraphWriter(&datapool.Conn{Neo4j: &rowSession{hasRow: true, consumeErr: driverErr}})
	require.ErrorIs(t, w.LinkMissionNodes(ctx, "acme", "a", "b"), driverErr)
}

// A tenant with no Neo4j has no graph to write into. The write is a no-op.
func TestMissionGraphWrites_NoNeo4jIsANoOp(t *testing.T) {
	w := missionGraphWriter(minimalConn())
	require.NoError(t, w.UpsertMissionRun(context.Background(), "acme", MissionRunProjection{ID: "run-1"}))
}

// The writer refuses before the pool: no pool, a bad tenant, a pool error.
func TestMissionGraphWrites_RefuseBeforeTheWrite(t *testing.T) {
	ctx := context.Background()

	noPool := newNeo4jGraphWriter(func() datapool.Pool { return nil })
	require.Error(t, noPool.LinkMissionNodes(ctx, "acme", "a", "b"))

	w := missionGraphWriter(&datapool.Conn{Neo4j: &rowSession{hasRow: true}})
	require.Error(t, w.LinkMissionNodes(ctx, "", "a", "b"))

	poolErr := errors.New("simulated pool failure")
	failing := newNeo4jGraphWriter(func() datapool.Pool { return &mockPool{err: poolErr} })
	require.ErrorIs(t, failing.LinkMissionNodes(ctx, "acme", "a", "b"), poolErr)
}

// An invalid node never reaches the driver.
func TestMissionGraphWrites_RefuseAnInvalidNode(t *testing.T) {
	sess := &rowSession{hasRow: true}
	w := missionGraphWriter(&datapool.Conn{Neo4j: sess})
	ctx := context.Background()

	require.Error(t, w.UpsertMissionNode(ctx, "acme", nil))
	bad := validMissionNode()
	bad.Name = ""
	require.Error(t, w.UpsertMissionNode(ctx, "acme", bad))
	assert.Empty(t, sess.params)
}
