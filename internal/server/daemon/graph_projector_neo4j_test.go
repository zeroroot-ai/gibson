// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"testing"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
)

// failingSession stands in for a tenant's Neo4j session whose write
// transaction always fails. Embedding the nil interface and overriding only
// ExecuteWrite/Close mirrors the sessionFake pattern in
// internal/platform/component/graphrag_querier_conn_test.go: every other
// method is left to the embedded nil, so an unexpected call panics rather
// than silently passing.
type failingSession struct {
	neo4j.SessionWithContext
	err error
}

func (s failingSession) ExecuteWrite(context.Context, neo4j.ManagedTransactionWork, ...func(*neo4j.TransactionConfig)) (any, error) {
	return nil, s.err
}

func (failingSession) Close(context.Context) error { return nil }

// TestNeo4jGraphWriter_UpsertMission_NilNeo4j_NoError exercises UpsertMission
// end to end (gibson#1254/ADR-0112): the mission MERGE moved here from the
// CreateMission RPC handler, which is now the projector's job to run through
// the shared exec path like every other projection. When Neo4j is not
// configured for the tenant, exec's nil guard must make this a no-op, not an
// error — that was the CreateMission handler's behaviour before the move, and
// UpsertMission must preserve it (mockPool/minimalConn from poolmock_test.go).
func TestNeo4jGraphWriter_UpsertMission_NilNeo4j_NoError(t *testing.T) {
	pool := &mockPool{conn: minimalConn()}
	w := newNeo4jGraphWriter(func() datapool.Pool { return pool })

	err := w.UpsertMission(context.Background(), "acme", MissionProjection{
		ID:        "m1",
		Name:      "recon",
		TargetID:  "target-1",
		Status:    "running",
		CreatedBy: "recon",
	})
	if err != nil {
		t.Fatalf("UpsertMission with no Neo4j configured for the tenant: %v", err)
	}
}

// TestNeo4jGraphWriter_Exec_PoolForError proves exec surfaces a pool.For
// failure rather than silently dropping the projection.
func TestNeo4jGraphWriter_Exec_PoolForError(t *testing.T) {
	poolErr := context.DeadlineExceeded
	pool := &mockPool{err: poolErr}
	w := newNeo4jGraphWriter(func() datapool.Pool { return pool })

	err := w.UpsertMission(context.Background(), "acme", MissionProjection{ID: "m1"})
	if err == nil {
		t.Fatal("expected an error when pool.For fails")
	}
}

// TestNeo4jGraphWriter_Exec_InvalidTenant proves exec rejects a malformed
// tenant before ever touching the pool.
func TestNeo4jGraphWriter_Exec_InvalidTenant(t *testing.T) {
	pool := &mockPool{conn: minimalConn()}
	w := newNeo4jGraphWriter(func() datapool.Pool { return pool })

	err := w.UpsertMission(context.Background(), "", MissionProjection{ID: "m1"})
	if err == nil {
		t.Fatal("expected an error for an invalid tenant")
	}
}

// TestNeo4jGraphWriter_Exec_ExecuteWriteError proves exec wraps a real
// ExecuteWrite failure into a descriptive error rather than swallowing it.
func TestNeo4jGraphWriter_Exec_ExecuteWriteError(t *testing.T) {
	writeErr := errors.New("simulated neo4j write failure")
	pool := &mockPool{conn: &datapool.Conn{Neo4j: failingSession{err: writeErr}}}
	w := newNeo4jGraphWriter(func() datapool.Pool { return pool })

	err := w.UpsertMission(context.Background(), "acme", MissionProjection{ID: "m1"})
	if err == nil {
		t.Fatal("expected exec to surface the ExecuteWrite failure")
	}
	if !errors.Is(err, writeErr) {
		t.Errorf("err = %v, want it to wrap %v", err, writeErr)
	}
}

// TestNeo4jGraphWriter_UpsertTarget_NilNeo4j_NoError exercises UpsertTarget
// through the shared exec path. A tenant with no Neo4j configured must be a
// no-op, like every other projection — a Target is written on every run, so an
// error here would fail every run on such a tenant (gibson#550).
func TestNeo4jGraphWriter_UpsertTarget_NilNeo4j_NoError(t *testing.T) {
	pool := &mockPool{conn: minimalConn()}
	w := newNeo4jGraphWriter(func() datapool.Pool { return pool })

	err := w.UpsertTarget(context.Background(), "acme", TargetProjection{
		ID:        "11111111-1111-1111-1111-111111111111",
		Name:      "prod-cluster",
		Type:      "kubernetes",
		URL:       "https://10.0.0.1:6443",
		Status:    "active",
		MissionID: "m1",
	})
	if err != nil {
		t.Fatalf("UpsertTarget with no Neo4j configured for the tenant: %v", err)
	}
}

// TestNeo4jGraphWriter_UpsertTarget_SurfacesAWriteFailure: a failed Target
// write must reach the bootstrap, which fails the run on it.
func TestNeo4jGraphWriter_UpsertTarget_SurfacesAWriteFailure(t *testing.T) {
	writeErr := errors.New("simulated neo4j write failure")
	pool := &mockPool{conn: &datapool.Conn{Neo4j: failingSession{err: writeErr}}}
	w := newNeo4jGraphWriter(func() datapool.Pool { return pool })

	err := w.UpsertTarget(context.Background(), "acme", TargetProjection{ID: "t1"})
	if err == nil {
		t.Fatal("expected UpsertTarget to surface the ExecuteWrite failure")
	}
	if !errors.Is(err, writeErr) {
		t.Errorf("err = %v, want it to wrap %v", err, writeErr)
	}
}
