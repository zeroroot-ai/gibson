// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package graph

import (
	"context"
	"errors"
	"testing"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// readOnlySession records each read transaction and fails it with err. It
// embeds the nil interface, so a call of ExecuteWrite or Run panics: a query
// that opens a write transaction fails the test.
type readOnlySession struct {
	neo4j.SessionWithContext
	err   error
	reads int
}

func (s *readOnlySession) ExecuteRead(context.Context, neo4j.ManagedTransactionWork, ...func(*neo4j.TransactionConfig)) (any, error) {
	s.reads++
	return nil, s.err
}

func (*readOnlySession) Close(context.Context) error { return nil }

// readOnlyDriver hands out readOnlySession and records the access mode that
// the client asked for.
type readOnlyDriver struct {
	neo4j.DriverWithContext
	session *readOnlySession
	modes   []neo4j.AccessMode
}

func (d *readOnlyDriver) NewSession(_ context.Context, cfg neo4j.SessionConfig) neo4j.SessionWithContext {
	d.modes = append(d.modes, cfg.AccessMode)
	return d.session
}

// A query of the driver client opens a read-mode session and a read
// transaction only, also for a write statement (gibson#673, ADR-0112).
func TestNeo4jClientQuery_RunsInAReadTransaction(t *testing.T) {
	readErr := errors.New("simulated read failure")
	drv := &readOnlyDriver{session: &readOnlySession{err: readErr}}
	c := &Neo4jClient{driver: drv}

	_, err := c.Query(context.Background(), "MERGE (n:Host {id: $id})", map[string]any{"id": "h1"})
	require.ErrorIs(t, err, readErr)
	assert.Equal(t, []neo4j.AccessMode{neo4j.AccessModeRead}, drv.modes)
	assert.Equal(t, 1, drv.session.reads)
}

// A query of the session client runs in a read transaction only.
func TestSessionGraphClientQuery_RunsInAReadTransaction(t *testing.T) {
	readErr := errors.New("simulated read failure")
	sess := &readOnlySession{err: readErr}
	c := NewSessionGraphClient(sess)

	_, err := c.Query(context.Background(), "MERGE (n:Host {id: $id})", map[string]any{"id": "h1"})
	require.ErrorIs(t, err, readErr)
	assert.Equal(t, 1, sess.reads)
}
