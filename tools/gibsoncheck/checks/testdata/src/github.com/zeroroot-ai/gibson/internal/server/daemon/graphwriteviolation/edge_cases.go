package graphwriteviolation

import (
	"context"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// noop is a plain, non-selector call target: calling it exercises the "Fun is
// not a *ast.SelectorExpr" early-return in runGraphWrite, which every other
// fixture call (always a method selector) never reaches.
func noop() {}

func callsNoop() {
	noop()
}

// fakeExecuteWriter has its own ExecuteWrite method that has nothing to do
// with the Neo4j driver. The analyzer is type-based, not name-based, so
// calling it must NOT be flagged — this exercises the isNeo4jDriverReceiver
// "not a driver type" branch.
type fakeExecuteWriter struct{}

func (fakeExecuteWriter) ExecuteWrite() error { return nil }

func callsUnrelatedExecuteWrite() error {
	var w fakeExecuteWriter
	return w.ExecuteWrite()
}

// sessionHolder gives a SelectorExpr receiver (obj.Session.ExecuteWrite): the
// diagnostic's receiver text is itself a field selector, not a bare
// identifier.
type sessionHolder struct {
	Session neo4j.SessionWithContext
}

func (h sessionHolder) writeViaField(ctx context.Context) error {
	_, err := h.Session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) { // want `h\.Session\.ExecuteWrite opens a managed write transaction`
		return tx.Run(ctx, "MERGE (m:Mission {id: $id}) RETURN m", nil)
	})
	return err
}

// getSession gives a CallExpr receiver (getSession().ExecuteWrite): the write
// call is chained directly off a function call rather than off a variable.
func getSession() neo4j.SessionWithContext { return nil }

func writeViaCall(ctx context.Context) error {
	_, err := getSession().ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) { // want `getSession\(…\)\.ExecuteWrite opens a managed write transaction`
		return tx.Run(ctx, "MERGE (m:Mission {id: $id}) RETURN m", nil)
	})
	return err
}

// sessions gives an IndexExpr receiver (sessions[0].ExecuteWrite): the write
// call is off a slice element rather than a plain variable or field.
var sessions []neo4j.SessionWithContext

func writeViaIndex(ctx context.Context) error {
	_, err := sessions[0].ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) { // want `sessions\[…\]\.ExecuteWrite opens a managed write transaction`
		return tx.Run(ctx, "MERGE (m:Mission {id: $id}) RETURN m", nil)
	})
	return err
}

// writeViaAssertion gives a receiver expression shape exprString has no named
// case for (a type assertion): it must still be flagged, falling back to the
// generic placeholder rather than panicking or silently passing through.
func writeViaAssertion(ctx context.Context, s any) error {
	_, err := s.(neo4j.SessionWithContext).ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) { // want `session\.ExecuteWrite opens a managed write transaction`
		return tx.Run(ctx, "MERGE (m:Mission {id: $id}) RETURN m", nil)
	})
	return err
}
