// Package neo4j is a stub of the Neo4j Go driver for analysistest fixtures.
// It carries only the surface the graphwrite analyzer reasons about: a session
// with read and write transaction entry points.
package neo4j

import "context"

// ManagedTransaction is a stub of the driver's managed transaction handle.
type ManagedTransaction interface {
	Run(ctx context.Context, cypher string, params map[string]any) (any, error)
}

// ExplicitTransaction is a stub of the driver's explicit transaction handle.
type ExplicitTransaction interface {
	Commit(ctx context.Context) error
}

// SessionWithContext is a stub of the driver's session type.
type SessionWithContext interface {
	ExecuteRead(ctx context.Context, fn func(ManagedTransaction) (any, error)) (any, error)
	ExecuteWrite(ctx context.Context, fn func(ManagedTransaction) (any, error)) (any, error)
	BeginTransaction(ctx context.Context) (ExplicitTransaction, error)
}
