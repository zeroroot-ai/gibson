// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	dbpostgres "github.com/zeroroot-ai/gibson/internal/infra/database/postgres"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/sdk/auth"
)

// poolSessionContextStore implements harness.SessionContextStore over the
// per-tenant dataplane (gibson#1184): blobs live in each tenant's dedicated
// Postgres database, envelope-encrypted under that tenant's KEK
// (datapool.Conn.SessionContext), so tenant isolation comes from which
// database the Conn is bound to — the same seam the component finding and
// graphrag queriers use — not from a query predicate.
//
// The pool is resolved lazily per call: the daemon wires this store before
// the data-plane pool finishes initializing, and a nil pool (or an
// unprovisioned tenant) is a per-call error, not a construction-time one.
type poolSessionContextStore struct {
	pool   func() datapool.Pool
	ops    func(*datapool.Conn) sessionContextBlobOps
	logger *slog.Logger
}

// sessionContextBlobOps is the slice of datapool's SessionContextOps this
// store drives; a seam so the acquire/translate paths are unit-testable
// without a live tenant database.
type sessionContextBlobOps interface {
	Put(ctx context.Context, sessionID string, data []byte, ifMatch string) (string, error)
	Get(ctx context.Context, sessionID string) ([]byte, string, error)
	Delete(ctx context.Context, sessionID string) error
}

// newPoolSessionContextStore constructs the store. pool is invoked on every
// call so it may return nil until the data-plane pool is up.
func newPoolSessionContextStore(pool func() datapool.Pool, logger *slog.Logger) *poolSessionContextStore {
	if logger == nil {
		logger = slog.Default()
	}
	return &poolSessionContextStore{
		pool:   pool,
		ops:    func(c *datapool.Conn) sessionContextBlobOps { return c.SessionContext() },
		logger: logger,
	}
}

// conn acquires the tenant-bound connection bundle. Callers must Release it.
func (s *poolSessionContextStore) conn(ctx context.Context, tenant string) (*datapool.Conn, error) {
	p := s.pool()
	if p == nil {
		return nil, fmt.Errorf("session context store: data-plane pool is not initialized")
	}
	tid, err := auth.NewTenantID(tenant)
	if err != nil {
		return nil, fmt.Errorf("session context store: invalid tenant %q: %w", tenant, err)
	}
	conn, err := p.For(ctx, tid)
	if err != nil {
		return nil, fmt.Errorf("session context store: acquire tenant data plane: %w", err)
	}
	return conn, nil
}

// translateSessionContextErr maps the storage layer's sentinel errors onto
// the harness seam's sentinels so the handler can classify conflicts and
// size-cap refusals without importing the database layer.
func translateSessionContextErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, dbpostgres.ErrSessionContextConflict):
		return fmt.Errorf("%w: %w", harness.ErrSessionContextConflict, err)
	case errors.Is(err, dbpostgres.ErrSessionContextTooLarge):
		return fmt.Errorf("%w: %w", harness.ErrSessionContextTooLarge, err)
	default:
		return err
	}
}

func (s *poolSessionContextStore) Put(ctx context.Context, tenant, sessionID string, data []byte, ifMatch string) (string, error) {
	conn, err := s.conn(ctx, tenant)
	if err != nil {
		return "", err
	}
	defer conn.Release()
	etag, err := s.ops(conn).Put(ctx, sessionID, data, ifMatch)
	return etag, translateSessionContextErr(err)
}

func (s *poolSessionContextStore) Get(ctx context.Context, tenant, sessionID string) ([]byte, string, error) {
	conn, err := s.conn(ctx, tenant)
	if err != nil {
		return nil, "", err
	}
	defer conn.Release()
	data, etag, err := s.ops(conn).Get(ctx, sessionID)
	return data, etag, translateSessionContextErr(err)
}

func (s *poolSessionContextStore) Delete(ctx context.Context, tenant, sessionID string) error {
	conn, err := s.conn(ctx, tenant)
	if err != nil {
		return err
	}
	defer conn.Release()
	return translateSessionContextErr(s.ops(conn).Delete(ctx, sessionID))
}
