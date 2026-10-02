// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package providerconfig

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	sdksecrets "github.com/zeroroot-ai/gibson/internal/infra/secrets"
	"github.com/zeroroot-ai/sdk/auth"
)

// noSecrets is a secrets service the unreachable store never reaches: the
// DAO read fails first.
type noSecrets struct{}

func (noSecrets) Put(context.Context, string, []byte) error       { return nil }
func (noSecrets) Resolve(context.Context, string) ([]byte, error) { return nil, sdksecrets.ErrNotFound }
func (noSecrets) Delete(context.Context, string) error            { return nil }
func (noSecrets) List(context.Context, sdksecrets.Filter) ([]string, error) {
	return nil, nil
}

// unreachablePool is a datapool.Pool whose Conn carries a pgx pool that
// connects lazily to a port nothing listens on, so the first query fails.
// Embedding the interface keeps the fake to the one method under test.
type unreachablePool struct {
	datapool.Pool
	pg *pgxpool.Pool
}

func (p *unreachablePool) For(context.Context, auth.TenantID) (*datapool.Conn, error) {
	return &datapool.Conn{Postgres: p.pg}, nil
}

func newUnreachableStore(t *testing.T) ProviderConfigStore {
	t.Helper()
	pg, err := pgxpool.New(context.Background(), "postgres://nobody@127.0.0.1:1/nothing?connect_timeout=1")
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pg.Close)
	return NewBrokerBackedStore(&unreachablePool{pg: pg}, noSecrets{})
}

// A failing DAO read surfaces from Get and Resolve as the DAO's error. The
// lazy migration that used to run on ErrNotFound is gone (gibson#505), so the
// first read error is the result.
func TestBrokerStore_GetAndResolve_SurfaceTheDAOError(t *testing.T) {
	store := newUnreachableStore(t)
	if _, err := store.Get(context.Background(), "tenant-a", "openai"); err == nil {
		t.Fatal("Get against an unreachable Postgres returned no error")
	}
	if _, err := store.Resolve(context.Background(), "tenant-a", "openai"); err == nil {
		t.Fatal("Resolve against an unreachable Postgres returned no error")
	}
}
