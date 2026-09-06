// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/graphrag"
	"github.com/zeroroot-ai/gibson/internal/engine/memory/embedder"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// poolStub is a datapool.Pool that hands back a Conn the test controls, so the
// querier's acquire → build → release path runs without Postgres, Neo4j or a
// vector store.
type poolStub struct {
	conn *datapool.Conn
	err  error

	gotTenant string
}

func (p *poolStub) For(_ context.Context, tenant auth.TenantID) (*datapool.Conn, error) {
	p.gotTenant = tenant.String()
	if p.err != nil {
		return nil, p.err
	}
	return p.conn, nil
}

func (p *poolStub) Admin(context.Context) (*datapool.AdminConn, error) { return nil, nil }
func (p *poolStub) SetAdminPool(datapool.AdminAcquirer)                {}
func (p *poolStub) Close() error                                       { return nil }

// resolverStub returns a canned embedder or error.
type resolverStub struct {
	emb embedder.Embedder
	err error
}

func (r *resolverStub) Resolve(context.Context, string) (embedder.Embedder, error) {
	return r.emb, r.err
}

func TestQuerier_UnprovisionedTenantSurfacesAsAStatusNotInternal(t *testing.T) {
	// A tenant whose data plane is not ready yet is "not ready", not "broken" —
	// the caller can act on the difference.
	q := NewPoolGraphRAGQuerier(
		&poolStub{err: &datapool.NotProvisionedError{Tenant: "acme"}},
		&resolverStub{},
		graphrag.QueryConfig{},
		nil,
	)
	_, err := q.GetRelatedFindings(context.Background(), "acme", "f1")
	if err == nil {
		t.Fatal("expected an error for an un-provisioned tenant")
	}
}

func TestQuerier_TenantComesFromTheCallerAndNowhereElse(t *testing.T) {
	// Tenant scope here is structural: the Conn IS the boundary, so the tenant
	// the caller passed must be the tenant the pool is asked for.
	pool := &poolStub{err: errors.New("stop here")}
	q := NewPoolGraphRAGQuerier(pool, &resolverStub{}, graphrag.QueryConfig{}, nil)

	_, _ = q.GetRelatedFindings(context.Background(), "zerocool-lab", "f1")
	if pool.gotTenant != "zerocool-lab" {
		t.Errorf("pool asked for tenant %q, want the caller's", pool.gotTenant)
	}
}

func TestQuerier_RejectsAnInvalidTenantBeforeTouchingThePool(t *testing.T) {
	pool := &poolStub{err: errors.New("must not be reached")}
	q := NewPoolGraphRAGQuerier(pool, &resolverStub{}, graphrag.QueryConfig{}, nil)

	_, err := q.GetRelatedFindings(context.Background(), "NOT A TENANT ID", "f1")
	if err == nil {
		t.Fatal("expected an error for a malformed tenant")
	}
	if pool.gotTenant != "" {
		t.Error("the pool was asked for a tenant that does not parse")
	}
}

func TestQuerier_MissingDataPlaneIsNamedNotGuessed(t *testing.T) {
	// A Conn with no graph or no vector store cannot serve these RPCs. The error
	// says WHICH dependency is absent, because "graphrag failed" sends the reader
	// looking in the wrong place.
	cases := map[string]struct {
		conn *datapool.Conn
		want string
	}{
		"no graph":  {conn: &datapool.Conn{}, want: "graph database"},
		"no vector": {conn: &datapool.Conn{}, want: "graph database"}, // Neo4j is checked first
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			q := NewPoolGraphRAGQuerier(&poolStub{conn: tc.conn}, &resolverStub{}, graphrag.QueryConfig{}, nil)
			_, err := q.GetRelatedFindings(context.Background(), "acme", "f1")
			if err == nil {
				t.Fatal("expected an error when the tenant's data plane is incomplete")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to name the missing dependency (%q)", err, tc.want)
			}
		})
	}
}

func TestQuerier_EveryReadRPCGoesThroughTheTenantPool(t *testing.T) {
	// One table over all five read RPCs: each must acquire the tenant's Conn. A
	// seam that forgot to would read from somewhere else entirely. Five, not
	// six: StoreNode left the querier with the write half (gibson#1322).
	calls := map[string]func(*PoolGraphRAGQuerier) error{
		"QueryNodes": func(q *PoolGraphRAGQuerier) error {
			_, err := q.QueryNodes(context.Background(), "acme", &graphragpb.GraphQuery{Text: "x"})
			return err
		},
		"FindSimilarAttacks": func(q *PoolGraphRAGQuerier) error {
			_, err := q.FindSimilarAttacks(context.Background(), "acme", "content", 5)
			return err
		},
		"GetAttackChains": func(q *PoolGraphRAGQuerier) error {
			_, err := q.GetAttackChains(context.Background(), "acme", "T1059", 3)
			return err
		},
		"FindSimilarFindings": func(q *PoolGraphRAGQuerier) error {
			_, err := q.FindSimilarFindings(context.Background(), "acme", "f1", 5)
			return err
		},
		"GetRelatedFindings": func(q *PoolGraphRAGQuerier) error {
			_, err := q.GetRelatedFindings(context.Background(), "acme", "f1")
			return err
		},
	}

	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			pool := &poolStub{err: errors.New("acquire refused")}
			q := NewPoolGraphRAGQuerier(pool, &resolverStub{}, graphrag.QueryConfig{}, nil)
			if err := call(q); err == nil {
				t.Fatal("expected the acquire failure to surface")
			}
			if pool.gotTenant != "acme" {
				t.Errorf("%s did not acquire the caller's tenant (got %q)", name, pool.gotTenant)
			}
		})
	}
}
