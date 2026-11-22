// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package loopgrantstore keeps the loop grants of each tenant in the
// per-tenant Postgres database (migration 025, gibson#1612).
//
// A loop grant lets the members of one catalog agent call the tools of the
// connectors that the tenant enabled, by tool class. The database is the tenant
// scope: a read for one tenant cannot return a row of another.
package loopgrantstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/sdk/auth"
)

// ErrNotFound marks an agent that holds no loop grant in the tenant.
var ErrNotFound = errors.New("loopgrantstore: no loop grant")

// Grant is the loop grant of one agent.
type Grant struct {
	// ID names the grant. The audit record of each member call holds it.
	ID string
	// AgentName is the catalog agent whose members hold the grant.
	AgentName string
	// ToolClasses are tool classes of the catalog, for example ticket.
	ToolClasses []string
	// HarnessCalls are harness calls besides the tool call.
	HarnessCalls []string
	// Grantor is the subject of the admin who gave the grant.
	Grantor   string
	GrantedAt time.Time
}

// Store reads and writes the loop grants of one tenant.
type Store interface {
	// Put saves the grant of an agent. A grant that exists is replaced.
	Put(ctx context.Context, tenant string, g Grant) (*Grant, error)
	// Get returns the grant of an agent, or ErrNotFound.
	Get(ctx context.Context, tenant, agentName string) (*Grant, error)
	// List returns each grant of the tenant, in agent name order.
	List(ctx context.Context, tenant string) ([]Grant, error)
	// Delete removes the grant of an agent. It is idempotent.
	Delete(ctx context.Context, tenant, agentName string) error
}

type conn interface {
	SQL() datapool.SQL
	Release()
}

type conns interface {
	For(ctx context.Context, tenantID string) (conn, error)
}

type poolConns struct{ pool datapool.Pool }

func (p poolConns) For(ctx context.Context, tenantID string) (conn, error) {
	tid, err := auth.NewTenantID(tenantID)
	if err != nil {
		return nil, fmt.Errorf("loopgrantstore: invalid tenant %q: %w", tenantID, err)
	}
	c, err := p.pool.For(ctx, tid)
	if err != nil {
		return nil, fmt.Errorf("loopgrantstore: acquire conn for %s: %w", tenantID, err)
	}
	return c, nil
}

type postgresStore struct{ conns conns }

// NewPostgresStore builds the production Store over the per-tenant data pool.
// A nil pool is a configuration error and panics at start.
func NewPostgresStore(pool datapool.Pool) Store {
	if pool == nil {
		panic("loopgrantstore: NewPostgresStore: pool must not be nil")
	}
	return &postgresStore{conns: poolConns{pool: pool}}
}

var _ Store = (*postgresStore)(nil)

const columns = `id, agent_name, tool_classes, harness_calls, grantor, granted_at`

type scanner interface {
	Scan(dest ...any) error
}

func scanGrant(row scanner) (*Grant, error) {
	var g Grant
	if err := row.Scan(&g.ID, &g.AgentName, &g.ToolClasses, &g.HarnessCalls, &g.Grantor, &g.GrantedAt); err != nil {
		return nil, fmt.Errorf("scan loop grant row: %w", err)
	}
	g.GrantedAt = g.GrantedAt.UTC()
	return &g, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (s *postgresStore) Put(ctx context.Context, tenant string, g Grant) (*Grant, error) {
	if g.ID == "" || g.AgentName == "" || g.Grantor == "" {
		return nil, errors.New("loopgrantstore: a grant needs an id, an agent and a grantor")
	}
	c, err := s.conns.For(ctx, tenant)
	if err != nil {
		return nil, fmt.Errorf("loopgrantstore: %w", err)
	}
	defer c.Release()
	out, err := scanGrant(c.SQL().QueryRow(ctx,
		`INSERT INTO loop_grants (id, agent_name, tool_classes, harness_calls, grantor)
		 VALUES ($1,$2,$3,$4,$5)
		 ON CONFLICT (agent_name) DO UPDATE
		   SET id = EXCLUDED.id, tool_classes = EXCLUDED.tool_classes,
		       harness_calls = EXCLUDED.harness_calls, grantor = EXCLUDED.grantor, granted_at = now()
		 RETURNING `+columns,
		g.ID, g.AgentName, nonNil(g.ToolClasses), nonNil(g.HarnessCalls), g.Grantor))
	if err != nil {
		return nil, fmt.Errorf("loopgrantstore: put %s: %w", g.AgentName, err)
	}
	return out, nil
}

func (s *postgresStore) Get(ctx context.Context, tenant, agentName string) (*Grant, error) {
	c, err := s.conns.For(ctx, tenant)
	if err != nil {
		return nil, fmt.Errorf("loopgrantstore: %w", err)
	}
	defer c.Release()
	g, err := scanGrant(c.SQL().QueryRow(ctx, `SELECT `+columns+` FROM loop_grants WHERE agent_name = $1`, agentName))
	if errors.Is(err, datapool.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, agentName)
	}
	if err != nil {
		return nil, fmt.Errorf("loopgrantstore: get %s: %w", agentName, err)
	}
	return g, nil
}

func (s *postgresStore) List(ctx context.Context, tenant string) ([]Grant, error) {
	c, err := s.conns.For(ctx, tenant)
	if err != nil {
		return nil, fmt.Errorf("loopgrantstore: %w", err)
	}
	defer c.Release()
	rows, err := c.SQL().Query(ctx, `SELECT `+columns+` FROM loop_grants ORDER BY agent_name ASC`)
	if err != nil {
		return nil, fmt.Errorf("loopgrantstore: list: %w", err)
	}
	defer rows.Close()
	out := []Grant{}
	for rows.Next() {
		g, scanErr := scanGrant(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("loopgrantstore: list: %w", scanErr)
		}
		out = append(out, *g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("loopgrantstore: list rows: %w", err)
	}
	return out, nil
}

func (s *postgresStore) Delete(ctx context.Context, tenant, agentName string) error {
	c, err := s.conns.For(ctx, tenant)
	if err != nil {
		return fmt.Errorf("loopgrantstore: %w", err)
	}
	defer c.Release()
	if _, err := c.SQL().Exec(ctx, `DELETE FROM loop_grants WHERE agent_name = $1`, agentName); err != nil {
		return fmt.Errorf("loopgrantstore: delete %s: %w", agentName, err)
	}
	return nil
}
