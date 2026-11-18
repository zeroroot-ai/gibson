// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package outsideagentstore keeps the outside agents of each tenant in the
// per-tenant Postgres database (migration 020, epic gibson#1366).
//
// An outside agent is an A2A agent that runs outside Gibson. The record holds
// its name, the HTTPS URL of its A2A endpoint and the NAME of a tenant secret
// for its credential. It never holds a credential value. The grant to a mission
// is an FGA tuple and not a column.
package outsideagentstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/sdk/auth"
)

var (
	// ErrNotFound marks a name that the tenant does not have.
	ErrNotFound = errors.New("outsideagentstore: not found")
	// ErrConflict marks a name that the tenant already holds with other fields.
	ErrConflict = errors.New("outsideagentstore: the name exists with other fields")
)

// Entry is one outside agent.
type Entry struct {
	Name             string
	A2AURL           string
	CredentialSecret string
	Description      string
	CreatedAt        time.Time
}

// Store reads and writes the outside agents of one tenant.
type Store interface {
	// Register saves an entry. The same entry again changes nothing and returns
	// the stored entry. The same name with other fields returns ErrConflict.
	Register(ctx context.Context, tenant string, e Entry) (*Entry, error)
	// List returns each outside agent of the tenant, in name order.
	List(ctx context.Context, tenant string) ([]Entry, error)
	// Get returns one outside agent, or ErrNotFound.
	Get(ctx context.Context, tenant, name string) (*Entry, error)
	// Delete removes one outside agent. It reports ErrNotFound for a name that
	// the tenant does not have.
	Delete(ctx context.Context, tenant, name string) error
}

type conn interface {
	SQL() datapool.SQL
	InTx(ctx context.Context, fn func(datapool.SQL) error) error
	Release()
}

type conns interface {
	For(ctx context.Context, tenantID string) (conn, error)
}

type poolConns struct{ pool datapool.Pool }

func (p poolConns) For(ctx context.Context, tenantID string) (conn, error) {
	tid, err := auth.NewTenantID(tenantID)
	if err != nil {
		return nil, fmt.Errorf("outsideagentstore: invalid tenant %q: %w", tenantID, err)
	}
	c, err := p.pool.For(ctx, tid)
	if err != nil {
		return nil, fmt.Errorf("outsideagentstore: acquire conn for %s: %w", tenantID, err)
	}
	return c, nil
}

type postgresStore struct{ conns conns }

// NewPostgresStore builds the production Store over the per-tenant data pool. A
// nil pool is a configuration error and panics at start.
func NewPostgresStore(pool datapool.Pool) Store {
	if pool == nil {
		panic("outsideagentstore: NewPostgresStore: pool must not be nil")
	}
	return &postgresStore{conns: poolConns{pool: pool}}
}

var _ Store = (*postgresStore)(nil)

const columns = `name, a2a_url, credential_secret, description, created_at`

type scanner interface {
	Scan(dest ...any) error
}

func scanEntry(row scanner) (*Entry, error) {
	var e Entry
	if err := row.Scan(&e.Name, &e.A2AURL, &e.CredentialSecret, &e.Description, &e.CreatedAt); err != nil {
		return nil, fmt.Errorf("scan outside agent row: %w", err)
	}
	e.CreatedAt = e.CreatedAt.UTC()
	return &e, nil
}

func (s *postgresStore) Register(ctx context.Context, tenant string, e Entry) (*Entry, error) {
	if e.Name == "" || e.A2AURL == "" {
		return nil, errors.New("outsideagentstore: register needs a name and a URL")
	}
	c, err := s.conns.For(ctx, tenant)
	if err != nil {
		return nil, err
	}
	defer c.Release()

	var out *Entry
	err = c.InTx(ctx, func(q datapool.SQL) error {
		if _, err := q.Exec(ctx,
			`INSERT INTO outside_agents (name, a2a_url, credential_secret, description)
			 VALUES ($1,$2,$3,$4)
			 ON CONFLICT (name) DO NOTHING`,
			e.Name, e.A2AURL, e.CredentialSecret, e.Description); err != nil {
			return fmt.Errorf("insert: %w", err)
		}
		got, gerr := scanEntry(q.QueryRow(ctx, `SELECT `+columns+` FROM outside_agents WHERE name = $1`, e.Name))
		if gerr != nil {
			return gerr
		}
		if got.A2AURL != e.A2AURL || got.CredentialSecret != e.CredentialSecret || got.Description != e.Description {
			return fmt.Errorf("%w: %s", ErrConflict, e.Name)
		}
		out = got
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("outsideagentstore: register %s: %w", e.Name, err)
	}
	return out, nil
}

func (s *postgresStore) List(ctx context.Context, tenant string) ([]Entry, error) {
	c, err := s.conns.For(ctx, tenant)
	if err != nil {
		return nil, err
	}
	defer c.Release()
	rows, err := c.SQL().Query(ctx, `SELECT `+columns+` FROM outside_agents ORDER BY name ASC`)
	if err != nil {
		return nil, fmt.Errorf("outsideagentstore: list: %w", err)
	}
	defer rows.Close()
	out := []Entry{}
	for rows.Next() {
		e, scanErr := scanEntry(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("outsideagentstore: list: %w", scanErr)
		}
		out = append(out, *e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("outsideagentstore: list rows: %w", err)
	}
	return out, nil
}

func (s *postgresStore) Get(ctx context.Context, tenant, name string) (*Entry, error) {
	c, err := s.conns.For(ctx, tenant)
	if err != nil {
		return nil, err
	}
	defer c.Release()
	e, err := scanEntry(c.SQL().QueryRow(ctx, `SELECT `+columns+` FROM outside_agents WHERE name = $1`, name))
	if errors.Is(err, datapool.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	if err != nil {
		return nil, fmt.Errorf("outsideagentstore: get %s: %w", name, err)
	}
	return e, nil
}

func (s *postgresStore) Delete(ctx context.Context, tenant, name string) error {
	c, err := s.conns.For(ctx, tenant)
	if err != nil {
		return err
	}
	defer c.Release()
	n, err := c.SQL().Exec(ctx, `DELETE FROM outside_agents WHERE name = $1`, name)
	if err != nil {
		return fmt.Errorf("outsideagentstore: delete %s: %w", name, err)
	}
	if n == 0 {
		return fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	return nil
}
