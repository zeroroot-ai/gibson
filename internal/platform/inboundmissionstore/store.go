// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package inboundmissionstore keeps the mission definitions that a tenant
// published for inbound A2A calls, in the per-tenant Postgres database
// (migration 022, epic gibson#1367).
//
// A record names the agent that an outside client calls, the mission definition
// that the call starts, and the target IDs that a tenant admin approved. The
// grant to a caller identity is an FGA tuple and not a column.
package inboundmissionstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/sdk/auth"
)

var (
	// ErrNotFound marks an agent name that the tenant has not published.
	ErrNotFound = errors.New("inboundmissionstore: not published")
	// ErrLimit marks a publication that has no free place for a new inbound mission.
	ErrLimit = errors.New("inboundmissionstore: the publication has its most active missions")
	// ErrConflict marks an agent name that the tenant already published with
	// other fields.
	ErrConflict = errors.New("inboundmissionstore: the agent is published with other fields")
)

// Entry is one published mission definition.
type Entry struct {
	// Agent is the name of the agent that the caller addresses. It is unique in
	// the tenant.
	Agent string
	// PublicationID is new for each publication of the agent name. The count of open
	// tasks is by publication.
	PublicationID string
	// DefinitionID is the ID of the mission definition that a call starts.
	DefinitionID string
	// DefinitionHash is the hash of the definition at publish. A call starts a
	// mission only while the definition has this hash.
	DefinitionHash string
	// TargetIDs are the approved targets. A message can only narrow this set.
	TargetIDs []string
	// TargetHashes holds the hash of each approved target at publish, by target ID.
	TargetHashes map[string]string
	// MaxActive is the most inbound missions of this publication that run or wait
	// at one time. It is at least 1.
	MaxActive int32
	// PublishedBy is the subject of the tenant admin who published it.
	PublishedBy string
	CreatedAt   time.Time
}

// Store reads and writes the published mission definitions of one tenant.
type Store interface {
	// Publish saves an entry. The same agent with the same definition and the same
	// targets again saves the new hashes, so an admin can publish again after the
	// definition or a target changed. The same agent with another definition or other
	// targets returns ErrConflict.
	//
	// The call takes a lock on the agent name in the database of the tenant, so two
	// publishes of one name run one after the other. onCreate, when it is not nil,
	// runs inside the same transaction, and only when this call created the row. A
	// call that finds the row does not run it. An error of onCreate undoes the
	// insert.
	Publish(ctx context.Context, tenant string, e Entry, onCreate func(ctx context.Context) error) (*Entry, error)
	// ListPage returns at most limit entries of the tenant, in agent order. With
	// hasAfter it returns the entries whose agent is larger than after.
	ListPage(ctx context.Context, tenant, after string, hasAfter bool, limit int) ([]Entry, error)
	// Get returns one entry, or ErrNotFound.
	Get(ctx context.Context, tenant, agent string) (*Entry, error)
	// Delete removes one entry, or reports ErrNotFound. The tasks of the entry stay.
	Delete(ctx context.Context, tenant, agent string) error
	// Reserve takes one place for a new inbound mission of the publication, for the
	// owner, and records the mission ID in the same step, so a running mission always
	// has its row. It returns the slot. It locks the row of the publication, so
	// parallel calls and more than one replica cannot go over MaxActive. known tells
	// whether a mission exists and whether it has ended. A task whose mission has
	// ended gives its place back, and so does a task whose mission is unknown after
	// grace. It returns ErrLimit when no place is free, and ErrNotFound when the
	// agent is not published.
	Reserve(ctx context.Context, tenant, agent, owner, missionID string,
		known func(missionID string) (exists, terminal bool), grace time.Duration) (slot string, err error)
	// Release gives a reserved place back, for a mission that did not start.
	Release(ctx context.Context, tenant, slot string) error
	// Finish marks the task of a mission as ended. It changes nothing for a mission
	// that has no task.
	Finish(ctx context.Context, tenant, missionID string) error
	// Owner returns the caller that started a mission and the agent of its
	// publication, or ErrNotFound.
	Owner(ctx context.Context, tenant, missionID string) (owner, agent string, err error)
	// WithIdentityLock runs fn while it holds a lock on one identity in the database
	// of the tenant. Two calls for the same identity run one after the other, also
	// on two replicas. The lock ends when fn returns. fn reads the store through the
	// reader that it gets. The reader runs in the same transaction, so fn holds one
	// connection and not two.
	WithIdentityLock(ctx context.Context, tenant, identity string, fn func(r Reader) error) error
}

// Reader reads published entries inside a transaction.
type Reader interface {
	// Get returns one entry, or ErrNotFound.
	Get(ctx context.Context, agent string) (*Entry, error)
}

type txReader struct{ q datapool.SQL }

func (r txReader) Get(ctx context.Context, agent string) (*Entry, error) {
	return getEntry(ctx, r.q, agent)
}

func getEntry(ctx context.Context, q datapool.SQL, agent string) (*Entry, error) {
	e, err := scanEntry(q.QueryRow(ctx, `SELECT `+columns+` FROM inbound_missions WHERE agent = $1`, agent))
	if errors.Is(err, datapool.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, agent)
	}
	if err != nil {
		return nil, fmt.Errorf("inboundmissionstore: get %s: %w", agent, err)
	}
	return e, nil
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
		return nil, fmt.Errorf("inboundmissionstore: invalid tenant %q: %w", tenantID, err)
	}
	c, err := p.pool.For(ctx, tid)
	if err != nil {
		return nil, fmt.Errorf("inboundmissionstore: acquire conn for %s: %w", tenantID, err)
	}
	return c, nil
}

type postgresStore struct{ conns conns }

// NewPostgresStore builds the production Store over the per-tenant data pool. A
// nil pool is a configuration error and panics at start.
func NewPostgresStore(pool datapool.Pool) Store {
	if pool == nil {
		panic("inboundmissionstore: NewPostgresStore: pool must not be nil")
	}
	return &postgresStore{conns: poolConns{pool: pool}}
}

var _ Store = (*postgresStore)(nil)

const columns = `agent, publication_id, mission_definition_id, definition_hash, target_ids, target_hashes, max_active_missions, published_by, created_at`

type scanner interface {
	Scan(dest ...any) error
}

func scanEntry(row scanner) (*Entry, error) {
	var e Entry
	var targets, hashes string
	if err := row.Scan(&e.Agent, &e.PublicationID, &e.DefinitionID, &e.DefinitionHash, &targets, &hashes, &e.MaxActive, &e.PublishedBy, &e.CreatedAt); err != nil {
		return nil, fmt.Errorf("scan inbound mission row: %w", err)
	}
	if err := json.Unmarshal([]byte(targets), &e.TargetIDs); err != nil {
		return nil, fmt.Errorf("decode the targets of %s: %w", e.Agent, err)
	}
	if err := json.Unmarshal([]byte(hashes), &e.TargetHashes); err != nil {
		return nil, fmt.Errorf("decode the target hashes of %s: %w", e.Agent, err)
	}
	e.CreatedAt = e.CreatedAt.UTC()
	return &e, nil
}

func (s *postgresStore) Publish(
	ctx context.Context, tenant string, e Entry, onCreate func(ctx context.Context) error,
) (*Entry, error) {
	if e.Agent == "" || e.DefinitionID == "" || e.DefinitionHash == "" || len(e.TargetIDs) == 0 {
		return nil, errors.New("inboundmissionstore: publish needs an agent, a definition with its hash and a target")
	}
	if e.MaxActive < 1 {
		return nil, errors.New("inboundmissionstore: publish needs a limit of at least one active mission")
	}
	for _, id := range e.TargetIDs {
		if e.TargetHashes[id] == "" {
			return nil, fmt.Errorf("inboundmissionstore: publish needs the hash of target %s", id)
		}
	}
	targets, err := json.Marshal(e.TargetIDs)
	if err != nil {
		return nil, fmt.Errorf("inboundmissionstore: encode the targets: %w", err)
	}
	hashes, err := json.Marshal(e.TargetHashes)
	if err != nil {
		return nil, fmt.Errorf("inboundmissionstore: encode the target hashes: %w", err)
	}
	c, err := s.conns.For(ctx, tenant)
	if err != nil {
		return nil, fmt.Errorf("inbound mission store: acquire conn: %w", err)
	}
	defer c.Release()

	var out *Entry
	err = c.InTx(ctx, func(q datapool.SQL) error {
		if _, err := q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "inbound-agent:"+e.Agent); err != nil {
			return fmt.Errorf("lock the agent: %w", err)
		}
		inserted, err := q.Exec(ctx,
			`INSERT INTO inbound_missions (agent, publication_id, mission_definition_id, definition_hash, target_ids, target_hashes, max_active_missions, published_by)
			 VALUES ($1,$8,$2,$3,$4,$5,$6,$7)
			 ON CONFLICT (agent) DO NOTHING`,
			e.Agent, e.DefinitionID, e.DefinitionHash, string(targets), string(hashes), e.MaxActive, e.PublishedBy, uuid.NewString())
		if err != nil {
			return fmt.Errorf("insert: %w", err)
		}
		if inserted > 0 && onCreate != nil {
			if err := onCreate(ctx); err != nil {
				return fmt.Errorf("on create: %w", err)
			}
		}
		got, gerr := scanEntry(q.QueryRow(ctx, `SELECT `+columns+` FROM inbound_missions WHERE agent = $1 FOR UPDATE`, e.Agent))
		if gerr != nil {
			return gerr
		}
		if got.DefinitionID != e.DefinitionID || !slices.Equal(got.TargetIDs, e.TargetIDs) {
			return fmt.Errorf("%w: %s", ErrConflict, e.Agent)
		}
		if got.DefinitionHash != e.DefinitionHash || !maps.Equal(got.TargetHashes, e.TargetHashes) ||
			got.MaxActive != e.MaxActive {
			if _, err := q.Exec(ctx,
				`UPDATE inbound_missions SET definition_hash = $2, target_hashes = $3, max_active_missions = $4 WHERE agent = $1`,
				e.Agent, e.DefinitionHash, string(hashes), e.MaxActive); err != nil {
				return fmt.Errorf("pin: %w", err)
			}
			got.DefinitionHash, got.TargetHashes, got.MaxActive = e.DefinitionHash, e.TargetHashes, e.MaxActive
		}
		out = got
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("inboundmissionstore: publish %s: %w", e.Agent, err)
	}
	return out, nil
}

func (s *postgresStore) ListPage(
	ctx context.Context, tenant, after string, hasAfter bool, limit int,
) ([]Entry, error) {
	c, err := s.conns.For(ctx, tenant)
	if err != nil {
		return nil, fmt.Errorf("inbound mission store: acquire conn: %w", err)
	}
	defer c.Release()
	rows, err := c.SQL().Query(ctx,
		`SELECT `+columns+` FROM inbound_missions WHERE (NOT $1 OR agent > $2) ORDER BY agent ASC LIMIT $3`,
		hasAfter, after, limit)
	if err != nil {
		return nil, fmt.Errorf("inboundmissionstore: list page: %w", err)
	}
	defer rows.Close()
	out := []Entry{}
	for rows.Next() {
		e, scanErr := scanEntry(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("inboundmissionstore: list page: %w", scanErr)
		}
		out = append(out, *e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inboundmissionstore: list page rows: %w", err)
	}
	return out, nil
}

func (s *postgresStore) Get(ctx context.Context, tenant, agent string) (*Entry, error) {
	c, err := s.conns.For(ctx, tenant)
	if err != nil {
		return nil, fmt.Errorf("inbound mission store: acquire conn: %w", err)
	}
	defer c.Release()
	return getEntry(ctx, c.SQL(), agent)
}

func (s *postgresStore) Delete(ctx context.Context, tenant, agent string) error {
	c, err := s.conns.For(ctx, tenant)
	if err != nil {
		return fmt.Errorf("inbound mission store: acquire conn: %w", err)
	}
	defer c.Release()
	n, err := c.SQL().Exec(ctx, `DELETE FROM inbound_missions WHERE agent = $1`, agent)
	if err != nil {
		return fmt.Errorf("inboundmissionstore: delete %s: %w", agent, err)
	}
	if n == 0 {
		return fmt.Errorf("%w: %s", ErrNotFound, agent)
	}
	return nil
}

func (s *postgresStore) Reserve(
	ctx context.Context, tenant, agent, owner, missionID string,
	known func(missionID string) (exists, terminal bool), grace time.Duration,
) (string, error) {
	c, err := s.conns.For(ctx, tenant)
	if err != nil {
		return "", fmt.Errorf("inbound mission store: acquire conn: %w", err)
	}
	defer c.Release()
	slot := uuid.NewString()
	err = c.InTx(ctx, func(q datapool.SQL) error {
		// The lock on the row of the publication makes the count and the insert one
		// step for every replica.
		var limit int
		var publication string
		if err := q.QueryRow(ctx,
			`SELECT max_active_missions, publication_id FROM inbound_missions WHERE agent = $1 FOR UPDATE`,
			agent).Scan(&limit, &publication); err != nil {
			if errors.Is(err, datapool.ErrNoRows) {
				return fmt.Errorf("%w: %s", ErrNotFound, agent)
			}
			return fmt.Errorf("lock the publication: %w", err)
		}
		rows, err := q.Query(ctx,
			`SELECT slot, mission_id, created_at < now() - ($2 * interval '1 second')
			 FROM inbound_tasks WHERE publication_id = $1 AND finished_at IS NULL`,
			publication, int64(grace/time.Second))
		if err != nil {
			return fmt.Errorf("read the open tasks: %w", err)
		}
		var ended []string
		for rows.Next() {
			var sl, mid string
			var lapsed bool
			if err := rows.Scan(&sl, &mid, &lapsed); err != nil {
				rows.Close()
				return fmt.Errorf("scan an open task: %w", err)
			}
			exists, terminal := known(mid)
			if terminal || (!exists && lapsed) {
				ended = append(ended, sl)
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return fmt.Errorf("read the open tasks: %w", err)
		}
		for _, sl := range ended {
			if _, err := q.Exec(ctx, `UPDATE inbound_tasks SET finished_at = now() WHERE slot = $1`, sl); err != nil {
				return fmt.Errorf("close a task: %w", err)
			}
		}
		var open int
		if err := q.QueryRow(ctx,
			`SELECT count(*) FROM inbound_tasks WHERE publication_id = $1 AND finished_at IS NULL`,
			publication).Scan(&open); err != nil {
			return fmt.Errorf("count the open tasks: %w", err)
		}
		if open >= limit {
			return fmt.Errorf("%w: %s allows %d", ErrLimit, agent, limit)
		}
		if _, err := q.Exec(ctx,
			`INSERT INTO inbound_tasks (slot, agent, publication_id, owner, mission_id) VALUES ($1,$2,$3,$4,$5)`,
			slot, agent, publication, owner, missionID); err != nil {
			return fmt.Errorf("insert the reservation: %w", err)
		}
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("inboundmissionstore: reserve for %s: %w", agent, err)
	}
	return slot, nil
}

func (s *postgresStore) Release(ctx context.Context, tenant, slot string) error {
	c, err := s.conns.For(ctx, tenant)
	if err != nil {
		return fmt.Errorf("inbound mission store: acquire conn: %w", err)
	}
	defer c.Release()
	if _, err := c.SQL().Exec(ctx, `DELETE FROM inbound_tasks WHERE slot = $1`, slot); err != nil {
		return fmt.Errorf("inboundmissionstore: release %s: %w", slot, err)
	}
	return nil
}

func (s *postgresStore) Finish(ctx context.Context, tenant, missionID string) error {
	c, err := s.conns.For(ctx, tenant)
	if err != nil {
		return fmt.Errorf("inbound mission store: acquire conn: %w", err)
	}
	defer c.Release()
	if _, err := c.SQL().Exec(ctx,
		`UPDATE inbound_tasks SET finished_at = now() WHERE mission_id = $1 AND finished_at IS NULL`, missionID); err != nil {
		return fmt.Errorf("inboundmissionstore: finish %s: %w", missionID, err)
	}
	return nil
}

func (s *postgresStore) Owner(ctx context.Context, tenant, missionID string) (owner, agent string, err error) {
	c, err := s.conns.For(ctx, tenant)
	if err != nil {
		return "", "", fmt.Errorf("inbound mission store: acquire conn: %w", err)
	}
	defer c.Release()
	err = c.SQL().QueryRow(ctx,
		`SELECT owner, agent FROM inbound_tasks WHERE mission_id = $1`, missionID).Scan(&owner, &agent)
	if errors.Is(err, datapool.ErrNoRows) {
		return "", "", fmt.Errorf("%w: mission %s", ErrNotFound, missionID)
	}
	if err != nil {
		return "", "", fmt.Errorf("inboundmissionstore: owner of %s: %w", missionID, err)
	}
	return owner, agent, nil
}

func (s *postgresStore) WithIdentityLock(ctx context.Context, tenant, identity string, fn func(r Reader) error) error {
	c, err := s.conns.For(ctx, tenant)
	if err != nil {
		return fmt.Errorf("inbound mission store: acquire conn: %w", err)
	}
	defer c.Release()
	err = c.InTx(ctx, func(q datapool.SQL) error {
		if _, err := q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "inbound-identity:"+identity); err != nil {
			return fmt.Errorf("lock the identity %s: %w", identity, err)
		}
		return fn(txReader{q: q})
	})
	if err != nil {
		return fmt.Errorf("inbound identity lock %s: %w", identity, err)
	}
	return nil
}
