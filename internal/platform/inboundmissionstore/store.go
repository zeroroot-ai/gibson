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
	// ErrConflict marks an agent name that the tenant already published with
	// other fields.
	ErrConflict = errors.New("inboundmissionstore: the agent is published with other fields")
)

// Entry is one published mission definition.
type Entry struct {
	// Agent is the name of the agent that the caller addresses. It is unique in
	// the tenant.
	Agent string
	// PublicationID is new for each publication of the agent name. A grant is by
	// publication.
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
	// Reserve records the task of a new inbound mission of the publication, for the
	// owner, with the mission ID, before the mission starts. A running mission
	// therefore always has its row. It returns the slot of the row. It returns
	// ErrNotFound when the agent is not published. There is no count limit.
	Reserve(ctx context.Context, tenant, agent, owner, missionID string) (slot string, err error)
	// Release deletes the task row of a mission that did not start.
	Release(ctx context.Context, tenant, slot string) error
	// Owner returns the caller that started a mission and the agent of its
	// publication, or ErrNotFound.
	Owner(ctx context.Context, tenant, missionID string) (owner, agent string, err error)
	// TakeMessage records that the message with this key started the mission. It
	// returns an empty string when the key is new. It returns the mission that
	// the first message started when the key was already taken. The key is
	// unique inside the database of the tenant, so the same key in another
	// tenant is a new key. A key older than MessageRetention is forgotten.
	TakeMessage(ctx context.Context, tenant, key, missionID string) (taken string, err error)
	// ForgetMessage deletes the key of a message whose mission did not start, so
	// that a retry of the message can start it.
	ForgetMessage(ctx context.Context, tenant, key string) error
	// WithIdentityLock runs fn while it holds a lock on one identity in the database
	// of the tenant. Two calls for the same identity run one after the other, also
	// on two replicas. The lock ends when fn returns. fn reads the store through the
	// reader that it gets. The reader runs in the same transaction, so fn holds one
	// connection and not two.
	WithIdentityLock(ctx context.Context, tenant, identity string, fn func(r Reader) error) error
	// WithAgentLock runs fn while it holds the lock of one agent name, the lock that
	// Publish takes. A publish and an unpublish of one name run one after the other.
	// fn reads and deletes through the transaction that holds the lock.
	WithAgentLock(ctx context.Context, tenant, agent string, fn func(tx AgentTx) error) error
}

// AgentTx reads and deletes the entry of the agent whose lock is held.
type AgentTx interface {
	Reader
	// Delete removes the entry, or reports ErrNotFound.
	Delete(ctx context.Context, agent string) error
}

// Reader reads published entries inside a transaction.
type Reader interface {
	// Get returns one entry, or ErrNotFound.
	Get(ctx context.Context, agent string) (*Entry, error)
}

type txReader struct{ q datapool.SQL }

func (r txReader) Delete(ctx context.Context, agent string) error {
	return deleteEntry(ctx, r.q, agent)
}

func deleteEntry(ctx context.Context, q datapool.SQL, agent string) error {
	n, err := q.Exec(ctx, `DELETE FROM inbound_missions WHERE agent = $1`, agent)
	if err != nil {
		return fmt.Errorf("inboundmissionstore: delete %s: %w", agent, err)
	}
	if n == 0 {
		return fmt.Errorf("%w: %s", ErrNotFound, agent)
	}
	return nil
}

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

// MessageRetention is how long the store remembers the id of a message. A sender
// that retries sends the same id again within this time.
const MessageRetention = 7 * 24 * time.Hour

var _ Store = (*postgresStore)(nil)

const columns = `agent, publication_id, mission_definition_id, definition_hash, target_ids, target_hashes, published_by, created_at`

type scanner interface {
	Scan(dest ...any) error
}

func scanEntry(row scanner) (*Entry, error) {
	var e Entry
	var targets, hashes string
	if err := row.Scan(&e.Agent, &e.PublicationID, &e.DefinitionID, &e.DefinitionHash, &targets, &hashes, &e.PublishedBy, &e.CreatedAt); err != nil {
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

// validatePublish checks an entry and returns the JSON of its targets and of its
// target hashes.
func validatePublish(e Entry) (targets, hashes []byte, err error) {
	if e.Agent == "" || e.DefinitionID == "" || e.DefinitionHash == "" || len(e.TargetIDs) == 0 {
		return nil, nil, errors.New("inboundmissionstore: publish needs an agent, a definition with its hash and a target")
	}
	for _, id := range e.TargetIDs {
		if e.TargetHashes[id] == "" {
			return nil, nil, fmt.Errorf("inboundmissionstore: publish needs the hash of target %s", id)
		}
	}
	targets, err = json.Marshal(e.TargetIDs)
	if err != nil {
		return nil, nil, fmt.Errorf("inboundmissionstore: encode the targets: %w", err)
	}
	hashes, err = json.Marshal(e.TargetHashes)
	if err != nil {
		return nil, nil, fmt.Errorf("inboundmissionstore: encode the target hashes: %w", err)
	}
	return targets, hashes, nil
}

func (s *postgresStore) Publish(
	ctx context.Context, tenant string, e Entry, onCreate func(ctx context.Context) error,
) (*Entry, error) {
	targets, hashes, err := validatePublish(e)
	if err != nil {
		return nil, err
	}
	c, err := s.conns.For(ctx, tenant)
	if err != nil {
		return nil, fmt.Errorf("inbound mission store: acquire conn: %w", err)
	}
	defer c.Release()

	var out *Entry
	err = c.InTx(ctx, func(q datapool.SQL) error {
		if _, err := q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, agentLockKey(e.Agent)); err != nil {
			return fmt.Errorf("lock the agent: %w", err)
		}
		inserted, err := q.Exec(ctx,
			`INSERT INTO inbound_missions (agent, publication_id, mission_definition_id, definition_hash, target_ids, target_hashes, published_by)
			 VALUES ($1,$7,$2,$3,$4,$5,$6)
			 ON CONFLICT (agent) DO NOTHING`,
			e.Agent, e.DefinitionID, e.DefinitionHash, string(targets), string(hashes), e.PublishedBy, uuid.NewString())
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
		if got.DefinitionHash != e.DefinitionHash || !maps.Equal(got.TargetHashes, e.TargetHashes) {
			if _, err := q.Exec(ctx,
				`UPDATE inbound_missions SET definition_hash = $2, target_hashes = $3 WHERE agent = $1`,
				e.Agent, e.DefinitionHash, string(hashes)); err != nil {
				return fmt.Errorf("pin: %w", err)
			}
			got.DefinitionHash, got.TargetHashes = e.DefinitionHash, e.TargetHashes
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
	return deleteEntry(ctx, c.SQL(), agent)
}

func (s *postgresStore) Reserve(ctx context.Context, tenant, agent, owner, missionID string) (string, error) {
	c, err := s.conns.For(ctx, tenant)
	if err != nil {
		return "", fmt.Errorf("inbound mission store: acquire conn: %w", err)
	}
	defer c.Release()
	slot := uuid.NewString()
	// One statement reads the publication and writes the task, so a task row always
	// names a publication that existed when the row was written.
	n, err := c.SQL().Exec(ctx,
		`INSERT INTO inbound_tasks (slot, agent, publication_id, owner, mission_id)
		 SELECT $1, agent, publication_id, $3, $4 FROM inbound_missions WHERE agent = $2`,
		slot, agent, owner, missionID)
	if err != nil {
		return "", fmt.Errorf("inboundmissionstore: reserve for %s: %w", agent, err)
	}
	if n == 0 {
		return "", fmt.Errorf("inboundmissionstore: reserve for %s: %w: %s", agent, ErrNotFound, agent)
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

func (s *postgresStore) TakeMessage(ctx context.Context, tenant, key, missionID string) (string, error) {
	c, err := s.conns.For(ctx, tenant)
	if err != nil {
		return "", fmt.Errorf("inbound mission store: acquire conn: %w", err)
	}
	defer c.Release()
	// An old key goes first, so the table stays small and an old id can start a mission again.
	if _, err := c.SQL().Exec(ctx,
		`DELETE FROM inbound_messages WHERE created_at < now() - make_interval(secs => $1)`,
		MessageRetention.Seconds()); err != nil {
		return "", fmt.Errorf("inboundmissionstore: forget old message ids: %w", err)
	}
	n, err := c.SQL().Exec(ctx,
		`INSERT INTO inbound_messages (message_key, mission_id) VALUES ($1, $2) ON CONFLICT (message_key) DO NOTHING`,
		key, missionID)
	if err != nil {
		return "", fmt.Errorf("inboundmissionstore: take message id: %w", err)
	}
	if n > 0 {
		return "", nil
	}
	var taken string
	err = c.SQL().QueryRow(ctx, `SELECT mission_id FROM inbound_messages WHERE message_key = $1`, key).Scan(&taken)
	if errors.Is(err, datapool.ErrNoRows) {
		// The retention delete of another call removed the row between the two statements.
		return "", fmt.Errorf("inboundmissionstore: message id vanished: %w", ErrNotFound)
	}
	if err != nil {
		return "", fmt.Errorf("inboundmissionstore: read message id: %w", err)
	}
	return taken, nil
}

func (s *postgresStore) ForgetMessage(ctx context.Context, tenant, key string) error {
	c, err := s.conns.For(ctx, tenant)
	if err != nil {
		return fmt.Errorf("inbound mission store: acquire conn: %w", err)
	}
	defer c.Release()
	if _, err := c.SQL().Exec(ctx, `DELETE FROM inbound_messages WHERE message_key = $1`, key); err != nil {
		return fmt.Errorf("inboundmissionstore: forget message id: %w", err)
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

func (s *postgresStore) WithAgentLock(ctx context.Context, tenant, agent string, fn func(tx AgentTx) error) error {
	c, err := s.conns.For(ctx, tenant)
	if err != nil {
		return fmt.Errorf("inbound mission store: acquire conn: %w", err)
	}
	defer c.Release()
	err = c.InTx(ctx, func(q datapool.SQL) error {
		if _, err := q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, agentLockKey(agent)); err != nil {
			return fmt.Errorf("lock the agent %s: %w", agent, err)
		}
		return fn(txReader{q: q})
	})
	if err != nil {
		return fmt.Errorf("inbound agent lock %s: %w", agent, err)
	}
	return nil
}

// agentLockKey is the advisory lock key of an agent name. Publish and WithAgentLock
// use the same key.
func agentLockKey(agent string) string { return "inbound-agent:" + agent }
