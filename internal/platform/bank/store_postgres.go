// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package bank

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/sdk/auth"
)

// conn is one tenant's database handle for the life of a call: statements, a
// transaction, and the release that returns it.
//
// It is an interface rather than *datapool.Conn so the store's own logic — what
// it validates, what it refuses, how it pages — is testable without a database.
// That matters more than it sounds: those are the parts a reader has to trust,
// and a container-only test exercises them on a machine that has Docker and
// nowhere else.
type conn interface {
	SQL() datapool.SQL
	InTx(ctx context.Context, fn func(datapool.SQL) error) error
	Release()
}

// conns hands out a conn per tenant. datapool.Pool satisfies it through
// poolConns; a test supplies a scripted one.
type conns interface {
	For(ctx context.Context, tenantID string) (conn, error)
}

// postgresStore keeps banks and members in the per-tenant database (migration
// 010). The tenant selects the database, so a bank id from one tenant never
// resolves in another: isolation is structural, not a WHERE clause.
type postgresStore struct {
	conns conns
}

// NewPostgresStore builds the production Store over the per-tenant data pool.
// A nil pool is misconfiguration and panics at startup rather than failing per
// request.
func NewPostgresStore(pool datapool.Pool) Store {
	if pool == nil {
		panic("bank: NewPostgresStore: pool must not be nil")
	}
	return &postgresStore{conns: poolConns{pool: pool}}
}

var _ Store = (*postgresStore)(nil)

// poolConns adapts the data-plane pool to conns.
type poolConns struct{ pool datapool.Pool }

func (p poolConns) For(ctx context.Context, tenantID string) (conn, error) {
	tid, err := auth.NewTenantID(tenantID)
	if err != nil {
		return nil, fmt.Errorf("bank: invalid tenant %q: %w", tenantID, err)
	}
	c, err := p.pool.For(ctx, tid)
	if err != nil {
		return nil, fmt.Errorf("acquire conn for %s: %w", tenantID, err)
	}
	return c, nil
}

// conn acquires the tenant's handle. The caller releases it.
func (s *postgresStore) conn(ctx context.Context, tenantID string) (conn, error) {
	c, err := s.conns.For(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("bank: %w", err)
	}
	return c, nil
}

const bankColumns = `id, name, owner_kind, owner_id, desired_count, login_shape,
	provider_config_name, agent_name, model, max_jobs_in_flight,
	stale_limit_seconds, spill_policy, created_at, updated_at`

func (s *postgresStore) Create(ctx context.Context, tenantID string, in CreateInput) (*Bank, error) {
	if err := in.Validate(); err != nil {
		return nil, err
	}
	c, err := s.conn(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defer c.Release()

	now := time.Now().UTC()
	b := &Bank{
		ID:                 string(types.NewID()),
		Name:               in.Name,
		OwnerKind:          in.OwnerKind,
		OwnerID:            in.OwnerID,
		DesiredCount:       in.DesiredCount,
		LoginShape:         in.LoginShape,
		ProviderConfigName: in.ProviderConfigName,
		AgentName:          in.AgentName,
		Model:              in.Model,
		MaxJobsInFlight:    in.MaxJobsInFlight,
		StaleLimit:         in.StaleLimit,
		SpillPolicy:        in.SpillPolicy,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	_, err = c.SQL().Exec(ctx,
		`INSERT INTO banks (`+bankColumns+`)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		b.ID, b.Name, string(b.OwnerKind), b.OwnerID, b.DesiredCount, string(b.LoginShape),
		b.ProviderConfigName, b.AgentName, b.Model, b.MaxJobsInFlight,
		staleLimitSeconds(b.StaleLimit), string(b.SpillPolicy), b.CreatedAt, b.UpdatedAt)
	if err != nil {
		if errors.Is(err, datapool.ErrUniqueViolation) {
			return nil, fmt.Errorf("%w: a bank named %q already exists", ErrAlreadyExists, b.Name)
		}
		return nil, fmt.Errorf("bank: insert %q: %w", b.Name, err)
	}
	return b, nil
}

func (s *postgresStore) Get(ctx context.Context, tenantID, id string) (*Bank, error) {
	c, err := s.conn(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defer c.Release()

	row := c.SQL().QueryRow(ctx, `SELECT `+bankColumns+` FROM banks WHERE id = $1`, id)
	b, err := scanBank(row)
	if errors.Is(err, datapool.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	if err != nil {
		return nil, fmt.Errorf("bank: get %s: %w", id, err)
	}
	return b, nil
}

func (s *postgresStore) List(ctx context.Context, tenantID string, page Page) ([]*Bank, string, error) {
	c, err := s.conn(ctx, tenantID)
	if err != nil {
		return nil, "", err
	}
	defer c.Release()

	size := clampPageSize(page.Size)
	after, err := decodeToken(page.Token)
	if err != nil {
		return nil, "", err
	}
	// Newest first, keyed by (created_at, id) so two banks created in the same
	// microsecond still page without a gap or a repeat.
	rows, err := c.SQL().Query(ctx,
		`SELECT `+bankColumns+` FROM banks
		 WHERE ($1::timestamptz IS NULL OR (created_at, id) < ($1, $2))
		 ORDER BY created_at DESC, id DESC
		 LIMIT $3`,
		after.at, after.id, size+1)
	if err != nil {
		return nil, "", fmt.Errorf("bank: list: %w", err)
	}
	defer rows.Close()

	banks := make([]*Bank, 0, size)
	for rows.Next() {
		b, scanErr := scanBank(rows)
		if scanErr != nil {
			return nil, "", fmt.Errorf("bank: list scan: %w", scanErr)
		}
		banks = append(banks, b)
	}
	if rows.Err() != nil {
		return nil, "", fmt.Errorf("bank: list rows: %w", rows.Err())
	}
	return trimPage(banks, size, func(b *Bank) cursor { return cursor{at: &b.CreatedAt, id: b.ID} })
}

func (s *postgresStore) Update(ctx context.Context, tenantID, id string, in UpdateInput) (*Bank, error) {
	if err := in.Validate(); err != nil {
		return nil, err
	}
	c, err := s.conn(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defer c.Release()

	// COALESCE per column: one statement, and an absent field keeps its value
	// without a read-modify-write that could lose a concurrent change.
	var stale *int64
	if in.StaleLimit != nil {
		v := staleLimitSeconds(*in.StaleLimit)
		stale = &v
	}
	var spill *string
	if in.SpillPolicy != nil {
		v := string(*in.SpillPolicy)
		spill = &v
	}
	row := c.SQL().QueryRow(ctx,
		`UPDATE banks SET
		   desired_count       = COALESCE($2, desired_count),
		   max_jobs_in_flight  = COALESCE($3, max_jobs_in_flight),
		   stale_limit_seconds = COALESCE($4, stale_limit_seconds),
		   spill_policy        = COALESCE($5, spill_policy),
		   updated_at          = $6
		 WHERE id = $1
		 RETURNING `+bankColumns,
		id, in.DesiredCount, in.MaxJobsInFlight, stale, spill, time.Now().UTC())
	b, err := scanBank(row)
	if errors.Is(err, datapool.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	if err != nil {
		return nil, fmt.Errorf("bank: update %s: %w", id, err)
	}
	return b, nil
}

func (s *postgresStore) Delete(ctx context.Context, tenantID, id string) error {
	c, err := s.conn(ctx, tenantID)
	if err != nil {
		return err
	}
	defer c.Release()

	// bank_members cascades on the foreign key, so one statement removes the
	// bank and its member rows together.
	affected, err := c.SQL().Exec(ctx, `DELETE FROM banks WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("bank: delete %s: %w", id, err)
	}
	if affected == 0 {
		return fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return nil
}

const memberColumns = `id, bank_id, mission_id, mission_run_id, agent_run_id, sandbox_id,
	state, jobs_in_flight, job_cap, active_job_ids, claude_version,
	last_heartbeat, created_at, updated_at`

func (s *postgresStore) ListMembers(ctx context.Context, tenantID, bankID string, page Page) ([]*Member, string, error) {
	c, err := s.conn(ctx, tenantID)
	if err != nil {
		return nil, "", err
	}
	defer c.Release()

	size := clampPageSize(page.Size)
	after, err := decodeToken(page.Token)
	if err != nil {
		return nil, "", err
	}
	// Oldest first: a reader sees members in the order they were launched.
	rows, err := c.SQL().Query(ctx,
		`SELECT `+memberColumns+` FROM bank_members
		 WHERE bank_id = $1 AND ($2::timestamptz IS NULL OR (created_at, id) > ($2, $3))
		 ORDER BY created_at ASC, id ASC
		 LIMIT $4`,
		bankID, after.at, after.id, size+1)
	if err != nil {
		return nil, "", fmt.Errorf("bank: list members of %s: %w", bankID, err)
	}
	defer rows.Close()

	members := make([]*Member, 0, size)
	for rows.Next() {
		m, scanErr := scanMember(rows)
		if scanErr != nil {
			return nil, "", fmt.Errorf("bank: list members scan: %w", scanErr)
		}
		members = append(members, m)
	}
	if rows.Err() != nil {
		return nil, "", fmt.Errorf("bank: list members rows: %w", rows.Err())
	}
	return trimPage(members, size, func(m *Member) cursor { return cursor{at: &m.CreatedAt, id: m.ID} })
}

// scanner is what a single row and a row of a page both satisfy, so one scan
// function serves a lookup and a listing.
type scanner interface {
	Scan(dest ...any) error
}

func scanBank(row scanner) (*Bank, error) {
	var (
		b       Bank
		owner   string
		shape   string
		spill   string
		staleS  int64
		created time.Time
		updated time.Time
	)
	if err := row.Scan(&b.ID, &b.Name, &owner, &b.OwnerID, &b.DesiredCount, &shape,
		&b.ProviderConfigName, &b.AgentName, &b.Model, &b.MaxJobsInFlight,
		&staleS, &spill, &created, &updated); err != nil {
		return nil, fmt.Errorf("scan bank row: %w", err)
	}
	b.OwnerKind = OwnerKind(owner)
	b.LoginShape = LoginShape(shape)
	b.SpillPolicy = SpillPolicy(spill)
	b.StaleLimit = time.Duration(staleS) * time.Second
	b.CreatedAt = created.UTC()
	b.UpdatedAt = updated.UTC()
	return &b, nil
}

func scanMember(row scanner) (*Member, error) {
	var (
		m       Member
		state   string
		beat    *time.Time
		created time.Time
		updated time.Time
	)
	if err := row.Scan(&m.ID, &m.BankID, &m.MissionID, &m.MissionRunID, &m.AgentRunID,
		&m.SandboxID, &state, &m.JobsInFlight, &m.JobCap, &m.ActiveJobIDs,
		&m.ClaudeVersion, &beat, &created, &updated); err != nil {
		return nil, fmt.Errorf("scan member row: %w", err)
	}
	m.State = MemberState(state)
	if beat != nil {
		m.LastHeartbeat = beat.UTC()
	}
	m.CreatedAt = created.UTC()
	m.UpdatedAt = updated.UTC()
	return &m, nil
}

// cursor is the keyset a page token encodes: the sort key and the tie-break id.
type cursor struct {
	at *time.Time
	id string
}

// encodeToken renders a cursor as an opaque token. It is opaque on purpose: a
// caller that parsed it would depend on the sort key, which is the store's
// business.
func encodeToken(c cursor) string {
	if c.at == nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString([]byte(c.at.UTC().Format(time.RFC3339Nano) + "\x00" + c.id))
}

// decodeToken parses a page token. An unparseable token is an error rather
// than a silent restart from the first page, which would loop a client forever.
func decodeToken(token string) (cursor, error) {
	if token == "" {
		return cursor{}, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return cursor{}, fmt.Errorf("%w: page token is not readable", ErrInvalid)
	}
	at, id, found := cutAtNUL(string(raw))
	if !found {
		return cursor{}, fmt.Errorf("%w: page token is not readable", ErrInvalid)
	}
	ts, err := time.Parse(time.RFC3339Nano, at)
	if err != nil {
		return cursor{}, fmt.Errorf("%w: page token is not readable", ErrInvalid)
	}
	return cursor{at: &ts, id: id}, nil
}

func cutAtNUL(s string) (before, after string, found bool) {
	for i := range len(s) {
		if s[i] == 0 {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}

// trimPage cuts the extra row the query asked for and turns it into the next
// token. Querying size+1 is how a page knows there is more without a second
// count query.
func trimPage[T any](rows []T, size int32, key func(T) cursor) (page []T, nextToken string, err error) {
	// size is a clamped page size, so it is small and positive; the query asked
	// for size+1 rows, so len(rows) is bounded by it too.
	if len(rows) <= int(size) {
		return rows, "", nil
	}
	last := rows[size-1]
	return rows[:size], encodeToken(key(last)), nil
}

// GetMember returns one member by id.
func (s *postgresStore) GetMember(ctx context.Context, tenantID, memberID string) (*Member, error) {
	if memberID == "" {
		return nil, fmt.Errorf("%w: no member id", ErrNotFound)
	}
	c, err := s.conn(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defer c.Release()

	row := c.SQL().QueryRow(ctx, `SELECT `+memberColumns+` FROM bank_members WHERE id = $1`, memberID)
	m, err := scanMember(row)
	if errors.Is(err, datapool.ErrNoRows) {
		return nil, fmt.Errorf("%w: member %s", ErrNotFound, memberID)
	}
	if err != nil {
		return nil, fmt.Errorf("bank: get member %s: %w", memberID, err)
	}
	return m, nil
}

// MemberByRun returns the member a mission run backs.
//
// The run id is the join: it comes from the verified grant on the request, so a
// caller cannot name a member it is not. A run with no member row is not an
// error to explain — it simply is not a member.
func (s *postgresStore) MemberByRun(ctx context.Context, tenantID, missionRunID string) (*Member, error) {
	if missionRunID == "" {
		return nil, fmt.Errorf("%w: no mission run", ErrNotFound)
	}
	c, err := s.conn(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defer c.Release()

	row := c.SQL().QueryRow(ctx,
		`SELECT `+memberColumns+` FROM bank_members WHERE mission_run_id = $1`, missionRunID)
	m, err := scanMember(row)
	if errors.Is(err, datapool.ErrNoRows) {
		return nil, fmt.Errorf("%w: run %s backs no member", ErrNotFound, missionRunID)
	}
	if err != nil {
		return nil, fmt.Errorf("bank: member by run %s: %w", missionRunID, err)
	}
	return m, nil
}

// ListAll returns every bank of the tenant, oldest first. The reconciler reads
// the whole set on each pass: a page would make it reconcile part of a tenant
// and call the pass done.
func (s *postgresStore) ListAll(ctx context.Context, tenantID string) ([]*Bank, error) {
	c, err := s.conn(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defer c.Release()

	rows, err := c.SQL().Query(ctx, `SELECT `+bankColumns+` FROM banks ORDER BY created_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("bank: list all: %w", err)
	}
	defer rows.Close()

	out := []*Bank{}
	for rows.Next() {
		b, scanErr := scanBank(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("bank: list all scan: %w", scanErr)
		}
		out = append(out, b)
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("bank: list all rows: %w", rows.Err())
	}
	return out, nil
}

// AddMember records a member the reconciler launched.
func (s *postgresStore) AddMember(ctx context.Context, tenantID string, m *Member) error {
	if m == nil || m.ID == "" || m.BankID == "" {
		return fmt.Errorf("%w: a member needs an id and a bank", ErrInvalid)
	}
	c, err := s.conn(ctx, tenantID)
	if err != nil {
		return err
	}
	defer c.Release()

	ids := m.ActiveJobIDs
	if ids == nil {
		ids = []string{}
	}
	_, err = c.SQL().Exec(ctx,
		`INSERT INTO bank_members (id, bank_id, mission_id, mission_run_id, agent_run_id,
		   sandbox_id, state, jobs_in_flight, job_cap, active_job_ids, claude_version)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		m.ID, m.BankID, m.MissionID, m.MissionRunID, m.AgentRunID, m.SandboxID,
		string(m.State), m.JobsInFlight, m.JobCap, ids, m.ClaudeVersion)
	if err != nil {
		if errors.Is(err, datapool.ErrUniqueViolation) {
			return fmt.Errorf("%w: member %s", ErrAlreadyExists, m.ID)
		}
		return fmt.Errorf("bank: insert member %s: %w", m.ID, err)
	}
	return nil
}

// UpdateMemberStatus records what a member reported, and stamps the heartbeat.
//
// The state a member may report is its own view: idle, busy or needs sign-in.
// It cannot report LAUNCHING, DRAINING or DEAD, because those are the daemon's
// decisions about the member rather than the member's about itself.
func (s *postgresStore) UpdateMemberStatus(ctx context.Context, tenantID, memberID string, status MemberStatus) (*Member, error) {
	if !isReportableState(status.State) {
		return nil, fmt.Errorf("%w: a member reports %s, %s or %s, never %q",
			ErrInvalid, MemberIdle, MemberBusy, MemberNeedsSignIn, status.State)
	}
	c, err := s.conn(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defer c.Release()

	ids := status.ActiveJobIDs
	if ids == nil {
		ids = []string{}
	}
	// A DRAINING member keeps that state: the daemon asked it to stop taking
	// work, and a heartbeat saying "idle" must not undo the decision.
	row := c.SQL().QueryRow(ctx,
		`UPDATE bank_members SET
		   state = CASE WHEN state = $7 THEN state ELSE $2 END,
		   jobs_in_flight = $3, job_cap = $4, active_job_ids = $5, claude_version = $6,
		   last_heartbeat = now(), updated_at = now()
		 WHERE id = $1
		 RETURNING `+memberColumns,
		memberID, string(status.State), status.JobsInFlight, status.JobCap, ids,
		status.ClaudeVersion, string(MemberDraining))
	m, err := scanMember(row)
	if errors.Is(err, datapool.ErrNoRows) {
		return nil, fmt.Errorf("%w: member %s", ErrNotFound, memberID)
	}
	if err != nil {
		return nil, fmt.Errorf("bank: update member %s: %w", memberID, err)
	}
	return m, nil
}

// SetMemberState moves a member the daemon decides about.
func (s *postgresStore) SetMemberState(ctx context.Context, tenantID, memberID string, state MemberState) (*Member, error) {
	if !IsMemberState(state) {
		return nil, fmt.Errorf("%w: member state %q", ErrInvalid, state)
	}
	c, err := s.conn(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defer c.Release()

	row := c.SQL().QueryRow(ctx,
		`UPDATE bank_members SET state = $2, updated_at = now() WHERE id = $1 RETURNING `+memberColumns,
		memberID, string(state))
	m, err := scanMember(row)
	if errors.Is(err, datapool.ErrNoRows) {
		return nil, fmt.Errorf("%w: member %s", ErrNotFound, memberID)
	}
	if err != nil {
		return nil, fmt.Errorf("bank: set member state %s: %w", memberID, err)
	}
	return m, nil
}

// RemoveMember deletes a member row after its sandbox is gone.
func (s *postgresStore) RemoveMember(ctx context.Context, tenantID, memberID string) error {
	c, err := s.conn(ctx, tenantID)
	if err != nil {
		return err
	}
	defer c.Release()

	n, err := c.SQL().Exec(ctx, `DELETE FROM bank_members WHERE id = $1`, memberID)
	if err != nil {
		return fmt.Errorf("bank: remove member %s: %w", memberID, err)
	}
	if n == 0 {
		return fmt.Errorf("%w: member %s", ErrNotFound, memberID)
	}
	return nil
}
