// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package job

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	jobpb "github.com/zeroroot-ai/sdk/api/gen/gibson/job/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// conn is one tenant's database handle for the life of a call. It is an
// interface for the same reason the bank store's is: the logic a reader has to
// trust — the queue's ordering, the state machine, what a member may report —
// should be testable without a container.
type conn interface {
	SQL() datapool.SQL
	InTx(ctx context.Context, fn func(datapool.SQL) error) error
	Release()
}

// conns hands out a conn per tenant.
type conns interface {
	For(ctx context.Context, tenantID string) (conn, error)
}

// postgresStore keeps jobs, their inputs and their events in the per-tenant
// database (migration 011).
type postgresStore struct {
	conns conns
}

// NewPostgresStore builds the production Store over the per-tenant data pool.
func NewPostgresStore(pool datapool.Pool) Store {
	if pool == nil {
		panic("job: NewPostgresStore: pool must not be nil")
	}
	return &postgresStore{conns: poolConns{pool: pool}}
}

var _ Store = (*postgresStore)(nil)

// poolConns adapts the data-plane pool to conns.
type poolConns struct{ pool datapool.Pool }

func (p poolConns) For(ctx context.Context, tenantID string) (conn, error) {
	tid, err := auth.NewTenantID(tenantID)
	if err != nil {
		return nil, fmt.Errorf("job: invalid tenant %q: %w", tenantID, err)
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
		return nil, fmt.Errorf("job: %w", err)
	}
	return c, nil
}

const jobColumns = `id, bank_id, member_id, state, spec, claude_session_id,
	opened_by_kind, opened_by_id, opened_at, last_input_at, closed_at,
	verdict, score, deliverables, attempts, spilled`

// Open records a new job. When MemberID names a member, the job is assigned
// only if that member still has a free slot — checked inside the transaction,
// so two concurrent opens cannot both take the last slot.
func (s *postgresStore) Open(ctx context.Context, tenantID string, in OpenInput) (*Job, error) {
	if err := in.Validate(); err != nil {
		return nil, err
	}
	c, err := s.conn(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defer c.Release()

	specJSON, err := protojson.Marshal(in.Spec)
	if err != nil {
		return nil, fmt.Errorf("job: marshal spec: %w", err)
	}
	now := time.Now().UTC()
	j := &Job{
		ID: string(types.NewID()), BankID: in.BankID, MemberID: in.MemberID,
		State: StateOpen, Spec: in.Spec, OpenedBy: in.OpenedBy,
		OpenedAt: now, LastInputAt: now,
	}

	err = c.InTx(ctx, func(tx datapool.SQL) error {
		if in.MemberID != "" {
			free, ferr := memberHasFreeSlot(ctx, tx, in.MemberID)
			if ferr != nil {
				return ferr
			}
			if !free {
				return fmt.Errorf("%w: %s", ErrNoFreeSlot, in.MemberID)
			}
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO jobs (id, bank_id, member_id, state, spec, opened_by_kind, opened_by_id, opened_at, last_input_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			j.ID, j.BankID, j.MemberID, string(j.State), specJSON,
			string(j.OpenedBy.Kind), j.OpenedBy.ID, now, now); err != nil {
			return fmt.Errorf("job: insert: %w", err)
		}
		return appendEvent(ctx, tx, j.ID, EventOpened, eventFields{State: j.State})
	})
	if err != nil {
		return nil, fmt.Errorf("job: transaction: %w", err)
	}
	return j, nil
}

func (s *postgresStore) Get(ctx context.Context, tenantID, id string) (*Job, error) {
	c, err := s.conn(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defer c.Release()

	row := c.SQL().QueryRow(ctx, `SELECT `+jobColumns+` FROM jobs WHERE id = $1`, id)
	j, err := scanJob(row)
	if errors.Is(err, datapool.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	if err != nil {
		return nil, fmt.Errorf("job: get %s: %w", id, err)
	}
	return j, nil
}

func (s *postgresStore) List(ctx context.Context, tenantID string, filter ListFilter, page Page) ([]*Job, string, error) {
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
	rows, err := c.SQL().Query(ctx,
		`SELECT `+jobColumns+` FROM jobs
		 WHERE ($1 = '' OR bank_id = $1)
		   AND ($2 = '' OR member_id = $2)
		   AND ($3 = '' OR state = $3)
		   AND ($4::timestamptz IS NULL OR (opened_at, id) < ($4, $5))
		 ORDER BY opened_at DESC, id DESC
		 LIMIT $6`,
		filter.BankID, filter.MemberID, string(filter.State), after.at, after.id, size+1)
	if err != nil {
		return nil, "", fmt.Errorf("job: list: %w", err)
	}
	defer rows.Close()

	jobs := make([]*Job, 0, size)
	for rows.Next() {
		j, scanErr := scanJob(rows)
		if scanErr != nil {
			return nil, "", fmt.Errorf("job: list scan: %w", scanErr)
		}
		jobs = append(jobs, j)
	}
	if rows.Err() != nil {
		return nil, "", fmt.Errorf("job: list rows: %w", rows.Err())
	}
	return trimPage(jobs, size)
}

// Send appends an input. It runs in a transaction with the state change and
// the event, so a reader never sees an input whose job still reads WAITING.
func (s *postgresStore) Send(ctx context.Context, tenantID string, in SendInput) (*Input, error) {
	if err := in.Validate(); err != nil {
		return nil, err
	}
	c, err := s.conn(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defer c.Release()

	var input *Input
	err = c.InTx(ctx, func(tx datapool.SQL) error {
		var state string
		// FOR UPDATE: two senders must not both read WAITING and both append.
		if serr := tx.QueryRow(ctx, `SELECT state FROM jobs WHERE id = $1 FOR UPDATE`, in.JobID).Scan(&state); serr != nil {
			if errors.Is(serr, datapool.ErrNoRows) {
				return fmt.Errorf("%w: %s", ErrNotFound, in.JobID)
			}
			return fmt.Errorf("job: lock %s: %w", in.JobID, serr)
		}
		// A wrap-up input is the one input a closed job accepts: the daemon
		// sends it right after the close, and it is what makes the
		// deliverables happen.
		if State(state) == StateClosed && in.Kind != InputWrapUp {
			return fmt.Errorf("%w: %s", ErrClosed, in.JobID)
		}

		var aerr error
		input, aerr = appendInput(ctx, tx, in)
		if aerr != nil {
			return aerr
		}
		// An input puts the job back to work. A closed job stays closed: its
		// wrap-up turn is not a state change.
		if State(state) != StateClosed {
			if _, uerr := tx.Exec(ctx,
				`UPDATE jobs SET state = $2, last_input_at = $3, updated_at = now() WHERE id = $1`,
				in.JobID, string(StateWorking), input.SentAt); uerr != nil {
				return fmt.Errorf("job: set working: %w", uerr)
			}
			return appendEvent(ctx, tx, in.JobID, EventState, eventFields{State: StateWorking})
		}
		if _, uerr := tx.Exec(ctx,
			`UPDATE jobs SET last_input_at = $2, updated_at = now() WHERE id = $1`, in.JobID, input.SentAt); uerr != nil {
			return fmt.Errorf("job: touch last input: %w", uerr)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("job: transaction: %w", err)
	}
	return input, nil
}

// Close records the verdict and appends the wrap-up input in one transaction,
// so a job cannot be closed twice and cannot be closed without its wrap-up.
func (s *postgresStore) Close(ctx context.Context, tenantID string, in CloseInput) (*Job, error) {
	if err := in.Validate(); err != nil {
		return nil, err
	}
	c, err := s.conn(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defer c.Release()

	var j *Job
	err = c.InTx(ctx, func(tx datapool.SQL) error {
		var state string
		if serr := tx.QueryRow(ctx, `SELECT state FROM jobs WHERE id = $1 FOR UPDATE`, in.JobID).Scan(&state); serr != nil {
			if errors.Is(serr, datapool.ErrNoRows) {
				return fmt.Errorf("%w: %s", ErrNotFound, in.JobID)
			}
			return fmt.Errorf("job: lock %s: %w", in.JobID, serr)
		}
		if State(state) == StateClosed {
			return fmt.Errorf("%w: %s", ErrClosed, in.JobID)
		}

		now := time.Now().UTC()
		if _, uerr := tx.Exec(ctx,
			`UPDATE jobs SET state = $2, verdict = $3, score = $4, closed_at = $5, updated_at = now() WHERE id = $1`,
			in.JobID, string(StateClosed), string(in.Verdict), in.Score, now); uerr != nil {
			return fmt.Errorf("job: close %s: %w", in.JobID, uerr)
		}
		// The wrap-up turn: commit, push, open the merge request, summarize.
		// It is the daemon's input, never a client's, which is why it is
		// appended here rather than accepted on SendInput.
		if _, aerr := appendInput(ctx, tx, SendInput{
			JobID: in.JobID, Kind: InputWrapUp, Sender: in.Closer,
			Message: "The job is closed with verdict " + string(in.Verdict) +
				". Perform the declared deliverables, then summarize what you did.",
		}); aerr != nil {
			return aerr
		}
		if eerr := appendEvent(ctx, tx, in.JobID, EventClosed, eventFields{
			State: StateClosed, Verdict: in.Verdict, Score: in.Score,
		}); eerr != nil {
			return eerr
		}
		var rerr error
		j, rerr = scanJob(tx.QueryRow(ctx, `SELECT `+jobColumns+` FROM jobs WHERE id = $1`, in.JobID))
		if rerr != nil {
			return fmt.Errorf("job: read back %s: %w", in.JobID, rerr)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("job: transaction: %w", err)
	}
	return j, nil
}

// Claim hands the oldest queued job of a bank to a member.
//
// SKIP LOCKED is what makes the queue safe with many members pulling at once:
// a row another transaction is already taking is skipped rather than waited
// for, so two members never get the same job and neither blocks the other.
func (s *postgresStore) Claim(ctx context.Context, tenantID, bankID, memberID string) (*Job, error) {
	c, err := s.conn(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defer c.Release()

	// An empty queue leaves j nil and the transaction commits: taking nothing
	// is the ordinary case, not a failure, and the caller reads it as nil.
	var j *Job
	err = c.InTx(ctx, func(tx datapool.SQL) error {
		free, ferr := memberHasFreeSlot(ctx, tx, memberID)
		if ferr != nil {
			return ferr
		}
		if !free {
			return fmt.Errorf("%w: %s", ErrNoFreeSlot, memberID)
		}

		var id string
		serr := tx.QueryRow(ctx,
			`SELECT id FROM jobs
			 WHERE bank_id = $1 AND member_id = '' AND state <> $2
			 ORDER BY opened_at ASC
			 LIMIT 1 FOR UPDATE SKIP LOCKED`, bankID, string(StateClosed)).Scan(&id)
		if errors.Is(serr, datapool.ErrNoRows) {
			return nil
		}
		if serr != nil {
			return fmt.Errorf("job: claim from %s: %w", bankID, serr)
		}
		if _, uerr := tx.Exec(ctx,
			`UPDATE jobs SET member_id = $2, updated_at = now() WHERE id = $1`, id, memberID); uerr != nil {
			return fmt.Errorf("job: assign %s: %w", id, uerr)
		}
		var rerr error
		j, rerr = scanJob(tx.QueryRow(ctx, `SELECT `+jobColumns+` FROM jobs WHERE id = $1`, id))
		if rerr != nil {
			return fmt.Errorf("job: read back %s: %w", id, rerr)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("job: transaction: %w", err)
	}
	return j, nil
}

func (s *postgresStore) PendingInputs(ctx context.Context, tenantID, memberID string, limit int32) ([]*Input, error) {
	c, err := s.conn(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defer c.Release()

	rows, err := c.SQL().Query(ctx,
		`SELECT i.id, i.job_id, i.seq, i.kind, i.message, i.sender_kind, i.sender_id, i.sent_at, i.acknowledged_at
		 FROM job_inputs i JOIN jobs j ON j.id = i.job_id
		 WHERE j.member_id = $1 AND i.acknowledged_at IS NULL
		 ORDER BY i.sent_at ASC, i.seq ASC
		 LIMIT $2`, memberID, clampPageSize(limit))
	if err != nil {
		return nil, fmt.Errorf("job: pending inputs for %s: %w", memberID, err)
	}
	defer rows.Close()

	out := []*Input{}
	for rows.Next() {
		in, scanErr := scanInput(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("job: pending input scan: %w", scanErr)
		}
		out = append(out, in)
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("job: pending input rows: %w", rows.Err())
	}
	return out, nil
}

func (s *postgresStore) Acknowledge(ctx context.Context, tenantID, inputID string) error {
	c, err := s.conn(ctx, tenantID)
	if err != nil {
		return err
	}
	defer c.Release()

	// Only the first acknowledgement wins, so a duplicate report does not move
	// the timestamp and a redelivery window cannot be reopened.
	affected, err := c.SQL().Exec(ctx,
		`UPDATE job_inputs SET acknowledged_at = now() WHERE id = $1 AND acknowledged_at IS NULL`, inputID)
	if err != nil {
		return fmt.Errorf("job: acknowledge %s: %w", inputID, err)
	}
	if affected == 0 {
		// Either it is already acknowledged or it never existed. Both mean the
		// caller has nothing left to do.
		return nil
	}
	return nil
}

func (s *postgresStore) SetState(ctx context.Context, tenantID, jobID string, state State, claudeSessionID string) (*Job, error) {
	if !IsState(state) {
		return nil, fmt.Errorf("%w: state %q is not one of open, working, waiting, closed", ErrInvalid, state)
	}
	if state == StateClosed {
		// Only a scorer closes a job. Letting SetState do it would give the
		// worker the one thing ADR-0019 takes away from it.
		return nil, fmt.Errorf("%w: a job is closed by a scorer through Close, never by a reported state", ErrInvalid)
	}
	c, err := s.conn(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defer c.Release()

	var j *Job
	err = c.InTx(ctx, func(tx datapool.SQL) error {
		var current string
		if serr := tx.QueryRow(ctx, `SELECT state FROM jobs WHERE id = $1 FOR UPDATE`, jobID).Scan(&current); serr != nil {
			if errors.Is(serr, datapool.ErrNoRows) {
				return fmt.Errorf("%w: %s", ErrNotFound, jobID)
			}
			return fmt.Errorf("job: lock %s: %w", jobID, serr)
		}
		if State(current) == StateClosed {
			return fmt.Errorf("%w: %s", ErrClosed, jobID)
		}
		if _, uerr := tx.Exec(ctx,
			`UPDATE jobs SET state = $2,
			   claude_session_id = CASE WHEN $3 = '' THEN claude_session_id ELSE $3 END,
			   updated_at = now()
			 WHERE id = $1`, jobID, string(state), claudeSessionID); uerr != nil {
			return fmt.Errorf("job: set state %s: %w", jobID, uerr)
		}
		if eerr := appendEvent(ctx, tx, jobID, EventState, eventFields{State: state}); eerr != nil {
			return eerr
		}
		var rerr error
		j, rerr = scanJob(tx.QueryRow(ctx, `SELECT `+jobColumns+` FROM jobs WHERE id = $1`, jobID))
		if rerr != nil {
			return fmt.Errorf("job: read back %s: %w", jobID, rerr)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("job: transaction: %w", err)
	}
	return j, nil
}

func (s *postgresStore) AddDeliverable(ctx context.Context, tenantID, jobID string, d *jobpb.Deliverable) (*Job, error) {
	if d == nil {
		return nil, fmt.Errorf("%w: a deliverable is required", ErrInvalid)
	}
	c, err := s.conn(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defer c.Release()

	payload, err := protojson.Marshal(d)
	if err != nil {
		return nil, fmt.Errorf("job: marshal deliverable: %w", err)
	}

	var j *Job
	err = c.InTx(ctx, func(tx datapool.SQL) error {
		affected, uerr := tx.Exec(ctx,
			`UPDATE jobs SET deliverables = deliverables || $2::jsonb, updated_at = now() WHERE id = $1`,
			jobID, payload)
		if uerr != nil {
			return fmt.Errorf("job: add deliverable to %s: %w", jobID, uerr)
		}
		if affected == 0 {
			return fmt.Errorf("%w: %s", ErrNotFound, jobID)
		}
		if eerr := appendEvent(ctx, tx, jobID, EventDeliverable, eventFields{Payload: payload}); eerr != nil {
			return eerr
		}
		var rerr error
		j, rerr = scanJob(tx.QueryRow(ctx, `SELECT `+jobColumns+` FROM jobs WHERE id = $1`, jobID))
		if rerr != nil {
			return fmt.Errorf("job: read back %s: %w", jobID, rerr)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("job: transaction: %w", err)
	}
	return j, nil
}

func (s *postgresStore) Events(ctx context.Context, tenantID, jobID string, since int64, limit int32) ([]*Event, error) {
	c, err := s.conn(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defer c.Release()

	rows, err := c.SQL().Query(ctx,
		`SELECT job_id, seq, kind, occurred_at, state, verdict, score, message, payload
		 FROM job_events WHERE job_id = $1 AND seq > $2 ORDER BY seq ASC LIMIT $3`,
		jobID, since, clampPageSize(limit))
	if err != nil {
		return nil, fmt.Errorf("job: events of %s: %w", jobID, err)
	}
	defer rows.Close()

	out := []*Event{}
	for rows.Next() {
		e, scanErr := scanEvent(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("job: event scan: %w", scanErr)
		}
		out = append(out, e)
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("job: event rows: %w", rows.Err())
	}
	return out, nil
}

// ReleaseMember hands a member's open jobs back to the queue. The state and
// the Claude session id stay, so the member that pulls the job next restores
// the transcript rather than starts over.
func (s *postgresStore) ReleaseMember(ctx context.Context, tenantID, memberID string) (int64, error) {
	if memberID == "" {
		return 0, fmt.Errorf("%w: release needs a member", ErrInvalid)
	}
	c, err := s.conn(ctx, tenantID)
	if err != nil {
		return 0, err
	}
	defer c.Release()

	n, err := c.SQL().Exec(ctx,
		`UPDATE jobs SET member_id = '', updated_at = now()
		 WHERE member_id = $1 AND state <> $2`, memberID, string(StateClosed))
	if err != nil {
		return 0, fmt.Errorf("job: release member %s: %w", memberID, err)
	}
	return n, nil
}

func (s *postgresStore) Stale(ctx context.Context, tenantID, bankID string, staleSeconds int64, limit int32) ([]*Job, error) {
	if staleSeconds <= 0 {
		// No limit means nothing is stale. Returning everything would close
		// every open job of a bank whose owner set no limit.
		return nil, nil
	}
	c, err := s.conn(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defer c.Release()

	rows, err := c.SQL().Query(ctx,
		`SELECT `+jobColumns+` FROM jobs
		 WHERE bank_id = $1 AND state <> $2
		   AND last_input_at < now() - make_interval(secs => $3)
		 ORDER BY last_input_at ASC LIMIT $4`,
		bankID, string(StateClosed), staleSeconds, clampPageSize(limit))
	if err != nil {
		return nil, fmt.Errorf("job: stale jobs of %s: %w", bankID, err)
	}
	defer rows.Close()

	out := []*Job{}
	for rows.Next() {
		j, scanErr := scanJob(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("job: stale scan: %w", scanErr)
		}
		out = append(out, j)
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("job: stale rows: %w", rows.Err())
	}
	return out, nil
}

// ---- shared statements -----------------------------------------------------

// memberHasFreeSlot reports whether a member holds fewer jobs than its cap.
// It reads bank_members, which the reconciler keeps current, so the queue and
// the reconciler agree on what "free" means.
func memberHasFreeSlot(ctx context.Context, tx datapool.SQL, memberID string) (bool, error) {
	var inFlight, slots int32
	err := tx.QueryRow(ctx,
		`SELECT jobs_in_flight, job_cap FROM bank_members WHERE id = $1 FOR UPDATE`, memberID).
		Scan(&inFlight, &slots)
	if errors.Is(err, datapool.ErrNoRows) {
		return false, fmt.Errorf("%w: member %s", ErrNotFound, memberID)
	}
	if err != nil {
		return false, fmt.Errorf("job: read member %s: %w", memberID, err)
	}
	return inFlight < slots, nil
}

// appendInput writes one input with the next per-job sequence number.
func appendInput(ctx context.Context, tx datapool.SQL, in SendInput) (*Input, error) {
	now := time.Now().UTC()
	input := &Input{
		ID: string(types.NewID()), JobID: in.JobID, Kind: in.Kind,
		Message: in.Message, Sender: in.Sender, SentAt: now,
	}
	err := tx.QueryRow(ctx,
		`INSERT INTO job_inputs (id, job_id, seq, kind, message, sender_kind, sender_id, sent_at)
		 VALUES ($1, $2,
		   (SELECT COALESCE(MAX(seq), 0) + 1 FROM job_inputs WHERE job_id = $2),
		   $3, $4, $5, $6, $7)
		 RETURNING seq`,
		input.ID, in.JobID, string(in.Kind), in.Message,
		string(in.Sender.Kind), in.Sender.ID, now).Scan(&input.Seq)
	if err != nil {
		return nil, fmt.Errorf("job: append input to %s: %w", in.JobID, err)
	}
	if err := appendEvent(ctx, tx, in.JobID, EventInput, eventFields{InputID: input.ID}); err != nil {
		return nil, err
	}
	return input, nil
}

// eventFields is what an appended event carries beyond its kind.
type eventFields struct {
	State   State
	Verdict Verdict
	Score   float64
	Message string
	InputID string
	Payload []byte
}

// appendEvent writes one event with the next per-job sequence number. The
// sequence is computed in the same statement, under the row lock the caller
// already holds, so two writers cannot produce the same seq.
func appendEvent(ctx context.Context, tx datapool.SQL, jobID string, kind EventKind, f eventFields) error {
	payload := f.Payload
	if f.InputID != "" {
		payload = []byte(`{"input_id":"` + f.InputID + `"}`)
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO job_events (job_id, seq, kind, state, verdict, score, message, payload)
		 VALUES ($1,
		   (SELECT COALESCE(MAX(seq), 0) + 1 FROM job_events WHERE job_id = $1),
		   $2, $3, $4, $5, $6, $7)`,
		jobID, string(kind), string(f.State), string(f.Verdict), f.Score, f.Message, payload)
	if err != nil {
		return fmt.Errorf("job: append %s event to %s: %w", kind, jobID, err)
	}
	return nil
}

// ---- scanning --------------------------------------------------------------

type scanner interface {
	Scan(dest ...any) error
}

func scanJob(row scanner) (*Job, error) {
	var (
		j            Job
		state        string
		specJSON     []byte
		openedKind   string
		verdict      string
		deliverables []byte
		closedAt     *time.Time
		openedAt     time.Time
		lastInputAt  time.Time
	)
	if err := row.Scan(&j.ID, &j.BankID, &j.MemberID, &state, &specJSON, &j.ClaudeSessionID,
		&openedKind, &j.OpenedBy.ID, &openedAt, &lastInputAt, &closedAt,
		&verdict, &j.Score, &deliverables, &j.Attempts, &j.Spilled); err != nil {
		return nil, fmt.Errorf("scan job row: %w", err)
	}
	j.State = State(state)
	j.OpenedBy.Kind = PrincipalKind(openedKind)
	j.Verdict = Verdict(verdict)
	j.OpenedAt = openedAt.UTC()
	j.LastInputAt = lastInputAt.UTC()
	if closedAt != nil {
		j.ClosedAt = closedAt.UTC()
	}
	spec := &jobpb.JobSpec{}
	if err := protojson.Unmarshal(specJSON, spec); err != nil {
		return nil, fmt.Errorf("unmarshal spec of %s: %w", j.ID, err)
	}
	j.Spec = spec
	ds, err := unmarshalDeliverables(deliverables)
	if err != nil {
		return nil, fmt.Errorf("unmarshal deliverables of %s: %w", j.ID, err)
	}
	j.Deliverables = ds
	return &j, nil
}

func scanInput(row scanner) (*Input, error) {
	var (
		in         Input
		kind       string
		senderKind string
		sentAt     time.Time
		ackedAt    *time.Time
	)
	if err := row.Scan(&in.ID, &in.JobID, &in.Seq, &kind, &in.Message,
		&senderKind, &in.Sender.ID, &sentAt, &ackedAt); err != nil {
		return nil, fmt.Errorf("scan input row: %w", err)
	}
	in.Kind = InputKind(kind)
	in.Sender.Kind = PrincipalKind(senderKind)
	in.SentAt = sentAt.UTC()
	if ackedAt != nil {
		in.AcknowledgedAt = ackedAt.UTC()
	}
	return &in, nil
}

func scanEvent(row scanner) (*Event, error) {
	var (
		e          Event
		kind       string
		state      string
		verdict    string
		occurredAt time.Time
		payload    []byte
	)
	if err := row.Scan(&e.JobID, &e.Seq, &kind, &occurredAt, &state, &verdict,
		&e.Score, &e.Message, &payload); err != nil {
		return nil, fmt.Errorf("scan event row: %w", err)
	}
	e.Kind = EventKind(kind)
	e.State = State(state)
	e.Verdict = Verdict(verdict)
	e.OccurredAt = occurredAt.UTC()
	if e.Kind == EventDeliverable && len(payload) > 0 {
		d := &jobpb.Deliverable{}
		if err := protojson.Unmarshal(payload, d); err != nil {
			return nil, fmt.Errorf("unmarshal deliverable event of %s: %w", e.JobID, err)
		}
		e.Deliverable = d
	}
	return &e, nil
}

// unmarshalDeliverables decodes the stored JSON array of Deliverable messages.
func unmarshalDeliverables(raw []byte) ([]*jobpb.Deliverable, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	// protojson has no list form, so the array is decoded through a wrapper
	// message field rather than by hand-parsing JSON.
	wrapper := &jobpb.Job{}
	if err := protojson.Unmarshal([]byte(`{"deliverables":`+string(raw)+`}`), wrapper); err != nil {
		return nil, fmt.Errorf("decode stored deliverables: %w", err)
	}
	return wrapper.GetDeliverables(), nil
}

// ---- paging ----------------------------------------------------------------

type cursor struct {
	at *time.Time
	id string
}

func encodeToken(c cursor) string {
	if c.at == nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString([]byte(c.at.UTC().Format(time.RFC3339Nano) + "\x00" + c.id))
}

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

func trimPage(rows []*Job, size int32) (page []*Job, nextToken string, err error) {
	// size is a clamped page size, so it is small and positive.
	if len(rows) <= int(size) {
		return rows, "", nil
	}
	last := rows[size-1]
	return rows[:size], encodeToken(cursor{at: &last.OpenedAt, id: last.ID}), nil
}
