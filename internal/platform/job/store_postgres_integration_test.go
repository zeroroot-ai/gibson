// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build integration
// +build integration

// store_postgres_integration_test.go exercises the job store against a real
// Postgres (testcontainers), running the shipped migrations rather than a copy
// of them — so the test proves the migrations and the DAO agree.
//
// Skipped when Docker is unavailable (testhelpers.StartPostgresTLS owns the skip).
package job_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/platform/job"
	"github.com/zeroroot-ai/gibson/tests/testhelpers"
	jobpb "github.com/zeroroot-ai/sdk/api/gen/gibson/job/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

const intTenant = "acme"

type tenantPool struct{ pg *pgxpool.Pool }

func (p *tenantPool) For(_ context.Context, tenant auth.TenantID) (*datapool.Conn, error) {
	return &datapool.Conn{Tenant: tenant, Postgres: p.pg}, nil
}
func (p *tenantPool) Admin(context.Context) (*datapool.AdminConn, error) { return nil, nil }
func (p *tenantPool) SetAdminPool(datapool.AdminAcquirer)                {}
func (p *tenantPool) Close() error                                       { return nil }

// newJobStore stands up Postgres, applies migrations 010 and 011, and seeds one
// bank with two members, because a job is always opened on a bank and claimed
// by a member.
func newJobStore(t *testing.T) (job.Store, *pgxpool.Pool, string) {
	t.Helper()
	ctx := context.Background()

	pgTLS := testhelpers.StartPostgresTLS(t, testhelpers.PostgresOptions{
		User: "testuser", Password: "testpass", Database: "testdb",
	})
	var pool *pgxpool.Pool
	require.Eventually(t, func() bool {
		var err error
		pool, err = pgxpool.New(ctx, pgTLS.DSN)
		if err != nil {
			return false
		}
		return pool.Ping(ctx) == nil
	}, 30*time.Second, 200*time.Millisecond, "Postgres not ready")
	t.Cleanup(pool.Close)

	base := filepath.Join("..", "..", "..", "pkg", "platform", "migrations", "postgres", "tenant")
	for _, name := range []string{"010_banks.up.sql", "011_jobs.up.sql"} {
		up, err := os.ReadFile(filepath.Join(base, name))
		require.NoError(t, err, "read %s", name)
		_, err = pool.Exec(ctx, string(up))
		require.NoError(t, err, "apply %s", name)
	}

	const bankID = "bank-1"
	_, err := pool.Exec(ctx,
		`INSERT INTO banks (id, name, owner_kind, owner_id, login_shape) VALUES ($1,'nightly','user','alice','api_key')`,
		bankID)
	require.NoError(t, err)
	for _, id := range []string{"m-1", "m-2"} {
		_, err = pool.Exec(ctx,
			`INSERT INTO bank_members (id, bank_id, state, jobs_in_flight, job_cap) VALUES ($1,$2,'idle',0,1)`,
			id, bankID)
		require.NoError(t, err)
	}
	return job.NewPostgresStore(&tenantPool{pg: pool}), pool, bankID
}

func spec(goal string) *jobpb.JobSpec {
	return &jobpb.JobSpec{
		Goal: goal,
		Repositories: []*jobpb.RepositorySpec{{
			Name: "app", ConnectorRef: "connector/gitlab", Project: "group/app",
			Deliverable: jobpb.DeliverableKind_DELIVERABLE_KIND_MERGE_REQUEST,
		}},
		CredentialNames: []string{"gitlab-token"},
	}
}

func opener() job.Principal {
	return job.Principal{Kind: job.PrincipalUser, ID: "alice"}
}

func TestJobStore_OpenSendClose(t *testing.T) {
	store, pool, bankID := newJobStore(t)
	ctx := context.Background()

	opened, err := store.Open(ctx, intTenant, job.OpenInput{BankID: bankID, Spec: spec("fix it"), OpenedBy: opener()})
	require.NoError(t, err)
	assert.Equal(t, job.StateOpen, opened.State)
	assert.Empty(t, opened.MemberID, "an unpinned job waits in the queue")

	got, err := store.Get(ctx, intTenant, opened.ID)
	require.NoError(t, err)
	assert.Equal(t, "fix it", got.Spec.GetGoal(), "the spec round-trips whole")
	assert.Len(t, got.Spec.GetRepositories(), 1)

	in, err := store.Send(ctx, intTenant, job.SendInput{
		JobID: opened.ID, Message: "try the patch", Sender: opener(),
	})
	require.NoError(t, err)
	assert.Equal(t, int64(1), in.Seq)
	assert.Equal(t, job.InputTurn, in.Kind)

	working, err := store.Get(ctx, intTenant, opened.ID)
	require.NoError(t, err)
	assert.Equal(t, job.StateWorking, working.State, "an input puts the job back to work")

	closed, err := store.Close(ctx, intTenant, job.CloseInput{
		JobID: opened.ID, Verdict: job.VerdictAccomplished, Score: 0.95, Closer: opener(),
	})
	require.NoError(t, err)
	assert.Equal(t, job.StateClosed, closed.State)
	assert.Equal(t, job.VerdictAccomplished, closed.Verdict)
	assert.InDelta(t, 0.95, closed.Score, 0.0001)
	assert.False(t, closed.ClosedAt.IsZero())

	// The close appends the wrap-up turn: the deliverables happen in it.
	var kind string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT kind FROM job_inputs WHERE job_id = $1 ORDER BY seq DESC LIMIT 1`, opened.ID).Scan(&kind))
	assert.Equal(t, string(job.InputWrapUp), kind)

	_, err = store.Close(ctx, intTenant, job.CloseInput{
		JobID: opened.ID, Verdict: job.VerdictFailed, Closer: opener(),
	})
	assert.ErrorIs(t, err, job.ErrClosed, "one job, one verdict")

	_, err = store.Send(ctx, intTenant, job.SendInput{JobID: opened.ID, Message: "more", Sender: opener()})
	assert.ErrorIs(t, err, job.ErrClosed)
}

func TestJobStore_UnknownJobIsNotFound(t *testing.T) {
	store, _, _ := newJobStore(t)
	ctx := context.Background()
	_, err := store.Get(ctx, intTenant, "nope")
	assert.ErrorIs(t, err, job.ErrNotFound)
	_, err = store.Send(ctx, intTenant, job.SendInput{JobID: "nope", Message: "x", Sender: opener()})
	assert.ErrorIs(t, err, job.ErrNotFound)
	_, err = store.Close(ctx, intTenant, job.CloseInput{JobID: "nope", Verdict: job.VerdictFailed, Closer: opener()})
	assert.ErrorIs(t, err, job.ErrNotFound)
}

// TestJobStore_QueueHandsEachJobToOneMember is the queue property the design
// turns on: two members, three jobs, a cap of one each — the third job waits,
// and the member that frees a slot takes it.
func TestJobStore_QueueHandsEachJobToOneMember(t *testing.T) {
	store, pool, bankID := newJobStore(t)
	ctx := context.Background()

	var ids []string
	for _, goal := range []string{"one", "two", "three"} {
		j, err := store.Open(ctx, intTenant, job.OpenInput{BankID: bankID, Spec: spec(goal), OpenedBy: opener()})
		require.NoError(t, err)
		ids = append(ids, j.ID)
		time.Sleep(2 * time.Millisecond)
	}

	first, err := store.Claim(ctx, intTenant, bankID, "m-1")
	require.NoError(t, err)
	require.NotNil(t, first)
	assert.Equal(t, ids[0], first.ID, "the queue is first in, first out")
	// The reconciler keeps jobs_in_flight; the queue reads it.
	_, err = pool.Exec(ctx, `UPDATE bank_members SET jobs_in_flight = 1 WHERE id = 'm-1'`)
	require.NoError(t, err)

	second, err := store.Claim(ctx, intTenant, bankID, "m-2")
	require.NoError(t, err)
	require.NotNil(t, second)
	assert.Equal(t, ids[1], second.ID)
	_, err = pool.Exec(ctx, `UPDATE bank_members SET jobs_in_flight = 1 WHERE id = 'm-2'`)
	require.NoError(t, err)

	// Both members are at their cap, so the third job waits.
	_, err = store.Claim(ctx, intTenant, bankID, "m-1")
	assert.ErrorIs(t, err, job.ErrNoFreeSlot)

	// m-1 finishes and takes the waiting job.
	_, err = pool.Exec(ctx, `UPDATE bank_members SET jobs_in_flight = 0 WHERE id = 'm-1'`)
	require.NoError(t, err)
	third, err := store.Claim(ctx, intTenant, bankID, "m-1")
	require.NoError(t, err)
	require.NotNil(t, third)
	assert.Equal(t, ids[2], third.ID)

	// An empty queue is the ordinary case, not an error.
	_, err = pool.Exec(ctx, `UPDATE bank_members SET jobs_in_flight = 0 WHERE id = 'm-2'`)
	require.NoError(t, err)
	empty, err := store.Claim(ctx, intTenant, bankID, "m-2")
	require.NoError(t, err)
	assert.Nil(t, empty)
}

// TestJobStore_UnacknowledgedInputRedelivers is the reconnect property: an
// input the member never acknowledged comes back once, and an acknowledged one
// does not.
func TestJobStore_UnacknowledgedInputRedelivers(t *testing.T) {
	store, pool, bankID := newJobStore(t)
	ctx := context.Background()

	j, err := store.Open(ctx, intTenant, job.OpenInput{
		BankID: bankID, MemberID: "m-1", Spec: spec("fix it"), OpenedBy: opener(),
	})
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `UPDATE bank_members SET jobs_in_flight = 1 WHERE id = 'm-1'`)
	require.NoError(t, err)

	first, err := store.Send(ctx, intTenant, job.SendInput{JobID: j.ID, Message: "one", Sender: opener()})
	require.NoError(t, err)
	second, err := store.Send(ctx, intTenant, job.SendInput{JobID: j.ID, Message: "two", Sender: opener()})
	require.NoError(t, err)

	pending, err := store.PendingInputs(ctx, intTenant, "m-1", 10)
	require.NoError(t, err)
	require.Len(t, pending, 2, "nothing acknowledged yet")
	assert.Equal(t, first.ID, pending[0].ID, "oldest first")

	require.NoError(t, store.Acknowledge(ctx, intTenant, first.ID))
	pending, err = store.PendingInputs(ctx, intTenant, "m-1", 10)
	require.NoError(t, err)
	require.Len(t, pending, 1, "an acknowledged input is not delivered again")
	assert.Equal(t, second.ID, pending[0].ID)

	// A second acknowledgement is a no-op, so a duplicate report cannot reopen
	// a redelivery window.
	require.NoError(t, store.Acknowledge(ctx, intTenant, first.ID))
	require.NoError(t, store.Acknowledge(ctx, intTenant, "no-such-input"))
	pending, err = store.PendingInputs(ctx, intTenant, "m-1", 10)
	require.NoError(t, err)
	assert.Len(t, pending, 1)
}

func TestJobStore_SetStateAndDeliverables(t *testing.T) {
	store, _, bankID := newJobStore(t)
	ctx := context.Background()

	j, err := store.Open(ctx, intTenant, job.OpenInput{BankID: bankID, Spec: spec("fix it"), OpenedBy: opener()})
	require.NoError(t, err)

	waiting, err := store.SetState(ctx, intTenant, j.ID, job.StateWaiting, "sess-1")
	require.NoError(t, err)
	assert.Equal(t, job.StateWaiting, waiting.State)
	assert.Equal(t, "sess-1", waiting.ClaudeSessionID)

	// An empty session id keeps the one already recorded.
	again, err := store.SetState(ctx, intTenant, j.ID, job.StateWorking, "")
	require.NoError(t, err)
	assert.Equal(t, "sess-1", again.ClaudeSessionID)

	// A worker never closes its own job, so SetState refuses the closed state.
	_, err = store.SetState(ctx, intTenant, j.ID, job.StateClosed, "")
	assert.ErrorIs(t, err, job.ErrInvalid)
	_, err = store.SetState(ctx, intTenant, j.ID, "paused", "")
	assert.ErrorIs(t, err, job.ErrInvalid)

	withDeliverable, err := store.AddDeliverable(ctx, intTenant, j.ID, &jobpb.Deliverable{
		Kind: jobpb.DeliverableKind_DELIVERABLE_KIND_MERGE_REQUEST, Ref: "mr-7", Url: "https://forge/mr/7",
	})
	require.NoError(t, err)
	require.Len(t, withDeliverable.Deliverables, 1)
	assert.Equal(t, "mr-7", withDeliverable.Deliverables[0].GetRef())

	_, err = store.AddDeliverable(ctx, intTenant, "nope", &jobpb.Deliverable{Ref: "x"})
	assert.ErrorIs(t, err, job.ErrNotFound)
	_, err = store.AddDeliverable(ctx, intTenant, j.ID, nil)
	assert.ErrorIs(t, err, job.ErrInvalid)
}

func TestJobStore_EventsFollowTheJob(t *testing.T) {
	store, _, bankID := newJobStore(t)
	ctx := context.Background()

	j, err := store.Open(ctx, intTenant, job.OpenInput{BankID: bankID, Spec: spec("fix it"), OpenedBy: opener()})
	require.NoError(t, err)
	_, err = store.Send(ctx, intTenant, job.SendInput{JobID: j.ID, Message: "go", Sender: opener()})
	require.NoError(t, err)
	_, err = store.AddDeliverable(ctx, intTenant, j.ID, &jobpb.Deliverable{
		Kind: jobpb.DeliverableKind_DELIVERABLE_KIND_PUSH_BRANCH, Ref: "job/1",
	})
	require.NoError(t, err)
	_, err = store.Close(ctx, intTenant, job.CloseInput{
		JobID: j.ID, Verdict: job.VerdictAccomplished, Score: 1, Closer: opener(),
	})
	require.NoError(t, err)

	events, err := store.Events(ctx, intTenant, j.ID, 0, 100)
	require.NoError(t, err)
	require.NotEmpty(t, events)
	assert.Equal(t, job.EventOpened, events[0].Kind)
	assert.Equal(t, int64(1), events[0].Seq)
	last := events[len(events)-1]
	assert.Equal(t, job.EventClosed, last.Kind)
	assert.Equal(t, job.VerdictAccomplished, last.Verdict)

	var sawDeliverable bool
	for _, e := range events {
		if e.Kind == job.EventDeliverable {
			require.NotNil(t, e.Deliverable, "a deliverable event carries the deliverable")
			assert.Equal(t, "job/1", e.Deliverable.GetRef())
			sawDeliverable = true
		}
	}
	assert.True(t, sawDeliverable)

	// Resuming from a sequence returns only what came after it.
	after, err := store.Events(ctx, intTenant, j.ID, events[0].Seq, 100)
	require.NoError(t, err)
	assert.Len(t, after, len(events)-1)
}

func TestJobStore_ListFiltersAndPages(t *testing.T) {
	store, _, bankID := newJobStore(t)
	ctx := context.Background()

	for _, goal := range []string{"one", "two", "three"} {
		_, err := store.Open(ctx, intTenant, job.OpenInput{BankID: bankID, Spec: spec(goal), OpenedBy: opener()})
		require.NoError(t, err)
		time.Sleep(2 * time.Millisecond)
	}

	page, next, err := store.List(ctx, intTenant, job.ListFilter{BankID: bankID}, job.Page{Size: 2})
	require.NoError(t, err)
	require.Len(t, page, 2)
	require.NotEmpty(t, next)
	assert.Equal(t, "three", page[0].Spec.GetGoal(), "newest first")

	rest, next2, err := store.List(ctx, intTenant, job.ListFilter{BankID: bankID}, job.Page{Size: 2, Token: next})
	require.NoError(t, err)
	require.Len(t, rest, 1)
	assert.Empty(t, next2)

	none, _, err := store.List(ctx, intTenant, job.ListFilter{BankID: "other"}, job.Page{})
	require.NoError(t, err)
	assert.Empty(t, none)

	open, _, err := store.List(ctx, intTenant, job.ListFilter{State: job.StateOpen}, job.Page{})
	require.NoError(t, err)
	assert.Len(t, open, 3)

	_, _, err = store.List(ctx, intTenant, job.ListFilter{}, job.Page{Token: "!!!"})
	assert.ErrorIs(t, err, job.ErrInvalid)
}

func TestJobStore_StaleJobs(t *testing.T) {
	store, pool, bankID := newJobStore(t)
	ctx := context.Background()

	fresh, err := store.Open(ctx, intTenant, job.OpenInput{BankID: bankID, Spec: spec("fresh"), OpenedBy: opener()})
	require.NoError(t, err)
	old, err := store.Open(ctx, intTenant, job.OpenInput{BankID: bankID, Spec: spec("old"), OpenedBy: opener()})
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `UPDATE jobs SET last_input_at = now() - interval '2 hours' WHERE id = $1`, old.ID)
	require.NoError(t, err)

	stale, err := store.Stale(ctx, intTenant, bankID, 3600, 10)
	require.NoError(t, err)
	require.Len(t, stale, 1)
	assert.Equal(t, old.ID, stale[0].ID)
	assert.NotEqual(t, fresh.ID, stale[0].ID)

	// No limit means nothing is stale: closing every open job of a bank whose
	// owner set no limit would be the opposite of what they asked for.
	none, err := store.Stale(ctx, intTenant, bankID, 0, 10)
	require.NoError(t, err)
	assert.Empty(t, none)

	// A closed job is never stale.
	_, err = store.Close(ctx, intTenant, job.CloseInput{
		JobID: old.ID, Verdict: job.VerdictAbandoned, Closer: opener(),
	})
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `UPDATE jobs SET last_input_at = now() - interval '2 hours' WHERE id = $1`, old.ID)
	require.NoError(t, err)
	after, err := store.Stale(ctx, intTenant, bankID, 3600, 10)
	require.NoError(t, err)
	assert.Empty(t, after)
}

func TestJobStore_PinnedToAFullMemberIsRefused(t *testing.T) {
	store, pool, bankID := newJobStore(t)
	ctx := context.Background()

	_, err := pool.Exec(ctx, `UPDATE bank_members SET jobs_in_flight = 1 WHERE id = 'm-1'`)
	require.NoError(t, err)
	_, err = store.Open(ctx, intTenant, job.OpenInput{
		BankID: bankID, MemberID: "m-1", Spec: spec("fix it"), OpenedBy: opener(),
	})
	assert.ErrorIs(t, err, job.ErrNoFreeSlot)

	_, err = store.Open(ctx, intTenant, job.OpenInput{
		BankID: bankID, MemberID: "ghost", Spec: spec("fix it"), OpenedBy: opener(),
	})
	assert.ErrorIs(t, err, job.ErrNotFound, "a job cannot be pinned to a member that does not exist")
}

func TestJobStore_JobsCascadeWithTheirBank(t *testing.T) {
	store, pool, bankID := newJobStore(t)
	ctx := context.Background()

	j, err := store.Open(ctx, intTenant, job.OpenInput{BankID: bankID, Spec: spec("fix it"), OpenedBy: opener()})
	require.NoError(t, err)
	_, err = store.Send(ctx, intTenant, job.SendInput{JobID: j.ID, Message: "go", Sender: opener()})
	require.NoError(t, err)

	_, err = pool.Exec(ctx, `DELETE FROM banks WHERE id = $1`, bankID)
	require.NoError(t, err)

	for _, table := range []string{"jobs", "job_inputs", "job_events"} {
		var count int
		require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM `+table).Scan(&count))
		assert.Zero(t, count, "%s must cascade with the bank", table)
	}
}
