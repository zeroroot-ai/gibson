-- 011_jobs.up.sql
--
-- Jobs, their inputs and their event log (ADR-0019, gibson#1710).
--
-- jobs        — one persistent Claude Code session on a bank member.
-- job_inputs  — the messages sent to a job, in order. The member pulls them
--               outbound and acknowledges each, so an input survives a
--               reconnect and is delivered again exactly once.
-- job_events  — the append-only log StreamJobEvents replays and follows.
--
-- Per-tenant database, so there is no tenant_id column (migration 010).

CREATE TABLE IF NOT EXISTS jobs (
    id                TEXT        PRIMARY KEY,
    bank_id           TEXT        NOT NULL REFERENCES banks(id) ON DELETE CASCADE,
    -- Empty while the job waits in the bank queue.
    member_id         TEXT        NOT NULL DEFAULT '',
    state             TEXT        NOT NULL,
    -- The JobSpec as protojson. The daemon reads repositories and
    -- credential_names out of it to mint a per-turn grant; it is stored whole
    -- so a member sees exactly what the opener declared.
    spec              JSONB       NOT NULL,
    claude_session_id TEXT        NOT NULL DEFAULT '',
    opened_by_kind    TEXT        NOT NULL,
    opened_by_id      TEXT        NOT NULL,
    opened_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_input_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    closed_at         TIMESTAMPTZ,
    verdict           TEXT        NOT NULL DEFAULT '',
    score             DOUBLE PRECISION NOT NULL DEFAULT 0,
    -- Deliverables as protojson, appended by the member at wrap-up.
    deliverables      JSONB       NOT NULL DEFAULT '[]'::jsonb,
    attempts          INTEGER     NOT NULL DEFAULT 0,
    -- True when the bank spilled this job to a one-shot launch instead of
    -- queueing it.
    spilled           BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The queue read: the oldest unassigned job of one bank. Partial, because the
-- queue only ever asks about jobs with no member.
CREATE INDEX IF NOT EXISTS jobs_queue_idx
    ON jobs (bank_id, opened_at)
    WHERE member_id = '';

CREATE INDEX IF NOT EXISTS jobs_member_idx ON jobs (member_id);
CREATE INDEX IF NOT EXISTS jobs_bank_opened_idx ON jobs (bank_id, opened_at DESC);
-- The stale sweep reads open jobs by how long they have gone without input.
CREATE INDEX IF NOT EXISTS jobs_stale_idx ON jobs (last_input_at) WHERE state <> 'closed';

CREATE TABLE IF NOT EXISTS job_inputs (
    id             TEXT        PRIMARY KEY,
    job_id         TEXT        NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    -- Per-job sequence, from 1. It is the delivery order and the resume point.
    seq            BIGINT      NOT NULL,
    kind           TEXT        NOT NULL,
    message        TEXT        NOT NULL,
    sender_kind    TEXT        NOT NULL,
    sender_id      TEXT        NOT NULL,
    -- The per-turn grant is NEVER stored. It is minted when the input is
    -- delivered and lives only in that delivery.
    sent_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Set when the member reports it ran this input. An unacknowledged input
    -- is delivered again after a reconnect.
    acknowledged_at TIMESTAMPTZ,
    UNIQUE (job_id, seq)
);

CREATE INDEX IF NOT EXISTS job_inputs_undelivered_idx
    ON job_inputs (job_id, seq)
    WHERE acknowledged_at IS NULL;

CREATE TABLE IF NOT EXISTS job_events (
    job_id      TEXT        NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    seq         BIGINT      NOT NULL,
    kind        TEXT        NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    state       TEXT        NOT NULL DEFAULT '',
    verdict     TEXT        NOT NULL DEFAULT '',
    score       DOUBLE PRECISION NOT NULL DEFAULT 0,
    message     TEXT        NOT NULL DEFAULT '',
    -- The input or the deliverable the event reports, as protojson. Null for
    -- an event that carries neither.
    payload     JSONB,
    PRIMARY KEY (job_id, seq)
);
