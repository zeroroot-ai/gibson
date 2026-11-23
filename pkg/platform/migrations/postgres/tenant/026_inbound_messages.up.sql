-- 026_inbound_messages.up.sql
--
-- The message ids that inbound A2A calls already used (gibson#1611).
--
-- inbound_messages - one row for each message id that a call claimed. A webhook
--                    sender sends the same id again when it retries. The state
--                    is pending while the first call starts its mission, and
--                    started after the start. A pending row is a lease: it ends
--                    at lease_until, so a call that stops leaves no key that
--                    blocks the retry. The key holds the agent, so one id sent
--                    to two agents starts both.
--
-- This table lives in the PER-TENANT database, so there is no tenant_id column:
-- the database is the tenant scope (migration 007). The same id in another
-- tenant is in another database and never matches.

CREATE TABLE IF NOT EXISTS inbound_messages (
    message_key TEXT        PRIMARY KEY,
    mission_id  TEXT        NOT NULL,
    state       TEXT        NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'started')),
    lease_until TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS inbound_messages_created_idx ON inbound_messages (created_at);
