-- 026_inbound_messages.up.sql
--
-- The message ids that inbound A2A calls already used (gibson#1611).
--
-- inbound_messages - one row for each message id that started a mission. A
--                    webhook sender sends the same id again when it retries, so
--                    the second message finds the row and starts no mission. The
--                    row names the mission that the first message started.
--
-- This table lives in the PER-TENANT database, so there is no tenant_id column:
-- the database is the tenant scope (migration 007). The same id in another
-- tenant is in another database and never matches.

CREATE TABLE IF NOT EXISTS inbound_messages (
    message_key TEXT        PRIMARY KEY,
    mission_id  TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS inbound_messages_created_idx ON inbound_messages (created_at);
