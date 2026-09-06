-- 009_session_context.up.sql
--
-- Session-context store (gibson#1184): one opaque, envelope-encrypted blob
-- per session, written and read by external components through the
-- HarnessCallbackService Put/Get/DeleteSessionContext RPCs (sdk v0.162.0).
--
-- The primary key is session_id alone: this table lives in the per-tenant
-- database, so the tenant half of the (tenant, session_id) key is implied by
-- which database the table lives in (same convention as 003_missions.up.sql;
-- enforced by check-no-tenant-id).
--
-- envelope carries the AES-KW + AES-256-GCM envelope produced under the
-- per-tenant KEK (internal/infra/datapool/envelope), AAD-bound to
-- "session_context:<session_id>" so a row cannot be re-keyed to another
-- session without decryption failing.
--
-- etag names the current version; writes are compare-and-swap on it
-- (If-Match). expires_at implements the server-side TTL — expired rows are
-- treated as absent by every query and reaped opportunistically on write.
CREATE TABLE IF NOT EXISTS session_context (
    session_id  TEXT PRIMARY KEY,
    envelope    BYTEA NOT NULL,
    etag        TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_session_context_expires_at
    ON session_context (expires_at);
