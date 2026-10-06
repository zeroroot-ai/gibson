-- 013_timeline_events.up.sql
--
-- The full history of the tenant Timeline (ADR-0163, gibson#786).
--
-- The live tail of the Timeline is a Redis stream. After each snapshot the
-- engine trims the stream. Before the trim, the Timeline store copies each
-- stream entry that the trim removes into this table, so the table plus the
-- stream tail are the full ordered history of the tenant.
--
-- timeline_events — one row for each Timeline event, in stream order.
--
-- Per-tenant database, so there is no tenant_id column (migration 010).
--
-- Retention follows the audit log. Migration 014 holds the export position
-- (gibson#992).

CREATE TABLE IF NOT EXISTS timeline_events (
    -- The two parts of the Redis stream id "<ms>-<seq>" that Redis assigned
    -- to the event. Together they are the identity and the order of the event.
    stream_ms   BIGINT      NOT NULL,
    stream_seq  BIGINT      NOT NULL,
    -- The event kind, for a reader that selects by kind with no JSON parse.
    kind        TEXT        NOT NULL,
    -- The encoded event envelope: {"kind": ..., "payload": ...}.
    event       JSONB       NOT NULL,
    -- When the row was written. The retention period counts from here.
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (stream_ms, stream_seq)
);

-- The retention read: the rows that are older than the retention period.
CREATE INDEX IF NOT EXISTS timeline_events_recorded_at_idx ON timeline_events (recorded_at);
