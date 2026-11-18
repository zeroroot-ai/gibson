-- One row for each evidence item of a finding (gibson#1380).
-- The finding row and its evidence rows go in one transaction.
-- No tenant_id column: the tenant is implied by which database this table lives in.

CREATE TABLE IF NOT EXISTS finding_evidence (
    finding_id     UUID        NOT NULL REFERENCES findings (id) ON DELETE CASCADE,
    position       INTEGER     NOT NULL CHECK (position >= 0),
    tier           SMALLINT    NOT NULL CHECK (tier IN (1, 2)),
    tool_call_id   TEXT,
    type           TEXT        NOT NULL,
    title          TEXT        NOT NULL DEFAULT '',
    content        TEXT        NOT NULL,
    content_sha256 BYTEA       NOT NULL CHECK (octet_length(content_sha256) = 32),
    metadata       JSONB       NOT NULL DEFAULT '{}',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (finding_id, position),
    -- A tier 1 item names the tool call that backs it. A tier 2 item names none.
    CHECK ((tier = 1 AND tool_call_id IS NOT NULL) OR (tier = 2 AND tool_call_id IS NULL))
);

COMMENT ON TABLE finding_evidence IS 'Evidence items of a finding. One row for each item. The delete of a finding deletes its rows.';
COMMENT ON COLUMN finding_evidence.tier IS '1 = recorded: the daemon copied the result of a tool call from its own record. 2 = typed: the agent typed the content.';
COMMENT ON COLUMN finding_evidence.tool_call_id IS 'ID of the recorded tool call that backs a tier 1 item. NULL on a tier 2 item.';
COMMENT ON COLUMN finding_evidence.content IS 'The content as the brain stored it, after the redaction for the tenant. A later change of the redaction policy does not change it.';
COMMENT ON COLUMN finding_evidence.content_sha256 IS 'SHA-256 of content.';
