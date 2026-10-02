-- Restores the two tables 028 dropped, with the shape 013+014 and 015 left.
CREATE TABLE IF NOT EXISTS connector_sandbox (
    tenant_id      TEXT        NOT NULL,
    connector_name TEXT        NOT NULL,
    sandbox_id     TEXT        NOT NULL,
    launched_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    principal_id   TEXT        NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, connector_name)
);
CREATE TABLE IF NOT EXISTS webhook_idempotency (
    event_id   TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    tenant_id  TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
