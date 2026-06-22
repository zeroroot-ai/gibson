CREATE TABLE IF NOT EXISTS tenant_neo4j_endpoints (
    tenant_id   TEXT        PRIMARY KEY,
    bolt_uri    TEXT        NOT NULL,
    secret_name TEXT        NOT NULL,
    tier        TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ready_at    TIMESTAMPTZ,
    version     INT         NOT NULL DEFAULT 1
);
