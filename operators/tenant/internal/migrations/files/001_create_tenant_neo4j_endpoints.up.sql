-- 001_create_tenant_neo4j_endpoints.up.sql
-- Registry table read by the daemon's instanceResolver (Neo4jEndpointResolver)
-- to discover the Bolt URI for each per-tenant Neo4j instance. Written by the
-- tenant-operator's neo4jProvisioner after the per-tenant StatefulSet reaches
-- Ready. See design Component 4 and spec per-tenant-data-plane-completion §5.3.

CREATE TABLE IF NOT EXISTS tenant_neo4j_endpoints (
    tenant_id   TEXT        PRIMARY KEY,
    bolt_uri    TEXT        NOT NULL,
    secret_name TEXT        NOT NULL,
    tier        TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ready_at    TIMESTAMPTZ,
    version     INT         NOT NULL DEFAULT 1
);
