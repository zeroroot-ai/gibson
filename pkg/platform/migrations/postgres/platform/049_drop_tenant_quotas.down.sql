-- 049_drop_tenant_quotas.down.sql
--
-- Makes tenant_quotas again in the shape that migrations 003, 005 and 025
-- left. The rows are gone.
CREATE TABLE IF NOT EXISTS tenant_quotas (
    tenant_id             TEXT PRIMARY KEY,
    concurrent_missions   INT NOT NULL DEFAULT 0,
    concurrent_agents     INT NOT NULL DEFAULT 0,
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    plan_id               TEXT NOT NULL DEFAULT '',
    concurrent_connectors INT NOT NULL DEFAULT 0
);
