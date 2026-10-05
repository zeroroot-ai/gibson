-- gibson#815: the catalog plugins each tenant enabled.
--
-- A row is what a tenant WANTS: one instance of the plugin, for that tenant.
-- CatalogPluginService writes the row. The tenant operator reads the desired
-- state from the daemon, runs the instance, and reports phase and last_error
-- back. The daemon starts nothing itself.
CREATE TABLE IF NOT EXISTS tenant_catalog_plugins (
    tenant_id   TEXT        NOT NULL,
    plugin_id   TEXT        NOT NULL,
    phase       TEXT        NOT NULL DEFAULT 'Pending',
    last_error  TEXT        NOT NULL DEFAULT '',
    enabled_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reported_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, plugin_id)
);
