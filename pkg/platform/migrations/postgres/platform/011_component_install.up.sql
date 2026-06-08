-- gibson#662 / ADR-0046: agents, tools, and plugins use ONE install registry.
-- Generalize the plugin-only install table to all component kinds: rename it,
-- rename plugin_name -> component_name, and add a `kind` discriminator (existing
-- rows are plugins). Physical-install uniqueness is now per (tenant, kind, name,
-- host) so a tool and a plugin of the same name on one host don't collide.
ALTER TABLE plugin_install RENAME TO component_install;
ALTER TABLE component_install RENAME COLUMN plugin_name TO component_name;
ALTER TABLE component_install ADD COLUMN kind TEXT NOT NULL DEFAULT 'plugin';
ALTER INDEX idx_plugin_install_tenant_name RENAME TO idx_component_install_tenant_name;
ALTER TABLE component_install RENAME CONSTRAINT plugin_install_pkey TO component_install_pkey;
ALTER TABLE component_install DROP CONSTRAINT plugin_install_unique_host;
ALTER TABLE component_install
    ADD CONSTRAINT component_install_unique_host
    UNIQUE (tenant_id, kind, component_name, host_id);
COMMENT ON TABLE component_install IS
    'Persistent registry for component installs (agent, tool, plugin). Transient runtime state (address, heartbeat, status) is tracked in Redis with a 90-second TTL.';
COMMENT ON COLUMN component_install.kind IS
    'Component kind: agent | tool | plugin.';
COMMENT ON COLUMN component_install.component_name IS
    'Canonical component name from the manifest metadata.name field.';
