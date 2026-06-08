ALTER TABLE component_install DROP CONSTRAINT component_install_unique_host;
ALTER TABLE component_install
    ADD CONSTRAINT plugin_install_unique_host
    UNIQUE (tenant_id, component_name, host_id);
ALTER TABLE component_install RENAME CONSTRAINT component_install_pkey TO plugin_install_pkey;
ALTER INDEX idx_component_install_tenant_name RENAME TO idx_plugin_install_tenant_name;
ALTER TABLE component_install DROP COLUMN kind;
ALTER TABLE component_install RENAME COLUMN component_name TO plugin_name;
ALTER TABLE component_install RENAME TO plugin_install;
