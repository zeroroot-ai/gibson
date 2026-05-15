-- gibson#99: rollback for 004_tenant_id_text.
--
-- Reverts tenant_id columns from TEXT back to UUID. The USING cast
-- will fail if any row holds a non-UUID-shaped slug — which is the
-- whole reason the up migration exists, so this down is unsafe in
-- practice. Provided for migration-tool completeness only; do not
-- run against a database that has accepted non-UUID tenant ids.

ALTER TABLE tenant_secrets_broker_config
    ALTER COLUMN tenant_id TYPE UUID USING tenant_id::uuid;

ALTER TABLE plugin_install
    ALTER COLUMN tenant_id TYPE UUID USING tenant_id::uuid;
