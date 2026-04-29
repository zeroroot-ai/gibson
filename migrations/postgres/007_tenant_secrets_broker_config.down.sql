-- secrets-broker Spec, Phase 7, Task 15: rollback for 007_tenant_secrets_broker_config.
--
-- Drops the tenant_secrets_broker_config table entirely. No data
-- preservation — this is a pre-release migration.

DROP TABLE IF EXISTS tenant_secrets_broker_config;
