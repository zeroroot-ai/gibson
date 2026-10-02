-- gibson#505 (ADR-0027): provider_config_meta held one key/value row,
-- "__default" -> provider name, a pointer that shadowed
-- provider_configs.is_default. The DAO reads the column now and the lazy
-- migration from tenant_secrets "provider_config:<name>" rows is gone, so
-- the table has no reader.
DROP TABLE IF EXISTS provider_config_meta;
