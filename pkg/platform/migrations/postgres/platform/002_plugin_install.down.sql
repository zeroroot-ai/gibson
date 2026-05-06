-- plugin-runtime Spec 2, Phase 7, Task 13: rollback plugin_install table.
--
-- Drops the index first (implicit via DROP TABLE, but listed explicitly for
-- clarity) then the table itself. All transient Redis keys are TTL-bound and
-- will expire naturally; no Redis cleanup is required.

DROP TABLE IF EXISTS plugin_install;
