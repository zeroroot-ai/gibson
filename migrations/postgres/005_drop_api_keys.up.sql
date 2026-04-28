-- Migration 005: Drop api_keys table.
-- The gsk_ API key system has been removed. API keys were dead-on-arrival:
-- ext-authz's Lua filter that validated them was removed in the Phase-2
-- unified-identity-and-authorization migration. Keys could be issued but
-- never authenticated. The table is no longer written to or read from.
-- Spec: agent-service-credentials Requirement 10.7.
--
-- Down migration recreates an empty table with the original schema (allowing
-- rollback of the same release).

DROP TABLE IF EXISTS api_keys;
