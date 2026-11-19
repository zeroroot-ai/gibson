-- 021_outside_agent_ca_bundle.up.sql
--
-- A private CA for an outside agent (epic gibson#1366, gibson#1403).
--
-- ca_bundle_secret — the NAME of the tenant secret that holds the PEM CA bundle
--                    that signs the certificate of the agent. Empty means the
--                    gateway uses its public roots. The row never holds the
--                    bundle. The daemon checks at save time that the secret
--                    holds certificates.
--
-- The CA bundle of a model provider is a credential field of the provider
-- (ca_bundle_secret, as base_url is), so it needs no column.

ALTER TABLE outside_agents
    ADD COLUMN IF NOT EXISTS ca_bundle_secret TEXT NOT NULL DEFAULT '';
