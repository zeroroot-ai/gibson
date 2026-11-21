-- gibson#1534, gibson#1538: what a tenant chose when it enabled a connector.
--
-- endpoint holds the MCP endpoint of a Remote connector that the tenant gave.
-- The daemon checked it against the endpointPatterns of the catalog entry
-- before it stored it, and checks it again each time it hands the connector to
-- the connector operator. Empty means the default endpoint of the entry.
--
-- oauth_client_id and oauth_client_secret_name hold the OAuth client that the
-- tenant registered at its identity provider, for a connector that has no
-- dynamic client registration. The table holds the NAME of the secret of the
-- tenant and never its value.
ALTER TABLE tenant_connectors
    ADD COLUMN IF NOT EXISTS endpoint                 TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS oauth_client_id          TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS oauth_client_secret_name TEXT NOT NULL DEFAULT '';
