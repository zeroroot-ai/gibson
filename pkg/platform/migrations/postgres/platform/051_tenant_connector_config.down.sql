ALTER TABLE tenant_connectors
    DROP COLUMN IF EXISTS oauth_client_secret_name,
    DROP COLUMN IF EXISTS oauth_client_id,
    DROP COLUMN IF EXISTS endpoint;
