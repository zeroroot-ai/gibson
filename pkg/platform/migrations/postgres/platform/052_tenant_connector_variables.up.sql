-- gibson#1508: the values that a tenant gave for the variables of a Hosted
-- connector, for example the address of its own Ansible Automation Platform.
--
-- variables holds a JSON object that maps the name of a variable to its value.
-- The daemon checked each value against the manifest of the catalog entry
-- before it stored it, and checks it again each time it hands the connector to
-- the connector operator. The table holds no credential: a value is an https
-- URL of a host. Empty object means no variable.
ALTER TABLE tenant_connectors
    ADD COLUMN IF NOT EXISTS variables JSONB NOT NULL DEFAULT '{}'::jsonb;
