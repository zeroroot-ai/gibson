-- hosted#195 / ADR-0093 decision 4: the tenant comes from the token's
-- verified Zitadel org, never from the client. ext-authz resolves a
-- person's tenant by looking up their token's org in this table, so one
-- org must map to at most one tenant, or the lookup would be ambiguous.
CREATE UNIQUE INDEX IF NOT EXISTS tenant_zitadel_orgs_org_uidx
    ON tenant_zitadel_orgs (zitadel_org_id);
