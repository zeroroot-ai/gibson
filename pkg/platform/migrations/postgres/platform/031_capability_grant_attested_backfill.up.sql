-- Rows of an attested plugin from before migration 030 (ADR-0066).
--
-- Migration 030 added `attested` with the default FALSE. A grant row does not
-- expire, so a plugin that enrolled with its SPIRE identity before 030 kept
-- rows that say "not attested", and PrincipalIsAttested needs every active
-- row of a principal to be attested. On an install that existed before 030
-- the platform's own plugin would read as a token enrollment for good.
--
-- This backfill runs once. Before 030 there were two producers of a plugin
-- principal. The SVID enrollment made `plugin_principal:<vendor>`, where
-- vendor matches ^[a-z][a-z0-9-]{2,40}$ (pluginVendorRe). The token paths
-- made `plugin_principal:<service account id>`, and the identity provider
-- gives numeric ids. The two forms never meet, so the form states how a row
-- from before the record enrolled. A row written after 030 carries the fact
-- itself and this statement does not touch its meaning: an SVID row is TRUE
-- already, and a token row cannot have the vendor form.
UPDATE capability_grant_hosts
SET    attested = TRUE
WHERE  attested = FALSE
  AND  principal_ref ~ '^plugin_principal:[a-z][a-z0-9-]{2,40}$';

UPDATE capability_grant_agents
SET    attested = TRUE
WHERE  attested = FALSE
  AND  principal_ref ~ '^plugin_principal:[a-z][a-z0-9-]{2,40}$';
