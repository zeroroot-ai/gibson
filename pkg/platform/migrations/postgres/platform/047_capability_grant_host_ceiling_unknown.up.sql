-- An unknown capability ceiling must not read as "no ceiling".
--
-- Migration 046 stored the ceiling of the enrolling credential on the host row
-- and gave every existing row the empty list. An empty list means "the
-- credential named no ceiling", which allows every capability of the
-- principal. A host that enrolled before 046 has no recoverable ceiling, so
-- its row must say "unknown", and a re-registration of it is refused until the
-- host enrolls again with a bootstrap token.
--
-- Every row that holds the empty list becomes unknown. A host that really had
-- no ceiling enrolls once more. A new enrollment writes its ceiling, empty or
-- not, so NULL means unknown and only that.
ALTER TABLE capability_grant_hosts ALTER COLUMN capability_ceiling DROP NOT NULL;
ALTER TABLE capability_grant_hosts ALTER COLUMN capability_ceiling DROP DEFAULT;
UPDATE capability_grant_hosts SET capability_ceiling = NULL WHERE capability_ceiling = '[]'::jsonb;
