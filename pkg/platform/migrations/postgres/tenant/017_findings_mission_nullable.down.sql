-- This statement fails if a finding row has a NULL mission_id.
-- Delete or attach those rows before the rollback.

ALTER TABLE findings ALTER COLUMN mission_id SET NOT NULL;

COMMENT ON COLUMN findings.mission_id IS 'UUID of the mission that produced this finding.';
