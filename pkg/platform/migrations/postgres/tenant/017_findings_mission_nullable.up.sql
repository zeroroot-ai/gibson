-- A finding can reach the daemon with no mission. The component path leaves
-- such a finding unattached to a mission. The findings table now holds the
-- full finding, so mission_id must accept NULL.

ALTER TABLE findings ALTER COLUMN mission_id DROP NOT NULL;

COMMENT ON COLUMN findings.mission_id IS 'UUID of the mission that produced this finding. NULL when the finding has no mission.';
