-- 023_finding_status_values.up.sql
--
-- A finding has four statuses: open, fixing, fixed and verified (ADR-0178,
-- gibson#1518). Rows that an older daemon wrote can hold one of the old
-- values. This migration maps each old value to one of the four, and keeps the
-- old value in document->>'legacy_status' so the down step can restore it
-- (review m11). The mapping:
--
--   confirmed      -> open     the flaw is real and no fix exists yet
--   resolved       -> fixed    a person said it is fixed, and the check that
--                              raised it has not verified the fix
--   false_positive -> open     only the check that raised a finding closes it
--                              (ADR-0178). A person's verdict is no check, so
--                              the next run of the check decides
--
-- A row with any other value outside the four keeps its value: the migration
-- does not guess.

UPDATE findings
SET document = jsonb_set(
        jsonb_set(document, '{legacy_status}', to_jsonb(document->>'status')),
        '{status}',
        to_jsonb(CASE document->>'status'
            WHEN 'confirmed' THEN 'open'
            WHEN 'resolved' THEN 'fixed'
            WHEN 'false_positive' THEN 'open'
        END)),
    updated_at = now()
WHERE document->>'status' IN ('confirmed', 'resolved', 'false_positive');
