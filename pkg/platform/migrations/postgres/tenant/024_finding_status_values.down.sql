-- 024_finding_status_values.down.sql
--
-- Restore the old status of each row that the up step mapped, from
-- document->>'legacy_status', and drop that key. A row that the daemon moved
-- after the up step keeps its new status (review r12): the old value is put
-- back only while the status still equals the value that the up step wrote.

UPDATE findings
SET document = jsonb_set(document, '{status}', document->'legacy_status') - 'legacy_status',
    updated_at = now()
WHERE document ? 'legacy_status'
  AND (
    (document->>'legacy_status' = 'confirmed' AND document->>'status' = 'open')
    OR (document->>'legacy_status' = 'resolved' AND document->>'status' = 'fixed')
    OR (document->>'legacy_status' = 'false_positive' AND document->>'status' = 'open')
  );

-- A row that the daemon moved drops the key and keeps its status.
UPDATE findings
SET document = document - 'legacy_status', updated_at = now()
WHERE document ? 'legacy_status';
