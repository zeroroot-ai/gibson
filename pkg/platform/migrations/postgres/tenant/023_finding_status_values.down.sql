-- 023_finding_status_values.down.sql
--
-- Restore the old status of each row that the up step mapped, from
-- document->>'legacy_status', and drop that key.

UPDATE findings
SET document = jsonb_set(document, '{status}', document->'legacy_status') - 'legacy_status',
    updated_at = now()
WHERE document ? 'legacy_status'
  AND document->>'legacy_status' IN ('confirmed', 'resolved', 'false_positive');
