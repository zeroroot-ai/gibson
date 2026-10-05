-- The backfill has no inverse: after it runs, a backfilled row and a row an
-- SVID enrollment wrote are the same. Migration 030's down drops the column.
SELECT 1;
