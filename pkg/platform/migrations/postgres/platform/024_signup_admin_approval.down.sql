-- 024_signup_admin_approval.down.sql
--
-- Rolls the approval rung's state off signup_verification. Rows still in an
-- approval state are moved to 'expired' first: the status constraint below
-- does not admit them, and an expired registration is the honest reading —
-- nobody decided it and it can no longer be decided.
UPDATE signup_verification
SET status = 'expired', updated_at = NOW()
WHERE status IN ('pending_approval', 'rejected');

DROP INDEX IF EXISTS signup_verification_pending_approval_idx;

DROP INDEX IF EXISTS signup_verification_retention_idx;
CREATE INDEX IF NOT EXISTS signup_verification_retention_idx
    ON signup_verification (updated_at)
    WHERE status IN ('consumed', 'expired', 'send_failed');

ALTER TABLE signup_verification
    DROP CONSTRAINT IF EXISTS signup_verification_status_check;
ALTER TABLE signup_verification
    ADD CONSTRAINT signup_verification_status_check
    CHECK (status IN ('pending', 'verified', 'consumed', 'expired', 'send_failed'));

ALTER TABLE signup_verification DROP COLUMN IF EXISTS decided_at;
ALTER TABLE signup_verification DROP COLUMN IF EXISTS decided_by;
ALTER TABLE signup_verification DROP COLUMN IF EXISTS owner_user_id;
