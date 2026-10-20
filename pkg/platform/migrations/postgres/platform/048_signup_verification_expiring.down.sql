-- 048_signup_verification_expiring.down.sql
--
-- An 'expiring' row has been decided by the janitor, so 'rejected' is the
-- honest reading once the state is gone.
UPDATE signup_verification
SET status = 'rejected', updated_at = NOW()
WHERE status = 'expiring';

ALTER TABLE signup_verification
    DROP CONSTRAINT IF EXISTS signup_verification_status_check;
ALTER TABLE signup_verification
    ADD CONSTRAINT signup_verification_status_check
    CHECK (status IN ('pending', 'verified', 'consumed', 'expired', 'send_failed',
                      'pending_approval', 'rejected'));
