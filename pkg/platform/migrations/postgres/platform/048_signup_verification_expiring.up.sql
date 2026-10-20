-- 048_signup_verification_expiring.up.sql
--
-- A pending registration that waited past its TTL frees its workspace name
-- (gibson#1191). The signup janitor first claims the row as 'expiring', then
-- removes the workspace org in the identity provider, then marks it
-- 'rejected'. A failed removal leaves the row 'expiring', and the next sweep
-- retries it, so the name is never held forever.
ALTER TABLE signup_verification
    DROP CONSTRAINT IF EXISTS signup_verification_status_check;
ALTER TABLE signup_verification
    ADD CONSTRAINT signup_verification_status_check
    CHECK (status IN ('pending', 'verified', 'consumed', 'expired', 'send_failed',
                      'pending_approval', 'rejected', 'expiring'));
