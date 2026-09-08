-- 024_signup_admin_approval.up.sql
--
-- The admin-approval registration rung (ADR-0006, gibson#22).
--
-- ADR-0006 defines three registration rungs: open (verification on, mail
-- required), approval (an administrator approves, no mail), and closed (admin
-- provisioning only). This migration gives the approval rung the state it
-- needs, on the table the open rung already uses.
--
-- ONE TABLE, ONE CODE PATH. A registration and a verification are the same
-- thing at different stages of proof: both park the non-secret form fields
-- until something authorizes provisioning. On the open rung that something is
-- the mailbox; on the approval rung it is an administrator. Splitting them
-- into two tables would have meant two completion paths, and the second one
-- would rot (ADR-0027).
--
-- What a pending registration IS: a row in status 'pending_approval' plus a
-- DEACTIVATED IdP user holding the password the registrant chose. The
-- credential goes straight to the identity provider, where credentials belong,
-- and the account cannot be signed into until an administrator approves it.
-- No tenant, no billing object and no provisioning-queue row exists until
-- approval.

-- owner_user_id is the deactivated IdP user created at registration time. It
-- is empty on the open rung, where the user is created at completion instead.
ALTER TABLE signup_verification
    ADD COLUMN IF NOT EXISTS owner_user_id TEXT NOT NULL DEFAULT '';

-- decided_by / decided_at record WHICH administrator approved or rejected the
-- registration and when. ADR-0006 requires the decision to be attributable;
-- the audit log carries the event and this row carries the same fact next to
-- the registration it decided.
ALTER TABLE signup_verification
    ADD COLUMN IF NOT EXISTS decided_by TEXT NOT NULL DEFAULT '';
ALTER TABLE signup_verification
    ADD COLUMN IF NOT EXISTS decided_at TIMESTAMPTZ;

-- Two new lifecycle states join the five the open rung uses:
--   pending_approval — registered, account deactivated, awaiting a decision
--   rejected         — an administrator refused it; the account stays
--                      deactivated and never becomes usable
-- An APPROVED registration does not get its own state: approval provisions the
-- tenant and the row reaches 'consumed', which is exactly what a completed
-- signup reaches on the open rung.
ALTER TABLE signup_verification
    DROP CONSTRAINT IF EXISTS signup_verification_status_check;
ALTER TABLE signup_verification
    ADD CONSTRAINT signup_verification_status_check
    CHECK (status IN ('pending', 'verified', 'consumed', 'expired', 'send_failed',
                      'pending_approval', 'rejected'));

-- The retention sweep covers rejected rows too: a refusal is terminal, and a
-- terminal row is kept for a week for forensics and then deleted.
DROP INDEX IF EXISTS signup_verification_retention_idx;
CREATE INDEX IF NOT EXISTS signup_verification_retention_idx
    ON signup_verification (updated_at)
    WHERE status IN ('consumed', 'expired', 'send_failed', 'rejected');

-- The approval queue: oldest first, so an administrator works through
-- registrations in the order people made them. A registration awaiting a
-- decision is NOT swept by the janitor: it waits for a person, and a clock
-- that decided it would strand the deactivated account it names.
CREATE INDEX IF NOT EXISTS signup_verification_pending_approval_idx
    ON signup_verification (created_at)
    WHERE status = 'pending_approval';
