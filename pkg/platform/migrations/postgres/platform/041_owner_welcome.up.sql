-- gibson#987: the owner of a workspace from self-serve signup gets the
-- onboarding email once, when the tenant is ready.
--
-- welcome_owner marks a row that a signup path enqueued. welcome_sent_at is
-- the claim of the one send: the daemon sets it in a conditional UPDATE, so a
-- retry or a restart does not send the email twice.
ALTER TABLE pending_tenant_provisioning ADD COLUMN IF NOT EXISTS welcome_owner BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE pending_tenant_provisioning ADD COLUMN IF NOT EXISTS welcome_sent_at TIMESTAMPTZ;
