-- gibson#713, ADR-0060 (D54): the platform holds no billing state.
--
-- The billing customer id and the billing-active flag leave every table. In
-- their place:
--
--   * tenant_status.activation: 'active' or 'suspended'. A component outside
--     this repository sets it through ConnectionPointService.SetTenantActivation.
--     A tenant that no call has named is active.
--   * the neutral signup step on pending_tenant_provisioning. A signup with a
--     step URL in config waits in status 'waiting_step' (or 'step_failed') until
--     ConnectionPointService.CompleteSignupStep reports it done. Only the hash
--     of the opaque step token is stored.
ALTER TABLE tenant_status DROP COLUMN IF EXISTS stripe_customer_id;
ALTER TABLE tenant_status DROP COLUMN IF EXISTS billing_active;
ALTER TABLE tenant_status ADD COLUMN IF NOT EXISTS activation TEXT NOT NULL DEFAULT 'active';
ALTER TABLE tenant_status DROP CONSTRAINT IF EXISTS tenant_status_activation_check;
ALTER TABLE tenant_status ADD CONSTRAINT tenant_status_activation_check
    CHECK (activation IN ('active', 'suspended'));

ALTER TABLE pending_tenant_provisioning DROP COLUMN IF EXISTS stripe_customer_id;
ALTER TABLE pending_tenant_provisioning ADD COLUMN IF NOT EXISTS attempt_id TEXT NOT NULL DEFAULT '';
ALTER TABLE pending_tenant_provisioning ADD COLUMN IF NOT EXISTS step_token_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE pending_tenant_provisioning ADD COLUMN IF NOT EXISTS step_expires_at TIMESTAMPTZ;
ALTER TABLE pending_tenant_provisioning DROP CONSTRAINT IF EXISTS pending_tenant_provisioning_status_check;
ALTER TABLE pending_tenant_provisioning ADD CONSTRAINT pending_tenant_provisioning_status_check
    CHECK (status IN ('waiting_step', 'step_failed', 'pending', 'claimed', 'done'));
CREATE UNIQUE INDEX IF NOT EXISTS pending_tenant_provisioning_step_token_idx
    ON pending_tenant_provisioning (step_token_hash) WHERE step_token_hash <> '';
CREATE INDEX IF NOT EXISTS pending_tenant_provisioning_attempt_idx
    ON pending_tenant_provisioning (attempt_id) WHERE attempt_id <> '';

ALTER TABLE signup_verification DROP COLUMN IF EXISTS stripe_customer_id;
