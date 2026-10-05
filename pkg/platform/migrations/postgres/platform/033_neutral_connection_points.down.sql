ALTER TABLE signup_verification ADD COLUMN IF NOT EXISTS stripe_customer_id TEXT NOT NULL DEFAULT '';

DROP INDEX IF EXISTS pending_tenant_provisioning_attempt_idx;
DROP INDEX IF EXISTS pending_tenant_provisioning_step_token_idx;
DELETE FROM pending_tenant_provisioning WHERE status IN ('waiting_step', 'step_failed');
ALTER TABLE pending_tenant_provisioning DROP CONSTRAINT IF EXISTS pending_tenant_provisioning_status_check;
ALTER TABLE pending_tenant_provisioning ADD CONSTRAINT pending_tenant_provisioning_status_check
    CHECK (status IN ('pending', 'claimed', 'done'));
ALTER TABLE pending_tenant_provisioning DROP COLUMN IF EXISTS step_expires_at;
ALTER TABLE pending_tenant_provisioning DROP COLUMN IF EXISTS step_token_hash;
ALTER TABLE pending_tenant_provisioning DROP COLUMN IF EXISTS attempt_id;
ALTER TABLE pending_tenant_provisioning ADD COLUMN IF NOT EXISTS stripe_customer_id TEXT NOT NULL DEFAULT '';

ALTER TABLE tenant_status DROP CONSTRAINT IF EXISTS tenant_status_activation_check;
ALTER TABLE tenant_status DROP COLUMN IF EXISTS activation;
ALTER TABLE tenant_status ADD COLUMN IF NOT EXISTS billing_active BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE tenant_status ADD COLUMN IF NOT EXISTS stripe_customer_id TEXT NOT NULL DEFAULT '';
