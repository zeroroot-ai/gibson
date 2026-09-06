-- 016_pending_tenant_provisioning.up.sql
--
-- pending_tenant_provisioning is the daemon-owned queue that drives
-- operator-pull tenant provisioning (E9, gibson#948, enables dashboard#813).
--
-- The daemon's Signup handler (gibson#812) inserts one row per self-serve
-- signup once it has provisioned the founding-owner Zitadel user. The
-- tenant-operator's pending-provisioning reconcile loop then drains the queue:
-- it reads pending rows, creates the Tenant CR (the same spec the dashboard
-- used to write — displayName/owner/tier + stripe-customer-id annotation), and
-- acks each row to status='done'.
--
-- This table lives in the PLATFORM (control-plane) Postgres, not a per-tenant
-- database: at signup time the tenant does not exist yet, so there is no
-- per-tenant DB to write to. ADR-0023: the daemon only touches Postgres here;
-- all Kubernetes (Tenant CR create) happens in the operator.
--
-- tenant_id is the PRIMARY KEY so the daemon's INSERT is idempotent on retry
-- (ON CONFLICT DO NOTHING / status preserved), mirroring the already_existed
-- handling in the Signup owner-provisioning path.
CREATE TABLE IF NOT EXISTS pending_tenant_provisioning (
    -- tenant_id is the deterministic tenant slug the daemon derived from the
    -- workspace name (SignupResponse.tenant_id). Used as the Tenant CR name.
    tenant_id          TEXT PRIMARY KEY,

    -- owner_user_id is the Zitadel id of the founding-owner human user the
    -- daemon provisioned. Carried for correlation; not currently required to
    -- build the Tenant CR (the CR's owner is the email).
    owner_user_id      TEXT NOT NULL DEFAULT '',

    -- owner_email is the founding owner's email — becomes Tenant.spec.owner.
    owner_email        TEXT NOT NULL,

    -- workspace_name is the human-readable workspace name — becomes
    -- Tenant.spec.displayName.
    workspace_name     TEXT NOT NULL,

    -- tier is the canonical plan id ("team"/"org"/"enterprise") — becomes
    -- Tenant.spec.tier.
    tier               TEXT NOT NULL,

    -- stripe_customer_id pins a pre-created Stripe customer for deterministic
    -- billing adoption on the card-first signup path. Optional; stamped on the
    -- Tenant CR as the gibson.zeroroot.ai/stripe-customer-id annotation when
    -- non-empty.
    stripe_customer_id TEXT NOT NULL DEFAULT '',

    -- status drives the queue: 'pending' (awaiting the operator),
    -- 'claimed' (reserved by a reconcile pass — optional intermediate), 'done'
    -- (the operator created the Tenant CR and acked).
    status             TEXT NOT NULL DEFAULT 'pending'
        CONSTRAINT pending_tenant_provisioning_status_check
        CHECK (status IN ('pending', 'claimed', 'done')),

    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Partial index over the hot path: the operator's ListPendingTenantProvisioning
-- scans only rows still awaiting provisioning.
CREATE INDEX IF NOT EXISTS pending_tenant_provisioning_pending_idx
    ON pending_tenant_provisioning (created_at)
    WHERE status <> 'done';
