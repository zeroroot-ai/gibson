-- 018_tenant_admin_ops.up.sql
--
-- tenant_admin_ops is the daemon-owned queue that drives operator-pull admin
-- tenant CRUD (gibson#964, enables dashboard#855). It is the admin sibling of
-- pending_tenant_provisioning (migration 016): where 016 carries self-serve
-- signup provisioning, this table carries the three cross-tenant platform-admin
-- operations the dashboard's app/actions/crd/tenant.ts used to apply to the
-- Tenant CR directly:
--
--   - provision : admin creates a tenant   (was applyTenant -> create Tenant CR)
--   - update    : admin patches a tenant    (was patchTenant -> patch spec.tier /
--                 spec.displayName)
--   - delete    : admin deletes a tenant    (was deleteTenant -> delete Tenant CR,
--                 letting the existing finalizer run the 4-phase teardown)
--
-- The daemon records the admin's intent here (AdminTenantService); the
-- tenant-operator -- the sole Kubernetes actor (ADR-0023) -- drains the queue and
-- applies each op to the Tenant CR (create / patch / delete), then acks.
--
-- This table lives in the PLATFORM (control-plane) Postgres, not a per-tenant
-- database: for a provision op the tenant does not exist yet, and the queue is a
-- control-plane concern keyed by the tenant slug. ADR-0023: the daemon only
-- touches Postgres here; every Tenant-CR mutation happens in the operator.
--
-- op_id is the PRIMARY KEY (a daemon-generated UUID) rather than tenant_id,
-- because a single tenant may have more than one op in flight (e.g. an update
-- followed by a delete). Ops for one tenant are applied in created_at order.
CREATE TABLE IF NOT EXISTS tenant_admin_ops (
    -- op_id is a daemon-generated UUID -- the queue's idempotency / ack key.
    op_id              TEXT PRIMARY KEY,

    -- tenant_id is the Tenant CR name the op targets.
    tenant_id          TEXT NOT NULL,

    -- op_type is the admin operation: 'provision', 'update', or 'delete'.
    op_type            TEXT NOT NULL
        CONSTRAINT tenant_admin_ops_op_type_check
        CHECK (op_type IN ('provision', 'update', 'delete')),

    -- display_name is Tenant.spec.displayName. Set on provision; on update it is
    -- applied only when display_name_set is true (so an update can change tier
    -- alone without clobbering displayName). Ignored for delete.
    display_name       TEXT NOT NULL DEFAULT '',

    -- display_name_set distinguishes "set displayName to ''" from "leave
    -- displayName untouched" on an update op. Always true for provision.
    display_name_set   BOOLEAN NOT NULL DEFAULT FALSE,

    -- owner_email is Tenant.spec.owner. Required for provision; unused for
    -- update/delete (owner is immutable post-provision).
    owner_email        TEXT NOT NULL DEFAULT '',

    -- tier is Tenant.spec.tier ("team"/"org"/"enterprise"/...). Set on provision;
    -- on update applied only when tier_set is true. Ignored for delete.
    tier               TEXT NOT NULL DEFAULT '',

    -- tier_set distinguishes "set tier" from "leave tier untouched" on update.
    -- Always true for provision.
    tier_set           BOOLEAN NOT NULL DEFAULT FALSE,

    -- status drives the queue: 'pending' (awaiting the operator) or 'done' (the
    -- operator applied the op to the Tenant CR and acked).
    status             TEXT NOT NULL DEFAULT 'pending'
        CONSTRAINT tenant_admin_ops_status_check
        CHECK (status IN ('pending', 'done')),

    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Partial index over the hot path: the operator's ListPendingTenantOps scans
-- only rows still awaiting application, in apply order.
CREATE INDEX IF NOT EXISTS tenant_admin_ops_pending_idx
    ON tenant_admin_ops (created_at)
    WHERE status <> 'done';
