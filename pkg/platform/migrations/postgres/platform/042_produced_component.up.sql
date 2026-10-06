-- 041_produced_component.up.sql
--
-- The components that agents enrolled (gibson#33). An agent that produced a
-- tool, an agent or a plugin enrolls it with ComponentService.EnrollComponent.
-- Each row is one enrollment. The count of rows of a tenant is the quota
-- that bounds how many components agents enroll in that tenant.
--
-- The row is written before the identity exists, under a lock on the tenant,
-- so two enrollments at the same time cannot pass the quota. principal_id is
-- empty until the identity exists. A failed enrollment removes its row.

CREATE TABLE IF NOT EXISTS produced_component (
    tenant_id          TEXT        NOT NULL,
    kind               TEXT        NOT NULL CHECK (kind IN ('agent', 'tool', 'plugin')),
    name               TEXT        NOT NULL,
    version            TEXT        NOT NULL,
    image              TEXT        NOT NULL,
    -- The agent that produced and enrolled the component.
    producer_principal TEXT        NOT NULL,
    -- The person who owns the producer, and so owns the component.
    owner_user_id      TEXT        NOT NULL,
    principal_id       TEXT        NOT NULL DEFAULT '',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, kind, name)
);
