-- gibson#788: the belief artifact versions of each tenant (ADR-0106).
--
-- The trainer of a tenant stores both artifacts of one fit as one version
-- through the daemon. A new version starts as a candidate. The quality gate
-- (gibson#789) makes a candidate current or marks it rejected. At most one
-- version of a tenant is current.
CREATE TABLE IF NOT EXISTS tenant_belief_artifacts (
    tenant_id       TEXT        NOT NULL,
    version         BIGINT      NOT NULL,
    belief_model    JSONB       NOT NULL,
    edge_posteriors JSONB       NOT NULL,
    state           TEXT        NOT NULL DEFAULT 'candidate'
                    CHECK (state IN ('candidate', 'current', 'rejected')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, version)
);

CREATE UNIQUE INDEX IF NOT EXISTS tenant_belief_artifacts_one_current
    ON tenant_belief_artifacts (tenant_id) WHERE state = 'current';
