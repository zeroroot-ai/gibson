-- gibson#597: the runtime cap an AgentEnrollment declares (spec.maxRuntime).
-- The tenant-operator reports it through DaemonOperatorService.
-- SetAgentEnrollmentLimits; the daemon reads it when it dispatches that
-- agent to a sandbox (internal/engine/harness/catalog_agent_resolver.go).
CREATE TABLE IF NOT EXISTS agent_enrollment_limits (
    tenant_id           TEXT        NOT NULL,
    agent_name          TEXT        NOT NULL,
    max_runtime_seconds BIGINT      NOT NULL CHECK (max_runtime_seconds >= 0),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, agent_name)
);
