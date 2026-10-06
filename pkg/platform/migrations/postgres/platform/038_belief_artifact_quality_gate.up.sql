-- gibson#789: the quality gate of the belief artifact versions (ADR-0106).
--
-- When the trainer stores a version, the daemon scores the new version and the
-- current version on the settled bets of the tenant (the Brier score). The new
-- version becomes current only when its score is not worse. A rejected version
-- stays, with its mark and the two scores. The version that a new current
-- version replaces is retired.
ALTER TABLE tenant_belief_artifacts
    ADD COLUMN IF NOT EXISTS brier_candidate DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS brier_current   DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS scored_bets     INTEGER;

ALTER TABLE tenant_belief_artifacts DROP CONSTRAINT IF EXISTS tenant_belief_artifacts_state_check;
ALTER TABLE tenant_belief_artifacts ADD CONSTRAINT tenant_belief_artifacts_state_check
    CHECK (state IN ('candidate', 'current', 'rejected', 'retired'));
