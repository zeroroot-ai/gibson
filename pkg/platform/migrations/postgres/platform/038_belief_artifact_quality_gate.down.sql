UPDATE tenant_belief_artifacts SET state = 'rejected' WHERE state = 'retired';

ALTER TABLE tenant_belief_artifacts DROP CONSTRAINT IF EXISTS tenant_belief_artifacts_state_check;
ALTER TABLE tenant_belief_artifacts ADD CONSTRAINT tenant_belief_artifacts_state_check
    CHECK (state IN ('candidate', 'current', 'rejected'));

ALTER TABLE tenant_belief_artifacts
    DROP COLUMN IF EXISTS brier_candidate,
    DROP COLUMN IF EXISTS brier_current,
    DROP COLUMN IF EXISTS scored_bets;
