-- 023_drop_inbound_mission_limit.down.sql
--
-- Makes the columns and the index of migration 022 again. A publication gets a
-- limit of 1, because the old values are gone. Each task gets no end time.
ALTER TABLE inbound_missions ADD COLUMN IF NOT EXISTS max_active_missions INT NOT NULL DEFAULT 1 CHECK (max_active_missions > 0);
ALTER TABLE inbound_missions ALTER COLUMN max_active_missions DROP DEFAULT;
ALTER TABLE inbound_tasks ADD COLUMN IF NOT EXISTS finished_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS inbound_tasks_open_idx ON inbound_tasks (publication_id) WHERE finished_at IS NULL;
