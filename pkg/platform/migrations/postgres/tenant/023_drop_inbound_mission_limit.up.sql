-- 023_drop_inbound_mission_limit.up.sql
--
-- The product is open source, so it has no count limits (gibson#1567). An A2A
-- publication has no limit on its active missions. Only the count read
-- max_active_missions, finished_at and inbound_tasks_open_idx, so all three go.
-- Migration 022 made them.
DROP INDEX IF EXISTS inbound_tasks_open_idx;
ALTER TABLE inbound_tasks DROP COLUMN IF EXISTS finished_at;
ALTER TABLE inbound_missions DROP COLUMN IF EXISTS max_active_missions;
