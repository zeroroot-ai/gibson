-- 013_timeline_events.down.sql — drop the Timeline history table (gibson#786).
DROP INDEX IF EXISTS timeline_events_recorded_at_idx;
DROP TABLE IF EXISTS timeline_events;
