-- 011_jobs.down.sql — drop the job tables (gibson#1710).
DROP TABLE IF EXISTS job_events;
DROP TABLE IF EXISTS job_inputs;
DROP INDEX IF EXISTS jobs_stale_idx;
DROP INDEX IF EXISTS jobs_bank_opened_idx;
DROP INDEX IF EXISTS jobs_member_idx;
DROP INDEX IF EXISTS jobs_queue_idx;
DROP TABLE IF EXISTS jobs;
