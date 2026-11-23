-- 027_job_turn.down.sql - drop the current turn of a job (gibson#1670).
ALTER TABLE jobs
    DROP COLUMN IF EXISTS turn_sender_kind,
    DROP COLUMN IF EXISTS turn_sender_id,
    DROP COLUMN IF EXISTS turn_input_id;
