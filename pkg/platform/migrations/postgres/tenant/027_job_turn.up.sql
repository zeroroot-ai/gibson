-- 027_job_turn.up.sql - the current turn of a job (gibson#1670).
--
-- A turn grant carries the authority of one sender for one turn. The daemon renews it only
-- while its sender holds the current turn of the job. The turn starts when the daemon pulls
-- the job to a member (the sender is the opener, and there is no input row) and when it
-- delivers an input (the sender is the sender of that input).

ALTER TABLE jobs
    ADD COLUMN IF NOT EXISTS turn_sender_kind TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS turn_sender_id   TEXT NOT NULL DEFAULT '',
    -- The input that started the turn. Empty for the first turn of a pulled job.
    ADD COLUMN IF NOT EXISTS turn_input_id    TEXT NOT NULL DEFAULT '';
