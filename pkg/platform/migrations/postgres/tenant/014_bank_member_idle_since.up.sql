-- 014_bank_member_idle_since.up.sql — when a bank member last became idle
-- (ADR-0119, gibson#809). The reconciler suspends a member that has had no
-- job for 10 minutes. A heartbeat with no job in flight sets the time once;
-- a heartbeat with a job clears it. NULL means the member has work.
ALTER TABLE bank_members ADD COLUMN IF NOT EXISTS idle_since TIMESTAMPTZ;
