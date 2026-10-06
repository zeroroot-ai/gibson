-- 014_bank_member_idle_since.down.sql — drop the idle time of a bank member.
ALTER TABLE bank_members DROP COLUMN IF EXISTS idle_since;
