-- 010_banks.down.sql — drop the bank tables (gibson#1708).
DROP INDEX IF EXISTS bank_members_mission_run_idx;
DROP INDEX IF EXISTS bank_members_bank_id_idx;
DROP TABLE IF EXISTS bank_members;
DROP TABLE IF EXISTS banks;
