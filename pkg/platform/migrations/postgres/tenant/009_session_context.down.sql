-- 009_session_context.down.sql
DROP INDEX IF EXISTS idx_session_context_expires_at;
DROP TABLE IF EXISTS session_context;
