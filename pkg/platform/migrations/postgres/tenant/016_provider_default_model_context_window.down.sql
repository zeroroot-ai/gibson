-- 016_provider_default_model_context_window.down.sql
--
-- Reverts the stored context window of the saved default model (gibson#1193).

ALTER TABLE provider_configs
    DROP COLUMN IF EXISTS default_model_context_window;
