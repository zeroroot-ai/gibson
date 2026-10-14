-- 016_provider_default_model_context_window.up.sql
--
-- The context window of the saved default model (gibson#1193). The daemon no
-- longer keeps a list of model windows and a mission never asks the provider
-- for one. The window is stored with the provider config at save time, from the
-- live model list or from the caller when the provider reports none.
--
--   default_model_context_window — tokens. 0 means none is stored (a provider
--                                  saved before this column): unknown, never
--                                  "no room".

ALTER TABLE provider_configs
    ADD COLUMN IF NOT EXISTS default_model_context_window INTEGER NOT NULL DEFAULT 0;

COMMENT ON COLUMN provider_configs.default_model_context_window IS 'Context window in tokens of default_model, stored at save time. 0 means none is stored and the window is unknown.';
