-- 008_provider_embedding_capability.down.sql
--
-- Reverts the E11 BYO-embedder columns (ADR-0059, gibson#810).

ALTER TABLE provider_configs
    DROP COLUMN IF EXISTS capabilities,
    DROP COLUMN IF EXISTS default_embedding_model;
