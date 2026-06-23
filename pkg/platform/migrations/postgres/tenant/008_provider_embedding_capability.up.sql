-- 008_provider_embedding_capability.up.sql
--
-- E11 BYO-embedder (ADR-0059, gibson#810). A provider config now declares which
-- services it fulfils (chat and/or embedding) and carries a separate default
-- embedding model, so an operator can run e.g. Anthropic for chat and
-- OpenAI/Bedrock/TEI for embeddings. The per-tenant embedder resolver reads
-- these columns to build the tenant's embedder via embedder.NewFromProvider;
-- absence of any embedding-capable provider gates vector recall / GraphRAG /
-- belief-RAG / finding-classification with a "configure an embedding provider"
-- prompt.
--
--   capabilities             — text[] of lower-cased capability strings
--                              ('chat','embedding'). Empty = legacy chat-only.
--   default_embedding_model  — embedding model, independent of default_model
--                              (the chat model). Empty when not an embedder.

ALTER TABLE provider_configs
    ADD COLUMN IF NOT EXISTS capabilities            TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS default_embedding_model TEXT   NOT NULL DEFAULT '';

COMMENT ON COLUMN provider_configs.capabilities IS 'Lower-cased capability strings the provider fulfils: chat and/or embedding. Empty implies legacy chat-only.';
COMMENT ON COLUMN provider_configs.default_embedding_model IS 'Default embedding model (independent of default_model, the chat model). Empty when the provider does not serve embeddings.';
