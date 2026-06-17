-- dashboard#780 / dashboard#785: Stripe webhook idempotency ledger.
--
-- BillingService.RecordWebhookEvent / DeleteWebhookEvent
-- (internal/daemon/billing_service.go) read and write this table so the
-- dashboard's Stripe webhook handler can short-circuit duplicate deliveries
-- without holding a Postgres pool itself (spec dashboard-no-backing-store-
-- clients, Module 3). The handler verifies the Stripe signature, then records
-- the event id here before processing.
--
-- This is a PLATFORM-level table (one row per Stripe event id, global) — Stripe
-- events arrive at the platform, not per-tenant. tenant_id carries the slug
-- from the event metadata for observability only and may be empty for
-- pre-tenant events (session events, etc.).
--
-- event_id is the PRIMARY KEY so RecordWebhookEvent's
-- `INSERT ... ON CONFLICT DO NOTHING` returns rowCount=1 only on first delivery.
--
-- NOTE: billing_service.go referred to a "0042_webhook_idempotency.sql"
-- migration that was never written, so RecordWebhookEvent failed with
-- `relation "webhook_idempotency" does not exist` (42P01) the moment the authz
-- fix (gibson#743 + deploy#921) let calls reach the SQL. This migration adds
-- the table the code has always assumed.
CREATE TABLE IF NOT EXISTS webhook_idempotency (
    event_id   TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    tenant_id  TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
