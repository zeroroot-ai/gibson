-- gibson#506: two tables had no reader and no writer in any first-party repo.
--
-- connector_sandbox (013, 014) was the inventory a connector-enable
-- reconciler was meant to read for idempotency and a disable was meant to
-- read for teardown and principal revocation. That reconciler was never
-- built. Under ADR-0065 a connector is a ConnectorInstance CR: the CR is
-- the inventory (one per tenant and connector, so a second enable is a
-- no-op on the same object), and the connector-operator's finalizer
-- revokes the grant on delete (GrantRevoker, ADR-0061).
--
-- webhook_idempotency (015) was read by BillingService.RecordWebhookEvent,
-- which left gibson with the closed billing tier (ADR-0089). The billing
-- repository keeps its own idempotency key in its own store.
DROP TABLE IF EXISTS connector_sandbox;
DROP TABLE IF EXISTS webhook_idempotency;
