// Package secrets implements the Gibson daemon's broker stack: the per-tenant
// registry that resolves which SecretsBroker backend serves each tenant, the
// Service that gRPC handlers call, the CircuitBreaker that isolates per-tenant
// backend failures, the AuditWriter that emits compliance_signal events, and
// the ConfigStore that persists and probes per-tenant broker configurations.
//
// # Component map
//
// The five principal types compose as follows (construction order from
// daemon.go initBrokerStack mirrors the dependency direction):
//
//	TenantConfigStore  — raw DB row I/O for tenant_secrets_broker_config
//	      |
//	ConfigStore        — Get/Set/Delete with Probe + audit on Set/Delete
//	      |
//	Registry           — per-tenant provider cache; default-Postgres fallback
//	      |
//	CircuitBreaker     — per-(tenant,provider) fault containment
//	      |
//	AuditWriter        — compliance_signal emission via Redis Streams
//	      |
//	Service            — single entry point for gRPC handlers
//
// Only Service is a direct dependency of gRPC handlers. The four types below
// it are internal; tests inject them via the narrow interfaces ServiceRegistry,
// ServiceCircuitBreaker, and ServiceAuditWriter defined in service.go.
//
// # Service
//
// Service.Resolve/Put/Delete/List are the only methods handlers call. Each
// method:
//
//  1. Extracts the tenant from the request context (set by the SDK auth
//     interceptor). No method accepts a tenant parameter directly — this
//     prevents callers from bypassing tenant isolation.
//  2. Calls Registry.For to obtain the SecretsBroker for that tenant.
//  3. Calls CircuitBreaker.Allow. If the circuit is open, returns
//     codes.Unavailable immediately without touching the provider.
//  4. Calls the provider method. On success calls CircuitBreaker.RecordSuccess;
//     on failure calls CircuitBreaker.RecordFailure.
//  5. Emits an AuditEvent with effect allow (on success) or deny (on failure).
//  6. Maps errors to gRPC status codes via the typed sentinels in
//     github.com/zero-day-ai/platform-clients/secrets.
//
// # Registry
//
// Registry.For returns the SecretsBroker for a given tenant. On first call for
// a tenant it reads the tenant's row from TenantConfigStore (via RegistryConfigGetter),
// constructs the appropriate provider using the matching ProviderConstructor,
// and caches the instance. Subsequent calls return the cached instance.
//
// Default-Postgres fallback: when no broker configuration row exists for a
// tenant (i.e. TenantConfigStore.Get returns ErrBrokerConfigNotFound), the
// pre-constructed Postgres provider passed to NewRegistry is returned. This
// preserves backward compatibility for tenants that pre-date the broker
// abstraction.
//
// Registry.Reload(tenant) removes the cached instance for that tenant, causing
// the next For call to re-read and re-construct. It is wired in daemon.go to
// broker-config-change events on the component callback stream so in-flight
// sessions pick up a new provider configuration on next acquisition.
//
// # CircuitBreaker
//
// CircuitBreaker is per-(tenant, provider). Parameters (unexported constants):
//
//   - Failure threshold: 5 consecutive failures within 60 seconds opens the
//     circuit.
//   - Open period: 30 seconds. After the period a single probe is admitted
//     (half-open state).
//   - Half-open: the probe succeeds → closed; the probe fails → re-open.
//
// Prometheus metrics emitted:
//
//	gibson_secrets_svc_circuit_open_total{tenant, provider}  — counter; each open
//	gibson_secrets_svc_circuit_state{tenant, provider}        — gauge; 0=closed, 1=open, 2=half_open
//
// The circuit does not auto-clear after 30 seconds without a probe: the open
// period expires and the circuit enters half-open, meaning the next real call
// acts as the probe. There is no operator-side "force close" command; clearing
// requires either a successful request or a daemon restart.
//
// # AuditWriter
//
// AuditWriter maps AuditEvent structs to the existing Redis Streams audit
// pipeline (core/gibson/internal/audit.AuditLogger). It retries 3 times with
// exponential backoff (250 ms, 500 ms, 1 s). On final failure it logs CRITICAL
// via slog and increments gibson_secrets_audit_failures_total{tenant}. The
// underlying secret operation is never failed because of an audit write failure
// (best-effort posture, consistent with audit-taxonomy-foundation).
//
// SECURITY: AuditWriter enforces a plaintext guard. Any string field that
// exceeds 256 bytes and contains the literal substring "value" or
// "secret_value" causes the event to be rejected entirely (CRITICAL log,
// counter increment, no write). This is a heuristic defence against accidental
// plaintext leakage in audit fields.
//
// # ConfigStore and TenantConfigStore
//
// TenantConfigStore handles raw database I/O for tenant_secrets_broker_config.
// Each row's config column is envelope-encrypted (AES-Key-Wrap DEK +
// AES-256-GCM) under the system-tenant KEK with AAD:
//
//	"tenant_secrets_broker_config:<tenant_id>"
//
// ConfigStore wraps TenantConfigStore and adds:
//
//   - Factory map: each provider name → ProviderFactory (constructor from JSON blob).
//   - Set: validates JSON, constructs a candidate provider, runs Probe, then
//     writes. The row is never written unless Probe succeeds.
//   - Audit on every Set and Delete.
//
// # Postgres-default fallback
//
// When no per-tenant config row exists, the Registry returns the pre-shared
// Postgres provider constructed at daemon startup. The Postgres provider
// acquires a per-tenant Conn from the data pool, calls Conn.Secrets() which
// returns a *TenantSecretsOps backed by the tenant_secrets table, and releases
// the Conn before returning. The per-tenant KEK is zeroed on Conn.Release,
// preserving the key-lifecycle semantics from the pre-broker credential store.
//
// # Cross-tenant decrypt detection
//
// The Postgres provider preserves the cross-tenant decrypt detection metric
// from the pre-spec TenantSecretsOps. When an envelope.Decrypt call fails with
// the AES-Unwrap authentication-failure signal — indicating the envelope was
// decrypted with a KEK that does not match the envelope's AAD — the provider
// maps the error to secrets.ErrUnavailable and the underlying DAO increments
// the gibson_xtenant_decrypt_attempt_total counter (labels: tenant, operation).
//
// This failure mode is Postgres-specific. Vault and cloud providers use
// per-tenant namespaces or path-prefix ACLs for isolation; there is no
// equivalent cross-namespace decrypt scenario.
//
// # Spec reference
//
// Spec: secrets-broker. Requirements: 6, 7, 9, 11.4. Phases 7 and 11.
package secrets
