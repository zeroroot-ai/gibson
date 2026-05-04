package saga

// ClientCapability is the canonical name of an external client that
// saga.Steps may require. The Runner uses this enum to gate at startup —
// if a Step lists a capability that the operator's Deps did not provide,
// startup fails fast (in production mode).
//
// Adding a capability: append a constant below, add a corresponding
// nullable field to Deps in deps.go, and have the operator's main.go
// populate it from env/config. The Runner does not interpret the
// capability — it only checks "is this capability satisfied by Deps?"
// via Deps.Has(capability).
type ClientCapability string

const (
	// CapabilityPostgresAdmin: admin pgx connection used for CREATE
	// DATABASE / CREATE ROLE / GRANT against the per-tenant Postgres
	// instance.
	CapabilityPostgresAdmin ClientCapability = "postgres-admin"

	// CapabilityVaultAdmin: Vault admin/management client used to create
	// per-tenant namespaces (Enterprise) or path-prefix policies +
	// JWT auth roles (Community), and to write per-tenant credentials.
	CapabilityVaultAdmin ClientCapability = "vault-admin"

	// CapabilityVaultTransit: Vault transit derive client used by the
	// DeriveTenantKEK step in production mode.
	CapabilityVaultTransit ClientCapability = "vault-transit"

	// CapabilityKubernetes: controller-runtime client.Client. Used by
	// every step that touches K8s objects (namespaces, StatefulSets,
	// Secrets, ConfigMaps).
	CapabilityKubernetes ClientCapability = "kubernetes"

	// CapabilityZitadelAdmin: Zitadel Management API client (IAM_OWNER
	// PAT) used by EnsureZitadelOrg + TenantMember sync.
	CapabilityZitadelAdmin ClientCapability = "zitadel-admin"

	// CapabilityFGA: OpenFGA client used to write tuples (founder admin,
	// feature flags, catalog enabled).
	CapabilityFGA ClientCapability = "fga"

	// CapabilityRedisAdmin: Redis admin client (DB 0) used to allocate
	// per-tenant logical-DB indices and publish tenant-name cache
	// entries.
	CapabilityRedisAdmin ClientCapability = "redis-admin"

	// CapabilityQdrantAdmin: Qdrant HTTP admin client used to PUT/DELETE
	// per-tenant collections.
	CapabilityQdrantAdmin ClientCapability = "qdrant-admin"

	// CapabilityStripe: Stripe API client used to create customers and
	// process billing webhooks. Optional for free-tier tenants.
	CapabilityStripe ClientCapability = "stripe"

	// CapabilityLangfuse: Langfuse admin client used to create per-tenant
	// projects and rotate keys.
	CapabilityLangfuse ClientCapability = "langfuse"

	// CapabilityDaemonGRPC: Connect-RPC client to the gibson daemon's
	// PlatformOperatorService. Used by the entitlements steps to write
	// tenant_quotas / FGA tuples / catalog seed via daemon gRPC, with
	// no dashboard hop.
	CapabilityDaemonGRPC ClientCapability = "daemon-grpc"

	// CapabilitySMTP: SMTP mailer used by TenantMember invitation flow.
	CapabilitySMTP ClientCapability = "smtp"
)

// AllCapabilities returns the full set of declared capabilities. Useful
// for tests that want to assert "the runner enumerates everything".
func AllCapabilities() []ClientCapability {
	return []ClientCapability{
		CapabilityPostgresAdmin,
		CapabilityVaultAdmin,
		CapabilityVaultTransit,
		CapabilityKubernetes,
		CapabilityZitadelAdmin,
		CapabilityFGA,
		CapabilityRedisAdmin,
		CapabilityQdrantAdmin,
		CapabilityStripe,
		CapabilityLangfuse,
		CapabilityDaemonGRPC,
		CapabilitySMTP,
	}
}
