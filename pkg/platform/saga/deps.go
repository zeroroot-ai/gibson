package saga

// Deps is the bag of clients available to every saga.Step. Each field is
// nullable (interface or pointer) and corresponds to one ClientCapability.
// The operator's main.go populates fields from env/config; missing real
// clients leave the field nil.
//
// Steps DO NOT receive a custom Deps subset — every step gets the same
// bag and must check `Deps.Has(capability)` (or the runner's startup
// gate must have already enforced presence) before using a client.
//
// Why interfaces instead of concrete types: this package must remain a
// leaf with no daemon-internal driver imports (per spec NFR — Code
// Architecture and Modularity). Concrete client types live in the
// operator (e.g., pgxpool.Pool, *neo4j.Driver, internal Vault client);
// the operator binds them to these interfaces at startup.
type Deps struct {
	// Postgres is the admin pgx connection (for CREATE DATABASE / ROLE).
	// Implementations declared in operator's internal/clients/postgres.
	Postgres PostgresAdminClient

	// Vault is the admin Vault client (for namespace/policy/secret writes).
	Vault VaultAdminClient

	// Transit is the Vault transit derive client (for production MasterKEK).
	Transit VaultTransitClient

	// K8s is the controller-runtime client.Client.
	K8s KubernetesClient

	// Zitadel is the Zitadel Management API client.
	Zitadel ZitadelClient

	// FGA is the OpenFGA client.
	FGA FGAClient

	// Redis is the Redis admin client (DB 0).
	Redis RedisAdminClient

	// Qdrant is the Qdrant HTTP admin client.
	Qdrant QdrantAdminClient

	// Stripe is the Stripe API client.
	Stripe StripeClient

	// DaemonGRPC is the Connect-RPC client to gibson's PlatformOperatorService.
	DaemonGRPC DaemonGRPCClient

	// SMTP is the mailer for TenantMember invitations.
	SMTP MailerClient
}

// Has reports whether the capability is satisfied — i.e., the
// corresponding Deps field is non-nil. Used by the Runner's startup
// gate.
func (d *Deps) Has(c ClientCapability) bool {
	if d == nil {
		return false
	}
	switch c {
	case CapabilityPostgresAdmin:
		return d.Postgres != nil
	case CapabilityVaultAdmin:
		return d.Vault != nil
	case CapabilityVaultTransit:
		return d.Transit != nil
	case CapabilityKubernetes:
		return d.K8s != nil
	case CapabilityZitadelAdmin:
		return d.Zitadel != nil
	case CapabilityFGA:
		return d.FGA != nil
	case CapabilityRedisAdmin:
		return d.Redis != nil
	case CapabilityQdrantAdmin:
		return d.Qdrant != nil
	case CapabilityStripe:
		return d.Stripe != nil
	case CapabilityDaemonGRPC:
		return d.DaemonGRPC != nil
	case CapabilitySMTP:
		return d.SMTP != nil
	}
	return false
}

// Client interfaces. These are intentionally opaque (`any`-shaped) at
// this layer — the saga package does not call methods on them. The
// operator's step implementations type-assert to the concrete client
// types they need. This keeps gibson/pkg/platform/saga a leaf package
// with no transitive driver imports.
//
// If a future caller wants type-safe method access without per-step
// type assertions, they can declare narrower interfaces in their own
// package and have the operator bind concrete clients to those.
type (
	PostgresAdminClient any
	VaultAdminClient    any
	VaultTransitClient  any
	KubernetesClient    any
	ZitadelClient       any
	FGAClient           any
	RedisAdminClient    any
	QdrantAdminClient   any
	StripeClient        any
	DaemonGRPCClient    any
	MailerClient        any
)
