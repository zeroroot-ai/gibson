// Package vectordb defines the narrow vector-store abstraction used by the
// daemon's data-plane pool and provides the Redis VSS (RediSearch FT.*)
// adapter as the production implementation.
//
// NOT YET WIRED — Pool.For(tenant).Vector() returns nil at runtime. The actual
// vector workloads (finding classification, GraphRAG) currently use
// internal/memory/vector/ with per-tenant key prefixing (see
// NewVectorStoreForTenantWithStore in that package).
//
// The production adapter is redis.go (NewRedisVSSDriver). The tenant-operator
// creates per-tenant RediSearch indexes with the HNSW COSINE schema; the daemon
// calls For(ctx, indexName) to obtain a Client scoped to that index.
//
// Key-derivation convention:
//
//	index name: "vector_idx:tenant_acme"
//	key prefix: "vec:tenant_acme:"
//
// See spec per-tenant-data-plane-completion Req 3 for the deferral rationale
// and gibson#325 for the Qdrant-to-Redis VSS migration.
//
// To wire this package into NewPool:
//
//  1. Read VectorCredentials from Vault at tenant/<id>/infra/vector.
//  2. Call NewRedisVSSDriver with the Redis connection params from
//     tenant/<id>/infra/redis (addr + password shared with the existing
//     redis sub-pool; DB index from RedisCredentials).
//  3. Uncomment: p.vector = newVectorPerTenant(driver) in pool_impl.go.
package vectordb
