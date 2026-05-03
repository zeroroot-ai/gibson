// Package vectordb is forward-looking infrastructure for per-tenant Qdrant
// collections accessed via Pool.For(tenant).Vector().
//
// NOT YET WIRED — Pool.For(tenant).Vector() returns nil at runtime. The actual
// vector workloads (finding classification, GraphRAG) currently use
// internal/memory/vector/ with per-tenant key prefixing (see
// NewVectorStoreForTenantWithStore in that package).
//
// The vectordb package contains a stub Qdrant adapter (qdrant.go) and the
// Driver/Client interfaces (vectordb.go) that will be wired into the data-plane
// Pool once a concrete per-tenant Qdrant use case justifies the infrastructure
// cost (estimated at ≥75 tenants or a dedicated embedding workload).
//
// See spec per-tenant-data-plane-completion Req 3 background for the deferral
// rationale: key-prefix isolation inside the shared in-memory / Redis vector
// store is sufficient for the current finding-classification and GraphRAG
// vector workloads; a per-collection Qdrant model adds deployment complexity
// (one collection per tenant, Qdrant admission webhook, backup CronJob variant)
// without a matching throughput requirement at current scale.
//
// To enable the real Qdrant adapter when the time comes:
//
//  1. Run: go get github.com/qdrant/go-client
//  2. Implement NewQdrantDriver in qdrant.go using the Qdrant gRPC client.
//  3. Remove the stub error from qdrant.go's For() method.
//  4. Wire NewQdrantDriver into NewPool in pool_impl.go.
//  5. Add tenant collection bootstrap to the tenant-operator saga.
package vectordb
