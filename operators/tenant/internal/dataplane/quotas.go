/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package dataplane

// TenantResourceLimits carries the per-tenant resource limits read from
// Tenant.spec.resources (or Helm defaults when the field is absent).
//
// All fields are optional (zero means "use engine default"). The pipeline
// orchestrator passes this struct to each provisioner's quota-apply path.
type TenantResourceLimits struct {
	// PostgresConnectionLimit is the maximum number of concurrent connections
	// the tenant's Postgres role is allowed. Maps to ALTER ROLE ... CONNECTION LIMIT N.
	// 0 = no limit (Postgres default: -1 = unlimited).
	PostgresConnectionLimit int

	// RedisMaxMemoryBytes is the per-DB MAXMEMORY value in bytes when the Redis
	// server supports per-DB CONFIG SET (Redis >= 7.4). 0 = no limit.
	// When the server does not support per-DB CONFIG SET, this field is ignored
	// and a log warning is emitted.
	RedisMaxMemoryBytes int64

	// Neo4jTransactionTimeoutMs is the per-transaction memory limit in
	// milliseconds (Neo4j Enterprise). 0 = no limit.
	// This field is reserved for future use and currently has no effect.
	Neo4jTransactionTimeoutMs int64

	// VectorMaxIndexedPoints is the upper bound for future FLAT-vs-HNSW
	// index-type selection for the RediSearch index. 0 = no limit (always
	// HNSW).
	VectorMaxIndexedPoints int64
}

// DefaultTenantResourceLimits returns safe defaults that match the Helm chart
// default values. Callers override individual fields from Tenant.spec.resources.
func DefaultTenantResourceLimits() TenantResourceLimits {
	return TenantResourceLimits{
		PostgresConnectionLimit: 50, // 50 concurrent connections per tenant role
		RedisMaxMemoryBytes:     0,  // no per-DB limit (global cluster policy applies)
		VectorMaxIndexedPoints:  0,  // no limit; always HNSW
	}
}
