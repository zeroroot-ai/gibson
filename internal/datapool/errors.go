// Package datapool owns the daemon's per-tenant data-plane connection pool.
// All four storage backends (Postgres, Redis, Neo4j, vector store) are
// accessed exclusively through this package; no other package in the daemon
// may import raw store client libraries.
//
// Spec: database-per-tenant-data-plane, Phase B.
package datapool

import "fmt"

// NotProvisionedError is returned by Pool.For when the requested tenant's
// data-plane resources have not been provisioned by the tenant-operator.
// Daemon handlers should translate this to gRPC codes.NotFound.
type NotProvisionedError struct {
	// Tenant is the string representation of the tenant that was not found.
	Tenant string
	// Reason carries optional detail about why provisioning is not complete
	// (e.g., "Tenant CRD not found", "status.dataPlane not ready").
	Reason string
}

func (e *NotProvisionedError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("datapool: tenant %q not provisioned: %s", e.Tenant, e.Reason)
	}
	return fmt.Sprintf("datapool: tenant %q not provisioned", e.Tenant)
}

// Is satisfies errors.Is so callers can write:
//
//	errors.Is(err, &NotProvisionedError{})
func (e *NotProvisionedError) Is(target error) bool {
	_, ok := target.(*NotProvisionedError)
	return ok
}

// EvictedError is returned when a caller holds a reference to a Conn whose
// underlying per-tenant pool was evicted while the Conn was still considered
// checked out. This indicates a programming error (the caller held the Conn
// longer than the idle TTL without releasing it). The caller should
// re-acquire via Pool.For.
type EvictedError struct {
	Tenant string
}

func (e *EvictedError) Error() string {
	return fmt.Sprintf("datapool: tenant %q pool was evicted while conn was checked out", e.Tenant)
}

// Is satisfies errors.Is so callers can write:
//
//	errors.Is(err, &EvictedError{})
func (e *EvictedError) Is(target error) bool {
	_, ok := target.(*EvictedError)
	return ok
}
